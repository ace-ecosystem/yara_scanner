#!/usr/bin/env python3


def main():

    import argparse
    import logging, logging.config, logging.handlers
    import os, os.path
    import sys
    import time
    import signal
    import tempfile

    import yara_scanner
    from yara_scanner import YaraScannerServer

    parser = argparse.ArgumentParser(description="Yara Scanner Server")
    parser.add_argument(
        "--base-dir",
        required=False,
        default="/opt/yara_scanner",
        help="Base directory of yara scanner. Defaults to /opt/yara_scanner",
    )
    parser.add_argument(
        "-L",
        "--logging-config-path",
        required=False,
        default="etc/logging.ini",
        help="Path to the logging configuration file.",
    )
    parser.add_argument(
        "-d",
        "--signature-dir",
        required=False,
        default="/opt/signatures",
        help="The signature directory to load. Defaults to /opt/signatures",
    )
    parser.add_argument(
        "-s",
        "--socket-dir",
        required=False,
        default="socket",
        help="The directory (relative to --base-dir) that contains the unix sockets.",
    )
    parser.add_argument(
        "-u",
        "--update-frequency",
        required=False,
        default=60,
        type=int,
        help="How often to check for modifications to the yara rules (in seconds). Defaults to 60.",
    )
    parser.add_argument(
        "-m",
        "--max-workers",
        required=False,
        default=None,
        type=int,
        help="Specify the maximum number of workers. Defaults to the local cpu count.",
    )
    parser.add_argument(
        "--cache-directory",
        required=False,
        default=None,
        help="The directory to use to cache compiled yara programs. Defaults to the system temp dir.",
    )
    parser.add_argument(
        "--max-contexts",
        required=False,
        default=yara_scanner.DEFAULT_MAX_CONTEXTS,
        type=int,
        help=f"How many yara contexts can stay in memory at one time. Applies to prefiltering. Defaults to {yara_scanner.DEFAULT_MAX_CONTEXTS}.",
    )
    parser.add_argument(
        "--disable-prefilter",
        required=False,
        action="store_true",
        default=False,
        help="Disable pre-filtering.",
    )
    parser.add_argument(
        "--pid-file",
        required=False,
        default=".yss.pid",
        help="The file name (relative to base_dir) used to store the pid of the running daemon yss process.",
    )
    parser.add_argument(
        "--backlog",
        required=False,
        default=50,
        type=int,
        help="The maximum number of queued connections. Defaults to 50.",
    )
    parser.add_argument(
        "-b", "--background", required=False, default=False, action="store_true", help="Execute in background."
    )
    parser.add_argument(
        "-k",
        "--kill",
        required=False,
        default=False,
        action="store_true",
        help="Kill the currently executing yara scanner server.",
    )
    # resource constraints
    parser.add_argument(
        "-T",
        "--timeout",
        default=yara_scanner.DEFAULT_TIMEOUT,
        type=int,
        help="""Maximum amount of time (in seconds) a single scan is allowed to take.
        Passed directly to libyara.""")

    parser.add_argument(
        "-M",
        "--max-bytes",
        default=yara_scanner.DEFAULT_MAX_BYTES,
        type=int,
        help="""Only the first N bytes of a file are scanned.""")
    args = parser.parse_args()

    if not os.path.isdir(args.base_dir):
        sys.stderr.write("unknown base directory {}\n".format(args.base_dir))
        sys.exit(1)

    pid_file = os.path.join(args.base_dir, args.pid_file)
    if args.kill:
        if os.path.exists(pid_file):
            # is it still running?
            import psutil

            with open(pid_file, "r") as fp:
                pid = int(fp.read().strip())

            if not psutil.pid_exists(pid):
                print("removing stale pid file")
                try:
                    os.remove(pid_file)
                    sys.exit(0)
                except Exception as e:
                    sys.stderr.write("unable to delete stale pid file {}: {}\n".format(pid_file, e))
                    sys.exit(1)

            # kill it
            p = psutil.Process(pid)
            try:
                print("terminating process {}".format(pid))
                p.terminate()
                p.wait(5)

                try:
                    os.remove(pid_file)
                except Exception as e:
                    sys.stderr.write("unable to delete pid file {}: {}\n".format(pid_file, e))

            except Exception as e:
                print("killing process {}".format(pid))
                try:
                    p.kill()
                    p.wait(1)

                    try:
                        os.remove(pid_file)
                    except Exception as e:
                        sys.stderr.write("unable to delete pid file {}: {}\n".format(pid_file, e))

                except Exception as e:
                    sys.stderr.write("unable to kill process {}\n".format(pid))
                    sys.exit(1)

            sys.exit(0)
        else:
            print("no process running")
            sys.exit(0)

    if os.path.exists(pid_file):
        print("existing process running or stale pid file (use -k to clear or kill)")
        sys.exit(1)

    # make sure these directories exist
    for _dir in ["logs", args.socket_dir]:
        path = os.path.join(args.base_dir, _dir)
        if not os.path.isdir(path):
            try:
                os.mkdir(path)
            except Exception as e:
                sys.stderr.write("unable to create directory {}: {}\n".format(path, e))
                sys.exit(1)

    # initialize logging
    # if the path is relative then it's relative to the base directory
    if not os.path.isabs(args.logging_config_path):
        args.logging_config_path = os.path.join(args.base_dir, args.logging_config_path)

    try:
        logging.config.fileConfig(args.logging_config_path)
    except Exception as e:
        sys.stderr.write("unable to load logging configuration: {}\n".format(e))
        import traceback

        traceback.print_exc()
        sys.exit(1)

    # are we running as a deamon/
    if args.background:
        pid = None

        # http://code.activestate.com/recipes/278731-creating-a-daemon-the-python-way/
        try:
            pid = os.fork()
        except OSError as e:
            logging.fatal("{} ({})".format(e.strerror, e.errno))
            sys.exit(1)

        if pid == 0:
            os.setsid()

            try:
                pid = os.fork()
            except OSError as e:
                logging.fatal("{} ({})".format(e.strerror, e.errno))
                sys.exit(1)

            if pid > 0:
                # write the pid to a file
                with open(pid_file, "w") as fp:
                    fp.write(str(pid))

                print("background pid = {}".format(pid))

                os._exit(0)
        else:
            os._exit(0)

        import resource

        maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        if maxfd == resource.RLIM_INFINITY:
            maxfd = MAXFD

            for fd in range(0, maxfd):
                try:
                    os.close(fd)
                except OSError:  # ERROR, fd wasn't open to begin with (ignored)
                    pass

        if hasattr(os, "devnull"):
            REDIRECT_TO = os.devnull
        else:
            REDIRECT_TO = "/dev/null"

        os.open(REDIRECT_TO, os.O_RDWR)
        os.dup2(0, 1)
        os.dup2(0, 2)

    context_cache_dir = args.cache_directory
    if context_cache_dir is None:
        context_cache_dir = os.path.join(tempfile.gettempdir(), ".yss_cache")

    server = YaraScannerServer(
        base_dir=args.base_dir,
        signature_dir=args.signature_dir,
        socket_dir=args.socket_dir,
        update_frequency=args.update_frequency,
        backlog=args.backlog,
        default_timeout=args.timeout,
        max_bytes=args.max_bytes,
        max_workers=args.max_workers,
        disable_prefilter=args.disable_prefilter,
        context_cache_dir=context_cache_dir,
        max_contexts=args.max_contexts,
    )

    try:
        server.start()
        server.wait_for_start()
        server.wait_for_stop()
        print("yara scanner server stopped")
    except KeyboardInterrupt:
        server.stop()
        server.wait_for_stop()
        print("yara scanner server stopped")
        sys.exit(0)


if __name__ == "__main__":
    main()
