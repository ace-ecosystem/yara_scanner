#!/usr/bin/env python3

def main():
    import argparse
    import sys
    import json

    from yara_scanner import scan_file, YaraJSONEncoder

    parser = argparse.ArgumentParser(description="Yara Scanner Client")
    parser.add_argument('--base-dir', required=False, default='/opt/yara_scanner',
        help="Base directory of yara scanner. Defaults to /opt/yara_scanner")
    parser.add_argument('--from-stdin', required=False, default=False, action='store_true', dest='from_stdin',
        help="Read the list of files to scan from stdin.")
    parser.add_argument('-j', '--dump-json', required=False, default=False, action='store_true', dest='dump_json',
        help="Dump JSON details of matches.  Otherwise just list the rules that hit.")
    parser.add_argument('files', nargs="*", help="The file to scan.")
    args = parser.parse_args()

    if args.from_stdin:
        for line in sys.stdin:
            line = line.strip()
            args.files.append(line)

    for _file in args.files:
        scan_results = scan_file(_file, base_dir=args.base_dir)
        if not scan_results:
            print("{}: no matches".format(_file))
        else:
            if args.dump_json:
                json.dump(scan_results, sys.stdout, sort_keys=True, indent=4, cls=YaraJSONEncoder)
            else:
                print("{}: {} rule matches".format(_file, len(scan_results)))
                for match in scan_results:
                    print('\t{}'.format(match['rule']))

if __name__ == '__main__':
    main()
