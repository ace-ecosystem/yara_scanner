import time
import os.path
import socket
import threading

import pytest
import yara

from yara_scanner import YaraScannerServer, YaraScannerWorker, scan_file, scan_data, send_data_block


@pytest.fixture
def signature_dir(tmp_path):
    signature_dir = tmp_path / "signatures"
    signature_dir.mkdir()
    rule_dir = signature_dir / "rules"
    rule_dir.mkdir()
    rule_path = rule_dir / "test.yar"
    rule_path.write_text(
        """rule test_rule {
    strings:
        $ = "hello world"
    condition:
        all of them
    }"""
    )
    return signature_dir


@pytest.fixture
def bad_signature_dir(tmp_path):
    signature_dir = tmp_path / "signatures"
    signature_dir.mkdir()
    rule_dir = signature_dir / "rules"
    rule_dir.mkdir()
    rule_path = rule_dir / "test.yar"
    rule_path.write_text(
        """rule test_rule {
    strings:
        $ = "hello world"
    condition:
        all of them
    }"""
    )
    bad_rule_path = rule_dir / "bad.yar"
    bad_rule_path.write_text(
        """rule test_rule {
    strings:
        $ = "hello world"
    condition:
        all of them
    }"""
    )
    return signature_dir


@pytest.fixture
def base_dir(tmp_path):
    result = tmp_path / "yss_base"
    result.mkdir()
    return result


@pytest.fixture
def sample_target(tmp_path):
    result = tmp_path / "target.txt"
    result.write_text("hello world")
    return result


@pytest.fixture
def worker(base_dir, signature_dir):
    return YaraScannerWorker(
        base_dir=str(base_dir),
        signature_dir=str(signature_dir),
        update_frequency=0,
        disable_signal_handling=True,
        use_threads=True,
        shutdown_event=threading.Event(),
        cpu_index=0,
    )


@pytest.fixture
def running_worker(base_dir, signature_dir):
    worker = YaraScannerWorker(
        base_dir=str(base_dir),
        signature_dir=str(signature_dir),
        update_frequency=0,
        disable_signal_handling=True,
        use_threads=True,
        shutdown_event=threading.Event(),
        cpu_index=0,
    )
    worker.start()
    worker.wait_for_start()

    try:
        yield worker
    finally:
        worker.stop()
        worker.wait_for_stop()


@pytest.fixture
def server(base_dir, signature_dir):
    return YaraScannerServer(
        base_dir=str(base_dir),
        signature_dir=str(signature_dir),
        disable_signal_handling=True,
        use_threads=True,
        max_workers=1,
    )


@pytest.mark.unit
def test_YaraScannerWorker_is_alive_not_started(worker):
    # returns True because it hasn't been started yet
    assert worker.is_alive()


@pytest.mark.unit
def test_YaraScannerWorker_is_alive_started(worker):
    # returns True because it hasn't been started yet
    worker.start()
    worker.wait_for_start()
    assert worker.is_alive()
    worker.stop()
    worker.wait_for_stop()
    assert not worker.is_alive()


@pytest.mark.unit
def test_YaraScannerWorker_missing_base_dir(worker):
    worker.base_dir = None
    worker.execute()


@pytest.mark.unit
def test_YaraScannerWorker_server_socket_error(worker):
    worker.server_socket = "invalid value"  # this is to trigger an error on .accept()
    worker.execute()


@pytest.mark.unit
def test_YaraScannerWorker_initialize_server_socket(worker):
    assert worker.server_socket is None
    worker.initialize_server_socket()
    assert worker.server_socket is not None
    assert os.path.isdir(os.path.join(worker.base_dir, worker.socket_dir))


@pytest.mark.unit
def test_YaraScannerWorker_initialize_server_socket_existing_socket(worker):
    os.mkdir(os.path.join(worker.base_dir, worker.socket_dir))
    with open(os.path.join(worker.base_dir, worker.socket_dir, "0"), "w") as fp:
        pass

    worker.initialize_server_socket()
    assert worker.server_socket is not None


@pytest.mark.unit
def test_YaraScannerWorker_kill_server_socket_no_socket(worker):
    worker.kill_server_socket()
    assert worker.server_socket is None


@pytest.mark.unit
def test_YaraScannerWorker_kill_server_socket(worker):
    worker.initialize_server_socket()
    worker.kill_server_socket()
    assert worker.server_socket is None
    assert not os.path.exists(worker.socket_path)


@pytest.mark.unit
def test_YaraScannerWorker_initialize_scanner(worker):
    worker.initialize_scanner()
    assert worker.scanner is not None


@pytest.mark.unit
def test_YaraScannerWorker_run(worker):
    worker.shutdown_event.set()
    worker.run()


@pytest.mark.integration
def test_YaraScannerWorker_start_stop(worker):
    worker.start()
    worker.wait_for_start()
    worker.stop()
    worker.wait_for_stop()


@pytest.mark.parametrize("ext_vars", [{}, {"hello": "world"}])
@pytest.mark.integration
def test_YaraScannerWorker_scan_file(worker, sample_target, ext_vars):
    worker.start()
    worker.wait_for_start()

    try:
        result = scan_file(
            str(sample_target), base_dir=worker.base_dir, socket_dir=worker.socket_dir, ext_vars=ext_vars
        )
    finally:
        worker.stop()
        worker.wait_for_stop()


@pytest.mark.parametrize("ext_vars", [{}, {"hello": "world"}])
@pytest.mark.integration
def test_YaraScannerWorker_scan_data(worker, ext_vars):
    worker.start()
    worker.wait_for_start()

    try:
        result = scan_data(b"hello world", base_dir=worker.base_dir, socket_dir=worker.socket_dir, ext_vars=ext_vars)
    finally:
        worker.stop()
        worker.wait_for_stop()


@pytest.mark.integration
def test_YaraScannerWorker_scan_data_no_match(running_worker):
    result = scan_data(b"hella world", base_dir=running_worker.base_dir, socket_dir=running_worker.socket_dir)
    assert result == {}


@pytest.mark.integration
def test_YaraScannerWorker_scan_data_error(bad_signature_dir, base_dir):
    worker = YaraScannerWorker(
        base_dir=str(base_dir),
        signature_dir=str(bad_signature_dir),
        disable_signal_handling=True,
        use_threads=True,
        shutdown_event=threading.Event(),
        cpu_index=0,
    )

    worker.start()
    worker.wait_for_start()
    with pytest.raises(yara.SyntaxError):
        result = scan_data(b"hello world", base_dir=worker.base_dir, socket_dir=worker.socket_dir)

    worker.stop()
    worker.wait_for_stop()


@pytest.mark.integration
def test_YaraScannerServer_start_stop(server):
    server.start()
    server.wait_for_start()
    server.stop()
    server.wait_for_stop()


@pytest.mark.integration
def test_YaraScannerServer_failed_worker(server):
    # start the worker
    server.execute_process_manager()
    worker = server.workers[0]
    worker.wait_for_start()
    assert worker.is_alive()
    worker.stop()
    worker.wait_for_stop()
    assert not worker.is_alive()
    server.execute_process_manager()
    assert not (worker is server.workers[0])
    server.workers[0].wait_for_start()
    assert server.workers[0].is_alive()
    server.workers[0].stop()
    server.workers[0].wait_for_stop()


@pytest.mark.unit
def test_scan_file_no_scanners(worker, sample_target):
    with pytest.raises(socket.error):
        scan_file(str(sample_target), base_dir=worker.base_dir, socket_dir=worker.socket_dir)


@pytest.mark.integration
def test_protocol_open_close(running_worker):
    client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client_socket.connect(running_worker.socket_path)
    client_socket.close()


@pytest.mark.integration
def test_protocol_invalid_command(running_worker):
    client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client_socket.connect(running_worker.socket_path)
    client_socket.sendall(b"3")
    send_data_block(client_socket, b"")
    send_data_block(client_socket, b"")
    client_socket.close()
