import os.path

import pytest 

from yara_scanner import __version__, YaraScanner, \
    ALL_RESULT_KEYS, \
    RESULT_KEY_META, \
    RESULT_KEY_NAMESPACE, \
    RESULT_KEY_RULE, \
    RESULT_KEY_STRINGS, \
    RESULT_KEY_TAGS, \
    RESULT_KEY_TARGET

@pytest.fixture
def scanner(shared_datadir):
    s = YaraScanner(signature_dir=str(shared_datadir / 'signatures'))
    s.load_rules()
    return s

def test_version():
    assert __version__ == '1.0.14'

def test_signature_dir_load(scanner):
    # there should be two loaded directories
    assert len(scanner.tracked_dirs) == 2
    for dir_name in scanner.tracked_dirs.keys():
        # and one file from each directory
        assert len(scanner.tracked_dirs[dir_name]) == 1

    assert not scanner.check_rules()
    assert scanner.load_rules()

def test_data_scan_matching(scanner):
    # this should match
    assert scanner.scan_data('test_rule_1')
    # this should also match
    assert scanner.scan_data(b'test_rule_1')
    # this should not match
    assert not scanner.scan_data('random data')

def test_data_scan_results(scanner):
    scanner.scan_data('test_rule_1')
    # this should match tests/data/signatures/ruleset_a/rule_1.yar
    assert len(scanner.scan_results) == 1
    for key in ALL_RESULT_KEYS:
        assert key in scanner.scan_results[0]

    assert scanner.scan_results[0][RESULT_KEY_TARGET] == ''
    assert scanner.scan_results[0][RESULT_KEY_META] == {}
    assert os.path.basename(scanner.scan_results[0][RESULT_KEY_NAMESPACE]) == 'ruleset_a'
    assert scanner.scan_results[0][RESULT_KEY_RULE] == 'rule_1'
    assert scanner.scan_results[0][RESULT_KEY_STRINGS] == [(0, '$', b'test_rule_1')]
    assert scanner.scan_results[0][RESULT_KEY_TAGS] == ['tag_1']

    scanner.scan_data('test_rule_1\ntest_rule_2\n')
    # this should match both rules
    assert len(scanner.scan_results) == 2

def test_file_scan_results(scanner, shared_datadir):
    assert scanner.scan(str(shared_datadir / 'scan_targets' / 'scan_target_1.txt'))

    assert os.path.basename(scanner.scan_results[0][RESULT_KEY_TARGET]) == 'scan_target_1.txt'
    assert scanner.scan_results[0][RESULT_KEY_META] == {}
    assert os.path.basename(scanner.scan_results[0][RESULT_KEY_NAMESPACE]) == 'ruleset_a'
    assert scanner.scan_results[0][RESULT_KEY_RULE] == 'rule_1'
    assert scanner.scan_results[0][RESULT_KEY_STRINGS] == [(0, '$', b'test_rule_1')]
    assert scanner.scan_results[0][RESULT_KEY_TAGS] == ['tag_1']


