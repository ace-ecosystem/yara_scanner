import os.path
import shutil
from subprocess import Popen

import pytest

from yara_scanner import (ALL_RESULT_KEYS, RESULT_KEY_META,
                          RESULT_KEY_NAMESPACE, RESULT_KEY_RULE,
                          RESULT_KEY_STRINGS, RESULT_KEY_TAGS,
                          RESULT_KEY_TARGET, YaraScanner, __version__)

def create_file(path, content):
    dir = os.path.dirname(path)
    if not os.path.isdir(dir):
        os.makedirs(dir)

    with open(path, 'w') as fp:
        fp.write(content)

    return path

@pytest.fixture
def scanner(shared_datadir):
    s = YaraScanner(signature_dir=str(shared_datadir / 'signatures'))
    s.load_rules()
    return s

@pytest.fixture
def repo(shared_datadir):
    repo_path = str(shared_datadir / 'signatures' / 'ruleset_a')
    Popen(['git', '-C', repo_path, 'init']).wait()
    Popen(['git', '-C', repo_path, 'config', 'user.name', 'Test User']).wait()
    Popen(['git', '-C', repo_path, 'config', 'user.email', 'test_user@localhost']).wait()
    Popen(['git', '-C', repo_path, 'add', '*.yar']).wait()
    Popen(['git', '-C', repo_path, 'commit', '-m', 'initial commit']).wait()
    return repo_path

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

def test_yara_rule_blacklisting(scanner):
    assert scanner.scan_data('test_rule_1')
    scanner.blacklist_rule('rule_1')
    scanner.load_rules()
    assert not scanner.scan_data('test_rule_1')

def test_single_file_tracking(scanner, shared_datadir):
    s = YaraScanner()
    yara_rule_path = str(shared_datadir / 'signatures' / 'ruleset_a' / 'rule_1.yar')
    s.track_yara_file(yara_rule_path)
    s.load_rules()
    assert not s.check_rules()
    assert s.tracked_files
    assert yara_rule_path in s.tracked_files
    with open(yara_rule_path, 'a') as fp:
        fp.write('\n//test')

    # this should return True after the file has been modified
    assert s.check_rules()
    s.load_rules()
    assert not s.check_rules()
    with open(yara_rule_path, 'r') as fp:
        rule_content = fp.read()

    os.remove(yara_rule_path)
    assert s.check_rules()
    assert s.tracked_files[yara_rule_path] is None
    assert not s.load_rules()

    with open(yara_rule_path, 'w') as fp:
        fp.write(rule_content)

    assert s.check_rules()
    assert s.load_rules()

def test_dir_tracking(shared_datadir):
    s = YaraScanner()
    yara_dir_path = str(shared_datadir / 'signatures' / 'ruleset_a')
    yara_rule_path = str(shared_datadir / 'signatures' / 'ruleset_a' / 'rule_1.yar')
    s.track_yara_dir(yara_dir_path)
    s.load_rules()
    assert not s.check_rules()
    assert s.tracked_dirs
    assert len(s.tracked_dirs[yara_dir_path]) == 1
    
    with open(yara_rule_path, 'a') as fp:
        fp.write('\ntest')

    # this should return True after the file has been modified
    assert s.check_rules()
    s.load_rules()
    assert not s.check_rules()
    
    os.remove(yara_rule_path)

    # this should return True after the file has been deleted
    assert s.check_rules()
    # when files are deleted from a tracked dir they are removed from the dict tracking
    assert not s.tracked_dirs[yara_dir_path]
    assert not s.load_rules()

@pytest.mark.skipif(not shutil.which('git'), reason="missing git in PATH")
def test_repo_tracking(repo):
    s = YaraScanner()
    s.track_yara_repository(repo)
    assert s.check_rules()
    assert s.load_rules()
    assert not s.check_rules()
    with open(os.path.join(repo, 'rule_1.yar'), 'a') as fp:
        fp.write('\n// modified')
    
    # not considered modified until changes committed to repo
    assert not s.check_rules()
    Popen(['git', '-C', repo, 'add', '*.yar']).wait()
    Popen(['git', '-C', repo, 'commit', '-m', 'modified']).wait()
    assert s.check_rules()
    assert s.load_rules()
    assert not s.check_rules()

#region meta_rule_tests
meta_rule_tests = [
    ("""
rule test_meta_filename {
meta:
    file_name = "scan_target_1.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filename_multi {
meta:
    file_name = "scan_target_1.txt,scan_target_2.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filename_not {
meta:
    file_name = "!scan_target_1.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_1.txt', 
    'Sample content.',
    False),
    ("""
rule test_meta_filename_not_multi {
meta:
    file_name = "!scan_target_1.txt,scan_target_2.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_2.txt', 
    'Sample content.',
    False),
    ("""
rule test_meta_filename_not_multi {
meta:
    file_name = "!scan_target_1.txt,scan_target_2.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_3.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filename_sub {
meta:
    file_name = "sub:scan_target_1."
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filename_re {
meta:
    file_name = "re:^scan_target_1"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filename_re {
meta:
    file_name = "re:^scan_target_1"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_2.txt', 
    'Sample content.',
    False),
    ("""
rule test_meta_filename_re {
meta:
    file_name = "!re:^scan_target_1"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_2.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filepath_sub {
meta:
    full_path = "sub:data/scan_target_1.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filepath_sub_multi {
meta:
    full_path = "sub:data/scan_target_1.txt,data/scan_target_2.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_2.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filepath_re {
meta:
    full_path = "re:data/scan_target_[0-9]+.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_fileext {
meta:
    file_ext = "txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_fileext_multi {
meta:
    file_ext = "txt,pdf,doc"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.doc', 
    'Sample content.',
    True),
    ("""
rule test_meta_mime {
meta:
    mime_type = "text/plain"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_mime_multi {
meta:
    mime_type = "text/plain,text/html"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_mime {
meta:
    mime_type = "re:^text/.+"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_multi_meta {
meta:
    file_name = "scan_target_1.txt"
    mime_type = "text/plain"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_multi_meta {
meta:
    file_name = "scan_target_1.txt"
    mime_type = "text/plain"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_2.txt', 
    'Sample content.',
    False),
    ("""
rule test_meta_multi_meta {
meta:
    file_name = "!scan_target_1.txt"
    mime_type = "text/plain"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    False),
    ("""
rule test_meta_multi_meta {
meta:
    file_name = "!scan_target_1.txt"
    mime_type = "text/plain"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_2.txt', 
    'Sample content.',
    True),
]
#endregion

@pytest.mark.parametrize("yara_rule_content, scan_target_name, scan_target_content, expected", meta_rule_tests)
def test_meta_directives(tmp_path, yara_rule_content, scan_target_name, scan_target_content, expected):
    s = YaraScanner()
    yara_rule_path = create_file(str(tmp_path / 'rule.yar'), yara_rule_content)
    scan_target_path = create_file(str(tmp_path / scan_target_name), scan_target_content)
    s.track_yara_file(yara_rule_path)
    s.load_rules()

    if expected:
        assert s.scan(scan_target_path)
        assert len(s.scan_results) == 1
    else:
        assert not s.scan(scan_target_path)
        assert len(s.scan_results) == 0
