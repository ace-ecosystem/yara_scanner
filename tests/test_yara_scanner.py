import json
import logging
import os
import os.path
import shutil
import time

import subprocess
from subprocess import Popen, PIPE, DEVNULL

import pytest
import plyara

from yara_scanner import (ALL_RESULT_KEYS, RESULT_KEY_META,
                          RESULT_KEY_NAMESPACE, RESULT_KEY_RULE,
                          RESULT_KEY_STRINGS, RESULT_KEY_TAGS,
                          RESULT_KEY_TARGET, YaraScanner, __version__, RulesNotLoadedError,
                          META_FILTER_FILE_EXT,
                          META_FILTER_FILE_NAME,
                          META_FILTER_FULL_PATH,
                          META_FILTER_MIME_TYPE,
                          DEFAULT_NAMESPACE,
                          DEFAULT_TIMEOUT,
                          extract_filters_from_metadata,
                          create_filter_check,
                          generate_context_key,
                          get_current_repo_commit,
                          is_yara_file,
                          YaraRuleFile,
                          YaraRuleDirectory,
                          YaraRuleRepository,
                          YaraContext,
                          TestConfig,
                          )

from tests.util import requires_git

def _generate_yara_rule(name: str, search: str="hello world", condition: str="all of them") -> str:
    return f"""
rule {name} {{ 
    strings:
        $ = "{search}"

    condition:
        {condition}
}}"""

def create_file(path, content):
    dir = os.path.dirname(path)
    if not os.path.isdir(dir):
        os.makedirs(dir)

    with open(path, 'w') as fp:
        fp.write(content)

    return path

@pytest.fixture
def scanner(shared_datadir):
    return YaraScanner(signature_dir=str(shared_datadir / 'signatures'))

YARA_RULE_DEPENDENCY = """
rule rule_1 {
    strings:
        $ = "test"
    condition:
        any of them
}

rule rule_0 {
    strings:
        $ = "test"
    condition:
        any of them and rule_1
}
"""

YARA_RULE_NO_VALID_META = """ rule test { 
    meta:
        hello = "world"
    strings:
        $a = "b"
    condition:
       any of them
} """

YARA_RULE_FILE_EXT = """ rule test { 
    meta:
        file_ext = "bas"
    strings:
        $a = "b"
    condition:
       any of them
} """

YARA_RULE_MULTIPLE_META = """ rule test { 
    meta:
        file_ext = "bas"
        file_name = "something"
    strings:
        $a = "b"
    condition:
       any of them
} """


@pytest.mark.unit
@pytest.mark.parametrize('meta_dicts,expected_dict', [
    ({}, {}),
    (plyara.Plyara().parse_string(YARA_RULE_NO_VALID_META)[0]['metadata'], {}),
    (plyara.Plyara().parse_string(YARA_RULE_FILE_EXT)[0]['metadata'], { "file_ext": "bas"}),
    (plyara.Plyara().parse_string(YARA_RULE_MULTIPLE_META)[0]['metadata'], { "file_ext": "bas", "file_name": "something"}),
])
def test_extract_filters_from_metadata(meta_dicts, expected_dict):
    assert extract_filters_from_metadata(meta_dicts) == expected_dict

@pytest.mark.unit
@pytest.mark.parametrize('filters, target, result', [
    # not a valid filter
    ({'test': 'bas'}, 'target.bas', True),
    # test file_ext
    ({META_FILTER_FILE_EXT: 'bas'}, 'target.bas', True),
    ({META_FILTER_FILE_EXT: 'bas'}, 'TARGET.BAS', True),
    ({META_FILTER_FILE_EXT: 'bas,exe'}, 'target.bas', True),
    ({META_FILTER_FILE_EXT: 'bas'}, 'target.exe', False),
    ({META_FILTER_FILE_EXT: 'bas,com'}, 'target.exe', False),
    ({META_FILTER_FILE_EXT: 'bas'}, 'target', False),
    # test file_name
    ({META_FILTER_FILE_NAME: 'target.bas'}, 'target.bas', True),
    ({META_FILTER_FILE_NAME: 'target.bas'}, 'TARGET.BAS', True),
    ({META_FILTER_FILE_NAME: 'target.bas,target.exe'}, 'target.bas', True),
    ({META_FILTER_FILE_NAME: 'target.bas'}, 'target.exe', False),
    ({META_FILTER_FILE_NAME: 'target.bas,target.com'}, 'target.exe', False),
    # test full_path
    ({META_FILTER_FILE_NAME: r'C:\WINDOWS\target.bas'}, r'C:\WINDOWS\target.bas', True),
    ({META_FILTER_FILE_NAME: r'C:\WINDOWS\target.bas'}, r'C:\WINDOWS\TARGET.BAS', True),
    ({META_FILTER_FILE_NAME: r'C:\WINDOWS\target.bas'}, r'D:\WINDOWS\target.bas', False),
    # test inversion logic
    ({META_FILTER_FILE_EXT: '!bas'}, 'target.bas', False),
    ({META_FILTER_FILE_EXT: '!bas'}, 'target.exe', True),
    ({META_FILTER_FILE_EXT: '!bas,exe'}, 'target.exe', False),
    # test substring
    ({META_FILTER_FILE_NAME: 'sub:test'}, 'test.exe', True),
    ({META_FILTER_FILE_NAME: 'sub:test'}, 'rest.exe', False),
    ({META_FILTER_FILE_NAME: 'sub:test'}, 'thattest.exe', True),
    # test regex
    ({META_FILTER_FILE_NAME: r're:test\.(bas|exe)'}, 'test.exe', True),
    ({META_FILTER_FILE_NAME: r're:test\.(bas|exe)'}, 'TEST.EXE', True),
    ({META_FILTER_FILE_NAME: r're:test\.(bas|exe)'}, 'test.bas', True),
    ({META_FILTER_FILE_NAME: r're:test\.(bas|exe)'}, 'test.com', False),
    # test filter combinations
    ({META_FILTER_FILE_EXT: 'bas',
      META_FILTER_FILE_NAME: 'sub:targ'}, 'target.bas', True),
    ({META_FILTER_FILE_EXT: 'bas',
      META_FILTER_FILE_NAME: 'sub:targ'}, 'tarfet.bas', False),
])
def test_create_filter_check(filters, target, result):
    filter_check = create_filter_check(filters)
    assert filter_check(target) == result

@pytest.mark.unit
def test_YaraRuleFile_file_missing():
    yara_rule_file = YaraRuleFile('missing.yar')
    assert yara_rule_file.is_error_state
    # no YaraRule object should be loaded
    assert not yara_rule_file.yara_rules

@pytest.mark.unit
def test_YaraRuleFile_invalid_syntax(datadir):
    yara_rule_file = YaraRuleFile(str(datadir / 'invalid_syntax.yar'))
    assert yara_rule_file.is_error_state
    assert yara_rule_file.compile_error is not None
    # no YaraRule object should be loaded
    assert not yara_rule_file.yara_rules

@pytest.mark.unit
def test_YaraRuleFile_valid_syntax(datadir):
    yara_rule_file = YaraRuleFile(str(datadir / 'valid_syntax.yar'))
    assert not yara_rule_file.is_error_state
    assert yara_rule_file.compile_error is None
    assert yara_rule_file.plyara_error is None
    # a single yara rule should be loaded
    assert len(yara_rule_file.yara_rules) == 1
    assert yara_rule_file.last_mtime is not None
    assert yara_rule_file.namespace == DEFAULT_NAMESPACE

@pytest.mark.unit
def test_YaraRuleFile_file_modified(datadir):
    file_path = str(datadir / 'valid_syntax.yar')
    yara_rule_file = YaraRuleFile(file_path)
    with open(file_path, 'w') as fp:
        fp.write("""
rule updated_rule {
    strings:
        $ = "test"
    condition:
        any of them
}""")

    # keep a reference to this rule
    yara_rule = yara_rule_file.yara_rules[0]
    yara_rule.is_valid
    assert yara_rule_file.is_modified
    assert yara_rule_file.update()
    # after the file is updated, the original YaraRule object is no longer valid
    assert not yara_rule.is_valid
    # not modified as this point
    assert not yara_rule_file.is_modified

@pytest.mark.unit
def test_YaraRuleFile_good_failed_fixed(datadir):
    # yara file is good initially
    file_path = str(datadir / 'valid_syntax.yar')
    yara_rule_file = YaraRuleFile(file_path)

    # keep a reference to the original rule
    yara_rule = yara_rule_file.yara_rules[0]
    assert yara_rule.is_valid

    # then someone makes a mistake
    with open(file_path, 'w') as fp:
        fp.write("""
rule whoops {
    strings:
        $ = "test"
    condition:
        all of tham 
}""")

    assert yara_rule_file.is_modified
    assert not yara_rule_file.update()
    assert yara_rule_file.is_error_state
    assert yara_rule_file.compile_error is not None
    assert not yara_rule_file.yara_rules

    # someone fixes it
    with open(file_path, 'w') as fp:
        fp.write("""
rule whoops {
    strings:
        $ = "test"
    condition:
        all of them
}""")

    assert yara_rule_file.is_modified
    assert yara_rule_file.update()
    assert not yara_rule_file.is_error_state
    assert yara_rule_file.compile_error is None

@pytest.mark.unit
def test_YaraRuleFile_disable_plyara(tmp_path):
    rule_path = tmp_path / 'test.yar'
    rule_path.write_text(_generate_yara_rule("test_rule"))
    yara_rule_file = YaraRuleFile(rule_path, disable_plyara=True)
    assert yara_rule_file.disable_plyara
    # should not have any YaraRule objects loaded because they come from plyara parsing
    assert not yara_rule_file.yara_rules

@pytest.mark.unit
def test_YaraRuleFile_dependencies(tmp_path):
    rule_path = tmp_path / 'test.yar'
    rule_path.write_text("""
rule rule_1 {
    strings:
        $ = "hello world"
    condition:
        all of them
}

rule rule_2 {
    strings:
        $ = "hey"
    condition:
        all of them and rule_1
}
""")
    yara_rule_file = YaraRuleFile(rule_path)
    # dependencies are not supported
    assert yara_rule_file.plyara_error is not None
    assert len(yara_rule_file.yara_rules) == 0

@pytest.mark.unit
def test_YaraRuleFile_includes(tmp_path):

    #
    # the include syntax is technically supported
    # but it seems you have to specify the full path to the file
    #

    target_path = tmp_path / 'target.yar'
    target_path.write_text("""
rule rule_2 {
    strings:
        $ = "hey"
    condition:
        all of them
}
""")

    source_path = tmp_path / 'source.yar'
    source_path.write_text(f"""
include "{target_path}"
rule rule_1 {{
    strings:
        $ = "hello world"
    condition:
        all of them
}}
""")

    yara_rule_file = YaraRuleFile(str(source_path))
    assert not yara_rule_file.is_error_state
    assert not yara_rule_file.plyara_error
    # only one yara rule is loaded from this even though there is an include for more
    assert len(yara_rule_file.yara_rules) == 1

@pytest.mark.parametrize('file_path,result', [
    (None, False),
    ('', False),
    ('test.yar', True),
    ('test.yara', True),
    ('TEST.YAR', True),
    ('TEST.YARA', True),
    ('test.txt', False)
])
@pytest.mark.unit
def test_is_yara_file(file_path, result):
    assert is_yara_file(file_path) == result

@pytest.mark.unit
def test_YaraRuleDirectory_new_empty(tmpdir):
    dir_path = str(tmpdir.mkdir("rules"))
    rule_dir = YaraRuleDirectory(dir_path)
    # should be initially empty
    assert not rule_dir.tracked_files

@pytest.mark.unit
def test_YaraRuleDirectory_new_single_rule(tmpdir):
    dir_path = str(tmpdir.mkdir("rules"))
    with open(os.path.join(dir_path, "test.yar"), "w") as fp:
        fp.write(_generate_yara_rule("rule_1"))

    rule_dir = YaraRuleDirectory(dir_path)
    assert len(rule_dir.tracked_files) == 1

@pytest.mark.unit
def test_YaraRuleDirectory_new_multi_rules(tmpdir):
    dir_path = str(tmpdir.mkdir("rules"))
    for i in range(2):
        with open(os.path.join(dir_path, f"test_{i}.yar"), "w") as fp:
            fp.write(_generate_yara_rule(f"rule_{i}"))

    rule_dir = YaraRuleDirectory(dir_path)
    assert len(rule_dir.tracked_files) == 2

@pytest.mark.unit
def test_YaraRuleDirectory_remove_missing_files(tmp_path):
    dir_path = tmp_path / "rules"
    dir_path.mkdir()
    rule_path = dir_path / "test.yar"
    rule_path.write_text(_generate_yara_rule("rule_1"))
    rule_dir = YaraRuleDirectory(dir_path)
    assert len(rule_dir.tracked_files) == 1
    rule_path.unlink()
    rule_dir.refresh()
    assert len(rule_dir.tracked_files) == 0

@pytest.mark.unit
def test_YaraRuleDirectory_update_new_file(tmpdir):
    dir_path = str(tmpdir.mkdir("rules"))
    rule_dir = YaraRuleDirectory(dir_path)
    # initially empty
    assert not rule_dir.tracked_files

    with open(os.path.join(dir_path, "test.yar"), "w") as fp:
        fp.write(_generate_yara_rule("test_rule"))

    rule_dir.refresh()
    assert len(rule_dir.tracked_files) == 1

@pytest.mark.unit
def test_YaraRuleDirectory_update_existing_file(tmp_path):
    dir_path = tmp_path / "rules"
    dir_path.mkdir()
    rule_path = dir_path / "test.yar"
    rule_path.write_text(_generate_yara_rule("test_rule"))
    rule_dir = YaraRuleDirectory(str(dir_path))
    # grab the reference to the yara rule file
    yara_rule_file = rule_dir.tracked_files[str(rule_path)]
    # and the yara rule
    yara_rule = yara_rule_file.yara_rules[0]
    assert yara_rule.is_valid
    assert not yara_rule_file.is_modified
    rule_dir.refresh()
    # nothing changed so should still be valid
    assert yara_rule.is_valid
    assert not yara_rule_file.is_modified

    rule_path.write_text(_generate_yara_rule("test_rule_2"))
    assert yara_rule_file.is_modified
    rule_dir.refresh()
    # now it should be modified
    assert not yara_rule_file.is_modified
    # and now the old one should be invalid
    assert not yara_rule.is_valid
    # and there should be a new YaraRule object
    assert not (yara_rule_file.yara_rules[0] is yara_rule)

@pytest.mark.unit
def test_get_current_repo_commit(tmp_path):
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    rule_path = rule_dir / "test_rule.yar"
    rule_path.write_text(_generate_yara_rule("test_rule"))

    # intially not a git repo
    assert get_current_repo_commit(str(rule_dir)) is None

    # is a repo but does not have a commit
    subprocess.run(['git', '-C', str(rule_dir), 'init'], stdout=DEVNULL, stderr=DEVNULL, check=True)
    assert get_current_repo_commit(str(rule_dir)) is None

    # has a commit
    subprocess.run(['git', '-C', str(rule_dir), 'add', 'test_rule.yar'], stdout=PIPE, stderr=PIPE)
    subprocess.run(['git', '-C', str(rule_dir), 'commit', '-m' 'testing'], stdout=PIPE, stderr=PIPE)
    current_commit = get_current_repo_commit(str(rule_dir))
    assert current_commit

    rule_path = rule_dir / "test_rule_2.yar"
    rule_path.write_text(_generate_yara_rule("test_rule_2"))
    subprocess.run(['git', '-C', str(rule_dir), 'add', 'test_rule_2.yar'], stdout=PIPE, stderr=PIPE)
    subprocess.run(['git', '-C', str(rule_dir), 'commit', '-m' 'testing'], stdout=PIPE, stderr=PIPE)
    next_commit = get_current_repo_commit(str(rule_dir))
    assert next_commit

    assert current_commit != next_commit

@pytest.mark.unit
def test_YaraRuleRepository_new(tmp_path):
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    rule_path = rule_dir / "test_rule.yar"
    rule_path.write_text(_generate_yara_rule("test_rule"))

    subprocess.run(['git', '-C', str(rule_dir), 'init'], stdout=PIPE, stderr=PIPE)
    subprocess.run(['git', '-C', str(rule_dir), 'add', 'test_rule.yar'], stdout=PIPE, stderr=PIPE)
    subprocess.run(['git', '-C', str(rule_dir), 'commit', '-m' 'testing'], stdout=PIPE, stderr=PIPE)

    yara_repo = YaraRuleRepository(str(rule_dir))
    assert len(yara_repo.tracked_files) == 1

@pytest.mark.unit
def test_YaraRuleRepository_rule_modified(tmp_path):
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    rule_path = rule_dir / "test_rule.yar"
    rule_path.write_text(_generate_yara_rule("test_rule"))

    subprocess.run(['git', '-C', str(rule_dir), 'init'], stdout=PIPE, stderr=PIPE)
    subprocess.run(['git', '-C', str(rule_dir), 'add', 'test_rule.yar'], stdout=PIPE, stderr=PIPE)
    subprocess.run(['git', '-C', str(rule_dir), 'commit', '-m' 'testing'], stdout=PIPE, stderr=PIPE)

    yara_repo = YaraRuleRepository(str(rule_dir))
    assert len(yara_repo.tracked_files) == 1

    # keep a reference to the YaraRule
    yara_rule = yara_repo.tracked_files[str(rule_path)].yara_rules[0]

    # update the yara rule
    rule_path.write_text(_generate_yara_rule("different_rule"))
    yara_repo.refresh()

    # yara rule should still be valid because the commit did not change
    assert yara_rule.is_valid

    # commit the changes
    subprocess.run(['git', '-C', str(rule_dir), 'add', 'test_rule.yar'], stdout=PIPE, stderr=PIPE)
    subprocess.run(['git', '-C', str(rule_dir), 'commit', '-m' 'testing'], stdout=PIPE, stderr=PIPE)
    yara_repo.refresh()

    # now the rule should be invalid
    assert not yara_rule.is_valid

@pytest.mark.unit
def test_YaraRuleRepository_repo_broken(tmp_path):
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    rule_path = rule_dir / "test_rule.yar"
    rule_path.write_text(_generate_yara_rule("test_rule"))

    subprocess.run(['git', '-C', str(rule_dir), 'init'], stdout=PIPE, stderr=PIPE)
    subprocess.run(['git', '-C', str(rule_dir), 'add', 'test_rule.yar'], stdout=PIPE, stderr=PIPE)
    subprocess.run(['git', '-C', str(rule_dir), 'commit', '-m' 'testing'], stdout=PIPE, stderr=PIPE)

    yara_repo = YaraRuleRepository(str(rule_dir))
    assert len(yara_repo.tracked_files) == 1

    # keep a reference to the YaraRule
    yara_rule = yara_repo.tracked_files[str(rule_path)].yara_rules[0]

    # update the yara rule
    rule_path.write_text(_generate_yara_rule("different_rule"))
    yara_repo.refresh()

    # yara rule should still be valid because the commit did not change
    assert yara_rule.is_valid

    # modify the yara rule
    rule_path.write_text(_generate_yara_rule("rule_modified"))

    # break the repo
    git_dir = rule_dir / '.git'
    shutil.rmtree(str(git_dir))

    yara_repo.refresh()

    # rule should still be valid because we can't check the commit
    assert yara_rule.is_valid

@pytest.mark.parametrize('yara_rule_source,expected_result', [
    # test single rule
    ( _generate_yara_rule("test_rule"), "test_rule" ),
    # test multiple rules
    ( f'{_generate_yara_rule("test_rule_1")}\n{_generate_yara_rule("test_rule_2")}', "test_rule_1,test_rule_2" ),
    # order does not matter
    ( f'{_generate_yara_rule("test_rule_2")}\n{_generate_yara_rule("test_rule_1")}', "test_rule_1,test_rule_2" ),
])
@pytest.mark.unit
def test_generate_context_key(yara_rule_source, expected_result, tmp_path):
    rule_file = tmp_path / "rule.yar"
    rule_file.write_text(yara_rule_source)
    yara_rule_file = YaraRuleFile(str(rule_file))

    assert generate_context_key(yara_rule_file.yara_rules) == expected_result

@pytest.mark.unit
def test_generate_context_key_empty_list(tmp_path):
    assert generate_context_key([]) == ''

@pytest.mark.unit
def test_YaraContext_new(tmp_path):
    rule_file = tmp_path / "rule.yar"
    yara_source = _generate_yara_rule("test_rule")
    rule_file.write_text(yara_source)
    yara_rule_file = YaraRuleFile(str(rule_file))
    yara_context = YaraContext(yara_rules=yara_rule_file.yara_rules)
    # the source won't be exactly the same
    assert len(yara_context.yara_rules) == 1
    assert len(yara_context.yara_rule_files) == 0

@pytest.mark.unit
def test_YaraContext_new_from_file(tmp_path):
    rule_file = tmp_path / "rule.yar"
    yara_source = _generate_yara_rule("test_rule")
    rule_file.write_text(yara_source)
    yara_rule_file = YaraRuleFile(str(rule_file))
    yara_context = YaraContext(yara_rule_files=[yara_rule_file])
    # the source should be exactly the same
    assert yara_context.sources[DEFAULT_NAMESPACE] == yara_source
    assert len(yara_context.yara_rules) == 0
    assert len(yara_context.yara_rule_files) == 1

@pytest.mark.unit
def test_YaraContext_yara_rule_modified(tmp_path):
    rule_file = tmp_path / "rule.yar"
    yara_source = _generate_yara_rule("test_rule")
    rule_file.write_text(yara_source)
    yara_rule_file = YaraRuleFile(str(rule_file))
    yara_context = YaraContext(yara_rules=yara_rule_file.yara_rules)
    assert yara_context.is_valid
    yara_rule_file.update()
    # after the file changes the context is no longer valid
    assert not yara_context.is_valid

@pytest.mark.unit
def test_YaraContext_yara_rule_file_modified(tmp_path):
    rule_file = tmp_path / "rule.yar"
    rule_file.write_text(_generate_yara_rule("test_rule"))
    yara_rule_file = YaraRuleFile(str(rule_file), disable_plyara=True)
    yara_context = YaraContext(yara_rule_files=[yara_rule_file])
    assert yara_context.is_valid

    # yara rule file is modified
    rule_file.write_text(_generate_yara_rule("rule_modified"))
    yara_rule_file.update()
    assert not yara_context.is_valid

@pytest.mark.unit
def test_YaraContext_yara_rule_file_missing(tmp_path):
    rule_file = tmp_path / "rule.yar"
    rule_file.write_text(_generate_yara_rule("test_rule"))
    yara_rule_file = YaraRuleFile(str(rule_file), disable_plyara=True)
    yara_context = YaraContext(yara_rule_files=[yara_rule_file])
    assert yara_context.is_valid

    # yara rule file is modified
    rule_file.unlink()
    yara_rule_file.update()
    assert not yara_context.is_valid

@pytest.mark.unit
def test_YaraScanner_new():
    scanner = YaraScanner()
    assert not scanner.tracked_files
    assert not scanner.tracked_dirs
    assert not scanner.tracked_repos
    assert scanner.default_timeout == DEFAULT_TIMEOUT
    assert not scanner.yara_contexts

@pytest.mark.unit
def test_YaraScanner_track_yara_file(tmp_path):
    rule_path = tmp_path / "rule.yar"
    rule_path.write_text(_generate_yara_rule("test_rule"))

    scanner = YaraScanner()
    scanner.track_yara_file(str(rule_path))
    assert len(scanner.tracked_files) == 1
    assert len(scanner.all_yara_rule_files) == 1

    # same file tracked twice is ignored
    scanner.track_yara_file(str(rule_path))
    assert len(scanner.tracked_files) == 1
    assert len(scanner.all_yara_rule_files) == 1

@pytest.mark.unit
def test_YaraScanner_track_yara_dir(tmp_path):
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    rule_path = rule_dir / "test_rule.yar"
    rule_path.write_text(_generate_yara_rule("test_rule"))

    not_a_dir = tmp_path / "not_a_dir"
    not_a_dir.write_text("test")

    scanner = YaraScanner()
    scanner.track_yara_dir(str(rule_dir))
    assert len(scanner.tracked_dirs) == 1
    assert len(scanner.all_yara_rule_files) == 1

    # same dir tracked twice is ignored
    scanner.track_yara_dir(str(rule_dir))
    assert len(scanner.tracked_dirs) == 1
    assert len(scanner.all_yara_rule_files) == 1

    # non-directories are ignored
    scanner.track_yara_dir(str(not_a_dir))
    assert len(scanner.tracked_dirs) == 1
    assert len(scanner.all_yara_rule_files) == 1

@requires_git
@pytest.mark.unit
def test_YaraScanner_track_yara_repo(tmp_path):
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    
    rule_path = rule_dir / "test_rule.yar"
    rule_path.write_text(_generate_yara_rule("test_rule"))

    not_a_dir = tmp_path / "not_a_dir"
    not_a_dir.write_text("test")

    not_a_repo = tmp_path / "not_a_repo"
    not_a_repo.mkdir()

    other_rule_path = not_a_repo / "other_rule.yar"
    other_rule_path.write_text(_generate_yara_rule("other_rule"))

    result = subprocess.run(['git', '-C', str(rule_dir), 'init'], stdout=PIPE, stderr=PIPE)
    result = subprocess.run(['git', '-C', str(rule_dir), 'add', 'test_rule.yar'], stdout=PIPE, stderr=PIPE)
    result = subprocess.run(['git', '-C', str(rule_dir), 'commit', '-m' 'testing'], stdout=PIPE, stderr=PIPE)

    scanner = YaraScanner()
    scanner.track_yara_repository(str(rule_dir))
    assert len(scanner.tracked_repos) == 1
    assert len(scanner.all_yara_rule_files) == 1

    # same dir tracked twice is ignored
    scanner.track_yara_repository(str(rule_dir))
    assert len(scanner.tracked_repos) == 1
    assert len(scanner.all_yara_rule_files) == 1

    # non-directories are ignored
    scanner.track_yara_repository(str(not_a_dir))
    assert len(scanner.tracked_repos) == 1
    assert len(scanner.all_yara_rule_files) == 1

    # non-git repos are ignored
    scanner.track_yara_repository(str(not_a_repo))
    assert len(scanner.tracked_repos) == 1
    assert len(scanner.all_yara_rule_files) == 1

@pytest.mark.unit
def test_YaraScanner_load_signature_directory(shared_datadir):
    scanner = YaraScanner(signature_dir=str(shared_datadir / 'signatures'))
    assert len(scanner.tracked_dirs) == 2
    assert len(scanner.all_yara_rule_files) == 2
    # each directory has one file
    for dir_path, yara_dir in scanner.tracked_dirs.items():
        assert len(yara_dir.tracked_files) == 1

@pytest.mark.unit
def test_YaraScanner_load_signature_directory_non_directory(tmp_path):
    signature_dir = tmp_path / 'signatures'
    signature_dir.mkdir()
    non_dir_path = signature_dir / 'test'
    non_dir_path.write_text("test")
    scanner = YaraScanner(signature_dir=str(signature_dir))
    assert len(scanner.tracked_dirs) == 0

@pytest.mark.unit
def test_YaraScanner_load_signature_directory_git_repo(tmp_path):
    signature_dir = tmp_path / 'signatures'
    signature_dir.mkdir()
    repo_dir = signature_dir / 'test'
    repo_dir.mkdir()
    repo_rule_path = repo_dir / "repo_rule.yar"
    repo_rule_path.write_text(_generate_yara_rule("repo_rule"))

    result = subprocess.run(['git', '-C', str(repo_dir), 'init'], stdout=PIPE, stderr=PIPE)
    result = subprocess.run(['git', '-C', str(repo_dir), 'add', 'repo_rule.yar'], stdout=PIPE, stderr=PIPE)
    result = subprocess.run(['git', '-C', str(repo_dir), 'commit', '-m' 'testing'], stdout=PIPE, stderr=PIPE)

    scanner = YaraScanner(signature_dir=str(signature_dir))
    assert len(scanner.tracked_dirs) == 0
    assert len(scanner.tracked_repos) == 1

@pytest.mark.unit
def test_YaraScanner_get_unparsed_yara_rule_files(tmp_path):
    rule_file = tmp_path / "rule.yar"
    rule_file.write_text(_generate_yara_rule("test_rule"))

    # should have zero unparsed yara rules here
    scanner = YaraScanner()
    scanner.track_yara_file(str(rule_file))
    assert not scanner.get_unparsed_yara_rule_files()

    # should have one unparsed yara rules here
    scanner = YaraScanner()
    scanner.track_yara_file(str(rule_file), disable_plyara=True)
    assert scanner.get_unparsed_yara_rule_files()

@pytest.mark.unit
def test_YaraScanner_check_rules(tmp_path):
    # a single yara rule
    single_rule_path = tmp_path / "test_rule.yar"
    single_rule_path.write_text(_generate_yara_rule("single_rule"))

    # a directory of yara rules
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    dir_rule_path = rule_dir / "dir_rule.yar"
    dir_rule_path.write_text(_generate_yara_rule("dir_rule"))

    # a repo of yara rules
    repo_dir = tmp_path / "rule_repo"
    repo_dir.mkdir()
    repo_rule_path = repo_dir / "repo_rule.yar"
    repo_rule_path.write_text(_generate_yara_rule("repo_rule"))

    result = subprocess.run(['git', '-C', str(repo_dir), 'init'], stdout=PIPE, stderr=PIPE)
    result = subprocess.run(['git', '-C', str(repo_dir), 'add', 'repo_rule.yar'], stdout=PIPE, stderr=PIPE)
    result = subprocess.run(['git', '-C', str(repo_dir), 'commit', '-m' 'testing'], stdout=PIPE, stderr=PIPE)

    scanner = YaraScanner()
    scanner.track_yara_file(str(single_rule_path))
    scanner.track_yara_dir(str(rule_dir))
    scanner.track_yara_repository(str(repo_dir))

    # get references to all the loaded YaraRule objects
    yara_rules = [_.yara_rules[0] for _ in scanner.all_yara_rule_files]
    assert len(yara_rules) == 3

    scanner.check_rules()

    # all the rules should still be valid because nothing has changed
    assert all([_.is_valid for _ in yara_rules])

    # modify all the rules
    single_rule_path.write_text(_generate_yara_rule("updated_single_rule"))
    dir_rule_path.write_text(_generate_yara_rule("updated_dir_rule"))
    repo_rule_path.write_text(_generate_yara_rule("updated_repo_rule"))
    result = subprocess.run(['git', '-C', str(repo_dir), 'commit', '-a', '-m' 'testing'], stdout=PIPE, stderr=PIPE)

    scanner.check_rules()

    # all the rules should still be invalid because everything changed
    assert all([not _.is_valid for _ in yara_rules])

    yara_rules = [_.yara_rules[0] for _ in scanner.all_yara_rule_files]
    assert len(yara_rules) == 3

@pytest.mark.unit
def test_YaraScanner_get_yara_context(tmp_path):
    rule_path = tmp_path / "test_rule.yar"
    rule_path.write_text(_generate_yara_rule("test_rule"))

    scanner = YaraScanner()
    scanner.track_yara_file(rule_path)

    scan_target = tmp_path / "target.txt"
    scan_target.write_text("test")

    # get the initial context for this file
    context = scanner.get_yara_context(str(scan_target))

    # nothing changes so context should stay the same
    scanner.check_rules()
    assert scanner.get_yara_context(str(scan_target)) is context

    # modify the yara rule
    rule_path.write_text(_generate_yara_rule("test_rule", search="something else"))
    scanner.check_rules()

    # we should have a different context now
    assert not (scanner.get_yara_context(str(scan_target)) is context)

@pytest.mark.unit
def test_YaraScanner_get_yara_context_empty(tmp_path):
    scanner = YaraScanner()
    scan_target = tmp_path / "target.txt"
    scan_target.write_text("test")
    context = scanner.get_yara_context(str(scan_target))
    assert context is not None
    assert context.context is not None
    assert not context.sources

@pytest.mark.unit
def test_YaraScanner_get_yara_context_invalid_syntax_fixed(tmp_path):
    rule_path = tmp_path / "test_rule.yar"
    rule_path.write_text("""rule { """)

    scanner = YaraScanner()
    scanner.track_yara_file(rule_path)

    scan_target = tmp_path / "target.txt"
    scan_target.write_text("test")

    # get the initial context for this file
    bad_context = scanner.get_yara_context(str(scan_target))
    # nothing should actually be loaded
    assert not bad_context.sources

    # fix the rule
    rule_path.write_text(_generate_yara_rule("test_rule"))
    scanner.check_rules()

    # should get a different context
    good_context = scanner.get_yara_context(str(scan_target))
    assert not (good_context is bad_context)

    # and should have rules loaded
    assert good_context.sources

@pytest.mark.parametrize('timeout', [ None, 0 ])
@pytest.mark.unit
def test_YaraScanner_scan(timeout, tmp_path):
    rule_path = tmp_path / "test_rule.yar"
    rule_path.write_text(_generate_yara_rule("test_rule", search="hello world"))

    scan_target = tmp_path / "target.txt"
    scan_target.write_text("hello world")
    
    scanner = YaraScanner()
    scanner.track_yara_file(str(rule_path))

    assert scanner.scan(str(scan_target), timeout=timeout)

@pytest.mark.parametrize('timeout', [ None, 0 ])
@pytest.mark.unit
def test_YaraScanner_scan_data(timeout, tmp_path):
    rule_path = tmp_path / "test_rule.yar"
    rule_path.write_text(_generate_yara_rule("test_rule", search="hello world"))

    scanner = YaraScanner()
    scanner.track_yara_file(str(rule_path))

    # this should match
    assert scanner.scan_data('hello world', timeout=timeout)
    # this should also match
    assert scanner.scan_data(b'hello world', timeout=timeout)
    # this should not match
    assert not scanner.scan_data('random data', timeout=timeout)

@pytest.mark.integration
def test_YaraScanner_filtering(tmp_path):
    bas_rule_path = tmp_path / 'bas_rule.yar'
    bas_rule_path.write_text("""
rule bas_rule {
    meta:
        file_ext = "bas"
    strings:
        $ = "test_1"
    condition:
        any of them
}
""")

    exe_rule_path = tmp_path / 'exe_rule.yar'
    exe_rule_path.write_text("""
rule exe_rule {
    meta:
        file_ext = "exe"
    strings:
        $ = "test_2"
    condition:
        any of them
}
""")

    scanner = YaraScanner(disable_postfiltering=True)
    scanner.track_yara_file(str(bas_rule_path))
    scanner.track_yara_file(str(exe_rule_path))

    # these two contexts should be different
    assert not (scanner.get_yara_context("sample.bas") is scanner.get_yara_context("sample.exe"))
    # and these two should be the same
    assert scanner.get_yara_context("sample.bas") is scanner.get_yara_context("file.bas")

    target_file = tmp_path / 'target.exe'
    target_file.write_text("test_1")

    # even though test_1 matches bas_rule, we don't get a match because of the prefiltering
    assert not scanner.scan(str(target_file))

    scanner = YaraScanner(disable_prefiltering=True)
    scanner.track_yara_file(str(bas_rule_path))
    scanner.track_yara_file(str(exe_rule_path))

    # if prefiltering is disabled then there is only one context to be used
    assert scanner.get_yara_context("sample.bas") is scanner.get_yara_context("sample.exe")
    assert scanner.get_yara_context("sample.bas") is scanner.get_yara_context("file.bas")

    # but this also works because of post filtering
    assert not scanner.scan(str(target_file))

    scanner = YaraScanner(disable_prefiltering=True, disable_postfiltering=True)
    scanner.track_yara_file(str(bas_rule_path))
    scanner.track_yara_file(str(exe_rule_path))

    # if all filtering is disabled you get a single yara context
    assert scanner.get_yara_context("sample.bas") is scanner.get_yara_context("sample.exe")
    assert scanner.get_yara_context("sample.bas") is scanner.get_yara_context("file.bas")

    # but this matches because there is no filtering
    assert scanner.scan(str(target_file))

@pytest.mark.unit
def test_YaraScanner_json_match(tmp_path):
    rule_path = tmp_path / "test_rule.yar"
    rule_path.write_text(_generate_yara_rule("test_rule"))

    scan_target = tmp_path / "target.txt"
    scan_target.write_text("hello world")

    scanner = YaraScanner()
    scanner.track_yara_file(str(rule_path))
    scanner.scan(str(scan_target))
    json_result = json.loads(scanner.json)

    assert len(json_result) == 1
    assert isinstance(json_result[0], dict)
    assert json_result[0][RESULT_KEY_META] == {}
    assert json_result[0][RESULT_KEY_NAMESPACE] == DEFAULT_NAMESPACE
    assert json_result[0][RESULT_KEY_RULE] == "test_rule"
    assert json_result[0][RESULT_KEY_TAGS] == []
    assert json_result[0][RESULT_KEY_TARGET] == str(scan_target)
    assert RESULT_KEY_STRINGS in json_result[0]


@pytest.mark.integration
def test_YaraScanner_scan_results(scanner):
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

@pytest.mark.integration
def test_YaraScanner_file_scan_results(scanner, shared_datadir):
    assert scanner.scan(str(shared_datadir / 'scan_targets' / 'scan_target_1.txt'))

    assert os.path.basename(scanner.scan_results[0][RESULT_KEY_TARGET]) == 'scan_target_1.txt'
    assert scanner.scan_results[0][RESULT_KEY_META] == {}
    assert os.path.basename(scanner.scan_results[0][RESULT_KEY_NAMESPACE]) == 'ruleset_a'
    assert scanner.scan_results[0][RESULT_KEY_RULE] == 'rule_1'
    assert scanner.scan_results[0][RESULT_KEY_STRINGS] == [(0, '$', b'test_rule_1')]
    assert scanner.scan_results[0][RESULT_KEY_TAGS] == ['tag_1']

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

@pytest.mark.integration
@pytest.mark.parametrize("yara_rule_content, scan_target_name, scan_target_content, expected", meta_rule_tests)
def test_YaraScanner_meta_directives(tmp_path, yara_rule_content, scan_target_name, scan_target_content, expected):
    scanner = YaraScanner()
    yara_rule_path = create_file(str(tmp_path / 'rule.yar'), yara_rule_content)
    scan_target_path = create_file(str(tmp_path / scan_target_name), scan_target_content)
    scanner.track_yara_file(yara_rule_path)

    if expected:
        assert scanner.scan(scan_target_path)
        assert len(scanner.scan_results) == 1
    else:
        assert not scanner.scan(scan_target_path)
        assert len(scanner.scan_results) == 0

@pytest.mark.unit
def test_YaraScanner_test_no_rules(tmp_path, capsys):
    scanner = YaraScanner()
    config = TestConfig()
    config.test = True
    assert not scanner.test_rules(config)

TEST_RULE_1 = """
rule test_rule_1 {
    strings:
        $1 = "string 1"
        $2 = "string 2"
    condition:
        any of them
}"""

TEST_RULE_2 = """
rule test_rule_2 {
    strings:
        $1 = "string 1"
        $2 = "string 2"
    condition:
        any of them
}"""

TEST_RULE_NO_STRINGS = """
rule test_rule_no_strings {
    condition:
        uint16(0) == 0x5A4D
}
"""

TEST_RULE_REGEX = """
rule test_rule_regex {
    strings:
        $ = /test/
    condition:
        any of them
}
"""

@pytest.mark.parametrize('test_config, test_rules, test_data, create_csv, expected_result', [
    (None, [], None, False, False), # no config
    (TestConfig(test=False), [], None, False, False), # do not run test
    (TestConfig(test=True), [], None, False, False), # no rules
    (TestConfig(test=True), [TEST_RULE_1], None, False, True), # single rule
    (TestConfig(test=True), [TEST_RULE_1], "test", False, True), # single rule with test data
    #(TestConfig(test=True, show_progress_bar=True), [TEST_RULE_1], None, False, True), # with the progress bar
    (TestConfig(test=True, test_rule="test_rule_1"), [TEST_RULE_1, TEST_RULE_2], None, False, True), # specify a specific rule
    (TestConfig(test=True, test_rule="unknown_rule"), [TEST_RULE_1], None, False, False), # specify an unknown rule for testing 
    (TestConfig(test=True), [YARA_RULE_DEPENDENCY], None, False, True), # dependencies
    (TestConfig(test=True), ["rule {"], None, False, True), # invalid syntax
    (TestConfig(test=True, test_strings=True), [TEST_RULE_1], None, False, True), # test strings
    (TestConfig(test=True, test_strings=True), [TEST_RULE_REGEX], None, True, True), # test strings with csv output
    (TestConfig(test=True, test_strings=True, test_strings_if=True, test_strings_threshold=0.0), [TEST_RULE_1], None, False, True), # test strings if
    (TestConfig(test=True, test_strings=True), [TEST_RULE_NO_STRINGS], None, False, True), # test strings with no strings
    (TestConfig(test=True, test_strings=True), [TEST_RULE_REGEX], None, False, True), # test regex strings
])
@pytest.mark.integration
def test_YaraScanner_test_rules(test_config, test_rules, test_data, create_csv, expected_result, tmp_path, capsys):
    test_data_path = None
    if test_data:
        test_data_path = tmp_path / "test.txt"
        test_data_path.write_text(test_data)
        test_config.test_data = str(test_data_path)

    scanner = YaraScanner()
    for index, rule in enumerate(test_rules):
        rule_path = tmp_path / f"test_{index}.yar"
        rule_path.write_text(rule)
        scanner.track_yara_file(str(rule_path))

    if create_csv:
        test_config.performance_csv = str(tmp_path / "performance.csv")
        test_config.failure_csv = str(tmp_path / "failure.csv")
        test_config.string_performance_csv = str(tmp_path / "string_performance.csv")
        test_config.string_failure_csv = str(tmp_path / "string_failure.csv")

    if test_config:
        test_config.show_progress_bar = True

    assert scanner.test_rules(test_config) == expected_result
    output = capsys.readouterr()
