#!/usr/bin/env python3
# vim: sw=4:ts=4:et:cc=120
from __future__ import annotations

__version__ = "2.0.3"
__doc__ = """
Yara Scanner
============

A wrapper around the yara library for Python. ::

    scanner = YaraScanner()
    # start tracking this yara file
    scanner.track_yara_file('/path/to/yara_file.yar')
    scanner.load_rules()
    scan_results = scanner.scan('/path/to/file/to/scan')

    # reload yara rules
    scanner.check_rules()

    # track an entire directory of yara files
    scanner.track_yara_dir('/path/to/directory')
    # did any of the yara files in this directory change?
    scanner.check_rules()

    # track a git repository of yara rules
    scanner.track_yara_repo('/path/to/git_repo')
    # reload the yara rules ONLY if the git commit changed
    scanner.check_rules()

"""

import csv
import datetime
import functools
import gc
import io
import json
import logging
import multiprocessing
import os
import os.path
import pickle
import random
import re
import shutil
import signal
import socket
import struct
import sys
import threading
import time
import traceback
import uuid

from dataclasses import dataclass, Field
from operator import itemgetter
import hashlib
import tempfile
from subprocess import PIPE, Popen
from typing import Dict, List
from pathlib import Path

import plyara, plyara.utils
import progress.bar
import yara


# DEPRECATED
class RulesNotLoadedError(Exception):
    """Raised when a call is made to scan before any rules have been loaded."""

    pass


# keys to the JSON dicts you get back from YaraScanner.scan_results
RESULT_KEY_TARGET = "target"
RESULT_KEY_META = "meta"
RESULT_KEY_NAMESPACE = "namespace"
RESULT_KEY_RULE = "rule"
RESULT_KEY_STRINGS = "strings"
RESULT_KEY_TAGS = "tags"
ALL_RESULT_KEYS = [
    RESULT_KEY_TARGET,
    RESULT_KEY_META,
    RESULT_KEY_NAMESPACE,
    RESULT_KEY_RULE,
    RESULT_KEY_STRINGS,
    RESULT_KEY_TAGS,
]

# default yara external variable definitions
DEFAULT_YARA_EXTERNALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
}

# the default namespace to use if one is not specified
# yara python library does not like using an empty string for this
DEFAULT_NAMESPACE = "DEFAULT"

# the default timeout for scanning (in seconds)
DEFAULT_TIMEOUT = 10

# the default maximum bytes of a file we're willing to scan
# if you set this any higher you should also increase the default timeout
DEFAULT_MAX_BYTES = 100 * 1024 * 1024 # 100 MB

# how many yara contexts to keep in memory at one time
DEFAULT_MAX_CONTEXTS = 5 

META_FILTER_FILE_EXT = "file_ext"
META_FILTER_FILE_NAME = "file_name"
META_FILTER_FULL_PATH = "full_path"
META_FILTER_MIME_TYPE = "mime_type"

VALID_META_FILTERS = [
    META_FILTER_FILE_EXT,
    META_FILTER_FILE_NAME,
    META_FILTER_FULL_PATH,
    META_FILTER_MIME_TYPE,
]

yara.set_config(max_strings_per_rule=30720)
log = logging.getLogger("yara-scanner")


def generate_context_key(rules: list[YaraRule]):
    """Return the key to use for a give list of yara rules."""
    return ",".join(sorted([_.parsed_rule["rule_name"] for _ in rules]))


def is_yara_file(file_path: str) -> bool:
    """Returns True if the given file name or path looks like it might be a yara file."""
    if not file_path:
        return False

    if file_path.lower().endswith(".yar"):
        return True

    if file_path.lower().endswith(".yara"):
        return True

    return False


def get_mime_type(file_path: str) -> str:
    """Returns the mime type of the given file as returned by the file command."""
    p = Popen(["file", "-b", "--mime-type", file_path], stdout=PIPE, stderr=PIPE, text=True)
    mime_type, _ = p.communicate()
    return mime_type.strip()


def extract_filters_from_metadata(metadata: list[dict]) -> dict[str, str]:
    """Extract the meta directives for filtering.
    meta_dicts is the list of dicts that is the metadata field of what is returned by plyara
    Returns the dict of filter_name: filter_value"""

    result = {}
    for meta_dict in metadata:
        for key, value in meta_dict.items():
            if key in VALID_META_FILTERS:
                result[key] = value

    return result


class Filterable:
    def filter_check(self, filters: dict[str, str], file_path: str, mime_type: str = None) -> bool:
        for directive, value in filters.items():
            # you can invert the logic by starting the value with !
            inverted = False
            if value.startswith("!"):
                value = value[1:]
                inverted = True

            # you can use regex by starting string with re: (after optional negation)
            use_regex = False
            if value.startswith("re:"):
                value = value[3:]
                use_regex = True

            # or you can use substring matching with sub:
            use_substring = False
            if value.startswith("sub:"):
                value = value[4:]
                use_substring = True

            # figure out what we're going to compare against
            compare_target = None
            if directive.lower() == "file_ext":
                if "." not in file_path:
                    compare_target = ""
                else:
                    compare_target = file_path.rsplit(".", maxsplit=1)[1]

            elif directive.lower() == "mime_type":
                compare_target = mime_type

            elif directive.lower() == "file_name":
                compare_target = os.path.basename(file_path)

            elif directive.lower() == "full_path":
                compare_target = file_path

            else:
                # not a meta tag we're using
                log.error(f"not a valid meta directive {directive}")
                continue

            # log.debug("compare target is {} for directive {}".format(compare_target, directive))

            # figure out how to compare what is supplied by the user to the search target
            if use_regex:
                compare_function = lambda user_supplied, target: re.search(user_supplied, target, re.IGNORECASE)
            elif use_substring:
                compare_function = lambda user_supplied, target: user_supplied.lower() in target.lower()
            else:
                compare_function = lambda user_supplied, target: user_supplied.lower() == target.lower()

            matches = False
            for search_item in [x.strip() for x in value.lower().split(",")]:
                matches = matches or compare_function(search_item, compare_target)
                # log.debug("search item {} vs compare target {} matches {}".format(search_item, compare_target, matches))

            if (inverted and matches) or (not inverted and not matches):
                # log.debug(
                # "skipping yara rule {} for file {} directive {} list {} negated {} regex {} subsearch {}".format(
                # match_result.rule, file_path, directive, value, inverted, use_regex, use_substring
                # )
                # )
                return False

        return True


class YaraRuleDirectory:
    """A directory that contains yara rule files."""

    def __init__(self, dir_path: str, disable_prefilter: bool = False, compiled_rules_dir: str = None):
        # the path to the directory that contains the yara rules
        self.dir_path = dir_path
        # if this is set then we disable prefiltering
        self.disable_prefilter = disable_prefilter
        # directory to store compiled rules into
        self.compiled_rules_dir = compiled_rules_dir
        # map file path to yara rule file
        self.tracked_files = {}  # key = path, value = YaraRuleFile

        self.refresh()

    @property
    def yara_rule_files(self) -> list["YaraRuleFile"]:
        """Returns the list of currently tracked YaraRuleFile objects."""
        return [_ for _ in self.tracked_files.values()]

    def refresh(self):
        self.update_existing_files()
        self.load_new_files()
        self.remove_missing_files()

    def load_new_files(self):
        """Starts tracking any new files that have appeared in this directory since the last time it was loaded."""
        for file_path in os.listdir(self.dir_path):
            file_path = os.path.join(self.dir_path, file_path)
            # if this is not a yara file then ignore it
            if not is_yara_file(file_path):
                continue

            if file_path not in self.tracked_files:
                log.debug(f"detected new yara file {file_path} in {self.dir_path}")
                # we use the directory path as the namespace for yara rules
                self.tracked_files[file_path] = YaraRuleFile(
                    file_path,
                    namespace=self.dir_path,
                    disable_prefilter=self.disable_prefilter,
                    compiled_rules_dir=self.compiled_rules_dir,
                )

    def update_existing_files(self):
        """Updates all tracked yara files."""
        for file_path, yara_rule_file in self.tracked_files.items():
            yara_rule_file.refresh()

    def remove_missing_files(self):
        """Removes any missing files from tracking."""
        removed_files = []
        for file_path, yara_rule_file in self.tracked_files.items():
            if yara_rule_file.is_deleted:
                log.info(f"yara file {file_path} was deleted from {self.dir_path}")
                removed_files.append(file_path)

        for removed_file in removed_files:
            del self.tracked_files[removed_file]


def get_current_repo_commit(dir_path: str) -> str:
    """Utility function to return the current commit hash for a given repo directory.  Returns None on failure."""
    p = Popen(["git", "-C", dir_path, "log", "-n", "1", "--format=oneline"], stdout=PIPE, stderr=PIPE, text=True)
    commit, stderr = p.communicate()

    if len(stderr.strip()) > 0:
        log.error(f"git reported an error on repo {dir_path}: {stderr.strip()}")
        return None

    if p.returncode != 0:  # pragma: no cover
        log.error(f"git returned a non-zero exit status on repo {dir_path}")
        return None

    if len(commit) < 40:  # pragma: no cover
        log.error(f"got {commit.strip()} for stdout with git log on repo {dir_path}")
        return None

    return commit[0:40]


class YaraRuleRepository(YaraRuleDirectory):
    """A git repository that contains yara rules."""

    def __init__(self, *args, **kwargs):
        # keep track of what the last commit was
        self.last_repo_commit = None
        super().__init__(*args, **kwargs)

    def refresh(self):
        """Only refresh if the git commit has changed."""
        current_repo_commit = get_current_repo_commit(self.dir_path)
        if not current_repo_commit:
            return

        if current_repo_commit != self.last_repo_commit:
            log.info(
                f"detected change in git repo {self.dir_path} " f"from {self.last_repo_commit} to {current_repo_commit}"
            )

            # works the same as a YaraRuleDirectory
            YaraRuleDirectory.refresh(self)
            self.last_repo_commit = current_repo_commit


class YaraRuleFile:
    """A file that contains one or more yara rules."""

    def __init__(
        self, file_path: str, namespace: str = None, disable_prefilter: bool = False, compiled_rules_dir: str = None
    ):
        # the path to the yara rule
        self.file_path = file_path
        # the contents of the yara file loaded into memory
        self.source = None
        # the sha256 of the source code
        self.source_sha256 = None
        # the namespace to use for these yara rules (optional)
        self.namespace = namespace if namespace else DEFAULT_NAMESPACE
        # set this to True to not use plyara (for filtering in advanced)
        self.disable_prefilter = disable_prefilter
        # the last time the yara rule file was modified
        self.last_mtime = None
        # set to True if the file was deleted
        self.is_deleted = False
        # the list of YaraRule objects created from this file
        # this may be empty if disable_prefilter is True or plyara cannot parse the file
        self.yara_rules = []
        # this is set if the yara rules fail to compile with libyara
        self.compile_error = None
        # this is set if the yara rules fail to parse with plyara
        self.plyara_error = None
        # directory to store compiled rules into
        self.compiled_rules_dir = compiled_rules_dir

        # process the yara file
        self.update()

    @property
    def is_error_state(self):
        """Returns True if the file is in some kind of an error state."""
        return self.compile_error is not None

    @property
    def is_plyara_incompatible(self):
        """Returns True if the file compiles with libyara but does not parse with plyara."""
        return self.plyara_error is not None

    @property
    def is_modified(self):
        """Returns True if this yara rule file has been modified since it was last loaded."""
        modified = False

        try:
            # has this yara rule been modified since the last time we loaded it?
            if os.path.getmtime(self.file_path) != self.last_mtime:
                return True
        except Exception as e:
            # has this yara rule been deleted?
            if not os.path.exists(self.file_path):
                self.is_deleted = True
                return True
            else:  # pragma: no cover
                # this would be something like file system failure
                log.error(f"error accessing {self.file_path}: {e}")
                return False

    def refresh(self):
        """Reloads the yara rule if it was modified since the last time it was loaded."""
        if self.is_modified:
            self.update()

    def update(self) -> bool:
        """Checks the state of the yara rule file and loads it into memory.
        Returns True if the update successfully loaded."""

        # clear the state flags
        self.compile_error = None
        self.plyara_error = None

        # invalidate the currently loaded rules
        for yara_rule in self.yara_rules:
            yara_rule.invalidate()

        self.yara_rules = []

        try:
            # load the source code into memory
            with open(self.file_path) as fp:
                self.source = fp.read()
        except Exception as e:
            self.compile_error = str(e)
            return False

        # compute the sha256 of the yara rule contents
        hasher = hashlib.sha256()
        hasher.update(self.source.encode(errors="ignore"))
        self.source_sha256 = hasher.hexdigest()

        # have we already compiled this rule?
        while True:
            if self.compiled_rules_dir:
                compiled_rule_path = os.path.join(self.compiled_rules_dir, self.source_sha256)
                if os.path.exists(compiled_rule_path):
                    break

            try:
                # verify that the source code compiles with libyara
                test_context = yara.compile(source=self.source)
                if self.compiled_rules_dir:
                    compiled_rule_path = os.path.join(self.compiled_rules_dir, self.source_sha256)

                    try:
                        test_context.save(compiled_rule_path)
                    except Exception as e:  # pragma: no cover
                        log.warning(
                            f"unable to save results of compiled yara file {self.file_path} to {compiled_rule_path}"
                        )

                break

            except Exception as e:
                log.error(f"yara file {self.file_path} fails to compile: {e}")
                self.compile_error = str(e)
                return False

        # remember the last time we loaded this rule from file
        self.last_mtime = os.path.getmtime(self.file_path)

        # if we are not using plyara then we are done here
        if self.disable_prefilter:
            return True

        try:
            parser = plyara.Plyara()

            # attempt to parse the rules
            rules = parser.parse_string(self.source)

            # ensure that each rule can be rebuilt and then compiles correctly
            for rule in rules:
                rebuilt_rule = plyara.utils.rebuild_yara_rule(rule)
                yara.compile(source=rebuilt_rule)

            log.debug(f"loaded {len(rules)} yara rules from {self.file_path}")
            for rule in rules:
                self.yara_rules.append(YaraRule(rule, namespace=self.namespace))

        except Exception as e:
            log.debug(f"failed to parse {self.file_path} with plyara: {e}")

            #
            # when a file fails to be parsed with plyara we assume something is wrong with plyara
            # in this case the rules in the yara file are just included in every scan
            #
            self.plyara_error = str(e)

        return True


class YaraRule(Filterable):
    """A single yara rule parsed out with plyara."""

    def __init__(self, parsed_rule: dict, *args, namespace: str = None, **kwargs):
        super().__init__()

        # the parsed rule as returned by plyara
        self.parsed_rule = parsed_rule
        # the namespace, if provided, that this rule came from
        self.namespace = namespace if namespace else DEFAULT_NAMESPACE

        # the list of meta filters for this yara rule
        self.filters = {}
        if "metadata" in self.parsed_rule:
            self.filters = extract_filters_from_metadata(self.parsed_rule["metadata"])

        # as long as this is set to True this rule can be used for scanning
        self.valid = True

    def __str__(self):
        return (
            f"YaraRule(name: {self.parsed_rule['rule_name']}, " f"namespace: {self.namespace}, " f"valid: {self.valid})"
        )

    def invalidate(self):
        self.valid = False

    @property
    def is_valid(self) -> bool:
        """Returns True if the rule is still valid.
        A rule becomes invalid if the source is modified in any way."""
        return self.valid


class YaraContext:
    """A compiled set of one or more yara rules or yara rule files."""

    def __init__(
        self,
        yara_rules: list[YaraRule] = None,
        yara_rule_files: list[YaraRuleFile] = None,
        compiled_rules_dir: str = None,
        context_cache_dir: str = None,
        max_contexts: int = DEFAULT_MAX_CONTEXTS,
    ):
        if yara_rules is None:
            yara_rules = []

        if yara_rule_files is None:
            yara_rule_files = []

        assert isinstance(yara_rules, list)
        assert all([isinstance(_, YaraRule) for _ in yara_rules])
        assert isinstance(yara_rule_files, list)
        assert all([isinstance(_, YaraRuleFile) for _ in yara_rule_files])

        if context_cache_dir:
            # unique path for caching the context to disk
            self.context_cache_path = os.path.join(context_cache_dir, str(uuid.uuid4()))
            # how long an idle context lives until it gets flushed out (in seconds)
            self.max_contexts = max_contexts
            # when the context should be flushed out
            self.context_flush_time = time.time() + self.max_contexts
        else:
            self.context_cache_path = None
            self.max_contexts = None
            self.context_flush_time = None

        # reference to the actual context itself
        self._context = None

        # the list of yara rules that are part of this context
        self.yara_rules = sorted(yara_rules, key=lambda x: x.parsed_rule["rule_name"])

        # the list of yara rule files that are also part of this context
        self.yara_rule_files = sorted(yara_rule_files, key=lambda x: x.file_path)

        # remember hash of the content so we know when it changes
        # so we know when something changed
        # maps file path to sha256
        self.yara_rule_file_sha256 = {_.file_path: _.source_sha256 for _ in self.yara_rule_files}

        # generate the source for this yara rule context
        sources = {}  # key = namespace, value = [] of rules
        yara_rule_count = 0
        for yara_rule in self.yara_rules:
            if yara_rule.namespace not in sources:
                sources[yara_rule.namespace] = []

            # NOTE rebuild_yara_rule is not deterministic
            sources[yara_rule.namespace].append(plyara.utils.rebuild_yara_rule(yara_rule.parsed_rule))
            yara_rule_count += 1

        yara_rule_file_count = 0
        for yara_rule_file in self.yara_rule_files:
            if yara_rule_file.namespace not in sources:
                sources[yara_rule_file.namespace] = []

            sources[yara_rule_file.namespace].append(yara_rule_file.source)
            yara_rule_file_count += 1

        log.debug(f"creating context with {yara_rule_count} parsed yara rules and {yara_rule_file_count} yara files")

        if not sources:
            log.warning("creating empty yara context")

        # for each namespace join the individual sources together with newlines
        sources = {namespace: "\n\n".join(yara_sources) for namespace, yara_sources in sources.items()}

        # the last time this context was used to scan
        self.last_used = time.time()

        # compute the sha256 of the combined source files
        # if we parsed out the yara rules then we don't do this because we cannot
        # deterministically rebuild the yara rules
        if not self.yara_rules and compiled_rules_dir is not None:
            hasher = hashlib.sha256()
            for namespace in sorted(sources.keys()):
                hasher.update(sources[namespace].encode(errors="ignore"))

            self.sha256 = hasher.hexdigest()

            # has this context already been created?
            compiled_yara_path = os.path.join(compiled_rules_dir, self.sha256)
            try:
                if os.path.exists(compiled_yara_path):
                    log.debug(f"loading compiled yara rules from {compiled_yara_path}")
                    start = datetime.datetime.now()
                    self._context = yara.load(compiled_yara_path)
                    end = datetime.datetime.now()
                    self.load_time_ms = int((end - start).total_seconds() * 1000)
                    log.debug(f"compiled yara rule loaded in {self.load_time_ms} ms")
                    return
            except Exception as e:
                log.warning(f"unable to load compiled yara file {compiled_yara_path}: {e}")

        # build the yara context
        start = datetime.datetime.now()
        self._context = yara.compile(sources=sources)
        end = datetime.datetime.now()
        self.compile_time_ms = int((end - start).total_seconds() * 1000)
        log.info(f"context compiled in {self.compile_time_ms} ms")

        # if we are using a cache for yara contexts then we go ahead and save the context
        if self.context_cache_path:
            try:
                self._context.save(self.context_cache_path)
            except Exception as e: # pragma: no cover
                log.warning(f"unable to cache context to {self.context_cache_path}: {e}")
                self.context_cache_path = None

        # if we parsed out the yara rules then we don't do this because we cannot
        # deterministically rebuild the yara rules
        if not self.yara_rules and compiled_rules_dir:
            log.debug(f"saving compiled yara rules to {compiled_rules_dir}")
            compiled_yara_path = os.path.join(compiled_rules_dir, self.sha256)
            try:
                self._context.save(compiled_yara_path)
            except Exception as e:  # pragma: no cover
                log.warning(f"unable to save compiled yara file {compiled_yara_path}: {e}")

    @property
    def context(self):
        """Returns the yara context for scanning. Loads from disk if the context has been flushed.
        Updates the context flush time."""
        # is context flushing not enabled?
        if not self.context_cache_path:
            return self._context

        # has the context been flushed out?
        if self._context is None:
            try:
                # load it back in
                self._context = yara.load(self.context_cache_path)
                log.info(f"loaded flushed context {self.context_cache_path}")
            except Exception as e:
                log.error(f"unable to load flushed context cache from {self.context_cache_path}: {e}")
                return None

        # reset the clock on the flush time
        self.last_used = time.time()
        return self._context

    def flush_context(self):
        """Deletes the yara context from memory."""
        # NOTE The current version of libyara (4.0.5) does not actually free the memory it uses.
        # But it does seem to re-use memory it has already allocated.

        # is context flushing not enabled?
        if not self.context_cache_path:
            return

        # is the context already flushed out?
        if not self._context:
            return

        # is it time to flush the context out?
        log.info(f"flushing yara context {self.context_cache_path}")
        self._context = None
        gc.collect() # this needs to happen right away (maybe?)

    @property
    def is_flushed(self):
        """Returns True if the yara context has been flushed."""
        if not self.context_cache_path:
            return False

        return self._context is None

    def delete_context_cache(self):
        """Deletes the context cache if it exists."""
        # is context flushing not enabled?
        if not self.context_cache_path:
            return

        try:
            if os.path.exists(self.context_cache_path):
                os.unlink(self.context_cache_path)
        except Exception as e: # pragma: no cover
            log.warning(f"unable to delete context cache {self.context_cache_path}: {e}")

    @property
    def is_valid(self) -> bool:
        """Returns True if all the yara rules and yara rule files are still valid."""
        for yara_rule in self.yara_rules:
            if not yara_rule.is_valid:
                return False

        for yara_rule_file in self.yara_rule_files:
            # did the sha256 change from the time we created this context?
            if yara_rule_file.source_sha256 != self.yara_rule_file_sha256[yara_rule_file.file_path]:
                log.debug(f"modified sha256 to {yara_rule_file} invalidates {self}")
                return False

            # is this yara rule now in an error state?
            # this should never happen since contexts cannot be created from rules that do not compile
            if yara_rule_file.is_error_state:  # pragma: no cover
                return False

        return True


class YaraJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return o.decode("utf-8", errors="backslashreplace")

        # scan results are either string or bytes
        return json.JSONEncoder.default(self, o)  # pragma: no cover


class YaraScanner(Filterable):
    """
    The primary object used for scanning files and data with yara rules."""

    def __init__(
        self,
        signature_dir=None,
        test_mode=False,
        default_timeout=DEFAULT_TIMEOUT,
        disable_prefilter=False,
        disable_postfilter=False,
        compiled_rules_dir=None,
        context_cache_dir=None,
        max_contexts=DEFAULT_MAX_CONTEXTS,
        max_bytes=DEFAULT_MAX_BYTES,
        *args,
        **kwargs,
    ):
        """
        Creates a new YaraScanner object.

        :param signature_dir: A directory that contains one directory per set
        of yara rules. Each subdirectory will get loaded into its own namespace
        (named after the path to the directory.) This is for convenience. Also
        see :func:`YaraScanner.track_yara_file`,
        :func:`YaraScanner.track_yara_dir`, and
        :func:`YaraScanner.track_yara_repo`.
        :type signature_dir: str or None

        """
        super().__init__()

        self.mime_type = None  # the last mime type we recorded on a scan of a file
        self._scan_results = []

        # we keep track of when the rules change and (optionally) automatically re-load the rules
        self.tracked_files = {}  # maps path to YaraRuleFile
        self.tracked_dirs = {}  # maps path to YaraRuleDirectory
        self.tracked_repos = {}  # maps path to YaraRuleRepository

        # the default amount of time (in seconds) a yara scan is allowed to take before it fails
        self.default_timeout = default_timeout

        # the maximum number of bytes to scan
        self.max_bytes = max_bytes

        # the dictionary of yara contexts to use for given rulesets
        self.yara_contexts = {}  # key = generate_context_key(), value = compiled yara context

        # if this is set then we disable prefiltering
        self.disable_prefilter = disable_prefilter

        # if this is set then we disable postfiltering
        self.disable_postfilter = disable_postfilter

        # optional directory to cache compiled yara rules
        self.compiled_rules_dir = compiled_rules_dir

        # a convenience function to load yara rules stored in a commonly seen organization
        if signature_dir is not None:
            self.load_signature_directory(signature_dir)

        # the directory to store cached yara contexts
        self.context_cache_dir = context_cache_dir
        if self.context_cache_dir:
            if not os.path.exists(self.context_cache_dir):
                os.mkdir(self.context_cache_dir)

        # how long a yara context will last until it is flushed out of memory (in second)
        self.max_contexts = max_contexts

        # the number of context requests
        self.context_cache_requests = 0

        # the number of times we hit a cached context
        self.context_cache_hit = 0

        # the number of times a context was found invalid
        self.context_cache_invalid = 0

        # the number of times we created a new context
        self.context_creation_count = 0

        # the number of times a context expired
        self.context_expiration_count = 0

    def load_signature_directory(self, signature_dir: str):
        """Loads a "signature directory".
        A signature directory contains one or more sub directories that each contain yara rules."""
        for dir_path in os.listdir(signature_dir):
            dir_path = os.path.join(signature_dir, dir_path)
            if not os.path.isdir(dir_path):
                continue

            if os.path.exists(os.path.join(dir_path, ".git")):
                self.track_yara_repository(dir_path)
            else:
                self.track_yara_dir(dir_path)

    @property
    def all_yara_rule_files(self):
        """Returns the list of all YaraRuleFile objects currently tracked."""
        result = []
        # all of the individually tracked files
        result.extend(self.tracked_files.values())
        # plus all of the files loaded from directories
        for yara_dir in self.tracked_dirs.values():
            result.extend(yara_dir.yara_rule_files)
        # plus all of the files loaded from repositories
        for yara_repo in self.tracked_repos.values():
            result.extend(yara_repo.yara_rule_files)
        return result

    def get_unparsed_yara_rule_files(self) -> list[YaraRuleFile]:
        """Returns the list of YaraRuleFile objects that were not parsed with plyara and not in an error state."""
        return [
            _
            for _ in self.all_yara_rule_files
            if not _.is_error_state and (_.is_plyara_incompatible or _.disable_prefilter)
        ]

    def get_yara_context(self, file_path: str = None, mime_type: str = None) -> YaraContext:
        """Returns the yara context to use for the given file.
        If a file is not specified, the default context is returned which contains all available rules."""
        # figure out which rules match which filters for teh given file

        self.context_cache_requests += 1

        filtered_yara_rules = []
        for yara_rule_file in self.all_yara_rule_files:
            for yara_rule in yara_rule_file.yara_rules:
                if file_path and not self.disable_prefilter:
                    if yara_rule.filter_check(yara_rule.filters, file_path, mime_type):
                        log.debug(f"{file_path} matches pre-filter for {yara_rule}")
                        filtered_yara_rules.append(yara_rule)
                else:
                    # if the file is not specified or prefiltering is disabled then we include all rules
                    filtered_yara_rules.append(yara_rule)

        # get the lookup key for this set of yara rules
        yara_context_key = generate_context_key(filtered_yara_rules)

        try:
            # do we already have this compiled?
            yara_context = self.yara_contexts[yara_context_key]
            self.context_cache_hit += 1
        except KeyError:
            yara_context = YaraContext(
                yara_rules=filtered_yara_rules,
                yara_rule_files=self.get_unparsed_yara_rule_files(),
                compiled_rules_dir=self.compiled_rules_dir,
                context_cache_dir=self.context_cache_dir,
                max_contexts=self.max_contexts,
            )
            self.yara_contexts[yara_context_key] = yara_context
            log.info(f"created new context - current count {len(self.yara_contexts)}")
            self.context_creation_count += 1

        # is this yara context still valid?
        if not yara_context.is_valid:
            # delete the cache file if it exists
            yara_context.delete_context_cache()
            # recreate the context with the new rules
            yara_context = YaraContext(
                yara_rules=filtered_yara_rules,
                yara_rule_files=self.get_unparsed_yara_rule_files(),
                compiled_rules_dir=self.compiled_rules_dir,
                context_cache_dir=self.context_cache_dir,
                max_contexts=self.max_contexts,
            )
            self.yara_contexts[yara_context_key] = yara_context
            log.info(f"replaced context - current count {len(self.yara_contexts)}")
            self.context_creation_count += 1
            self.context_cache_invalid += 1

        return yara_context

    def manage_yara_contexts(self):
        """Manages yara contexts by expiring ones not used in some time."""
        # sort the contexts by the last time they were used
        sorted_contexts = sorted(self.yara_contexts.values(), key=lambda c: c.last_used, reverse=True)
        # flush all contexts except for the first N
        for context in sorted_contexts[self.max_contexts:]:
            context.flush_context()

    def clear_yara_contexts(self):
        """Clears all yara contexts. Ensures all cache files are deleted."""
        for context in self.yara_contexts.values():
            context.delete_context_cache()

    @property
    def scan_results(self):
        """Returns the scan results of the most recent scan.

        This function returns a list of dict with the following format ::


                'target': str,
                'meta': dict,
                'namespace': str,
                'rule': str,
                'strings': list,
                'tags': list,
            }

        **target** is the target of the scane. In the case of file scans then target will be the path to the file that was scanned. In the case of data (raw binary) scans, this will be an empty string.

        **meta** is the dict of meta directives of the matching rule.

        **namespace** is the namespace the rule is in. In the case of repo and directory tracking, this will be the path of the directory. Otherwise it has a hard coded value of DEFAULT. *Setting the namespace to the path of the directory allows yara rules with duplicate names in different directories to be added to the same yara context.*

        **rule** is the name of the matching yara rule.

        **strings** is a list of tuples representing the individual string matches in the following format. ::

            (position, string_name, content)

        where **position** is the byte position of the match, **string_name** is the name of the yara string that matched, and **content** is the binary content it matched.

        **tags** is a list of tags contained in the matching rule.
        """
        return self._scan_results

    @scan_results.setter
    def scan_results(self, value):
        self._scan_results = value

    @property
    def json(self):
        """Returns the current scan results as a JSON formatted string."""
        return json.dumps(self.scan_results, indent=4, sort_keys=True, cls=YaraJSONEncoder)

    @functools.lru_cache()
    def git_available(self):
        """Returns True if git is available on the system, False otherwise."""
        return shutil.which("git")

    def track_yara_file(self, file_path):
        """Adds a single yara file.  The file is then monitored for changes to mtime, removal or adding."""
        # are we already tracking this file?
        if file_path in self.tracked_files:
            return

        self.tracked_files[file_path] = YaraRuleFile(
            file_path,
            namespace=None,
            disable_prefilter=self.disable_prefilter,
            compiled_rules_dir=self.compiled_rules_dir,
        )
        log.debug(f"tracking yara file {file_path}")

    def track_yara_dir(self, dir_path):
        """Adds all files in a given directory that end with .yar when converted to lowercase.
        All files are monitored for changes to mtime, as well as new and removed files."""
        if not os.path.isdir(dir_path):
            log.error(f"{dir_path} is not a directory")
            return

        # already tracking this one?
        if dir_path in self.tracked_dirs:
            return

        self.tracked_dirs[dir_path] = YaraRuleDirectory(
            dir_path, disable_prefilter=self.disable_prefilter, compiled_rules_dir=self.compiled_rules_dir
        )
        log.debug(f"tracking directory {dir_path} with {len(self.tracked_dirs[dir_path].tracked_files)} yara files")

    def track_yara_repository(self, dir_path):
        """Adds all files in a given directory **that is a git repository** that end with .yar when converted to lowercase.  Only commits to the repository trigger rule reload."""
        if not self.git_available():  # pragma: no cover
            log.warning("git cannot be found: defaulting to track_yara_dir")
            return self.track_yara_dir(dir_path)

        if not os.path.isdir(dir_path):
            log.error(f"{dir_path} is not a directory")
            return False

        if not os.path.exists(os.path.join(dir_path, ".git")):
            log.error(f"{dir_path} is not a git repository (missing .git)")
            return False

        if dir_path in self.tracked_repos:
            return False

        self.tracked_repos[dir_path] = YaraRuleRepository(
            dir_path, disable_prefilter=self.disable_prefilter, compiled_rules_dir=self.compiled_rules_dir
        )
        log.debug(f"tracking git repo {dir_path} with {len(self.tracked_repos[dir_path].tracked_files)} yara files")

    def check_rules(self):
        """
        Returns True if the rules need to be recompiled or reloaded, False
        otherwise. The criteria that determines if the rules are recompiled
        depends on how they are tracked.

        :rtype: bool"""

        for yara_rule_file in self.tracked_files.values():
            yara_rule_file.refresh()

        for yara_rule_dir in self.tracked_dirs.values():
            yara_rule_dir.refresh()

        for yara_rule_repo in self.tracked_repos.values():
            yara_rule_repo.refresh()

        return True

    def test_rules(self, test_config):
        if not test_config:
            return False

        if not test_config.test:
            return False

        file_count = len(self.all_yara_rule_files)

        # if we have no files to compile then we have nothing to do
        if file_count == 0:
            sys.stderr.write("ERROR: no yara files specified\n")
            return False

        # build the buffers we're going to use to test
        buffers = []  # [(buffer_name, buffer)]

        if test_config.test_data:  # random data to scan
            buffers.append(("random", test_config.test_data))
        else:
            buffers.append(("random", os.urandom(1024 * 1024)))

        # for x in range(255):
        # buffers.append((f"chr({x})", bytes([x]) * (1024 * 1024)))

        execution_times = []  # of (total_seconds, buffer_type, file_name, rule_name)
        execution_errors = []  # of (error_message, buffer_type, file_name, rule_name)
        string_execution_times = []
        string_errors = []

        bar = progress.bar.Bar("decompiling rules", max=file_count)
        parsed_rules = {}  # key = rule_name, value = parsed_yara_rule
        yara_sources = {}  # key = rule_name, value = yara_source_string
        yara_files = {}  # key = rule_name, value = file it came from
        for yara_rule_file in self.all_yara_rule_files:
            if test_config.show_progress_bar:
                bar.next()

            # did this rule compile?
            if yara_rule_file.is_error_state:
                log.warning(f"yara rule {yara_rule_file.file_path} does not compile: {yara_rule_file.compile_error}")
                continue

            # list of parsed rules for this yara rule file
            parsed_rule_list = []

            # did this not parse with plyara?
            if yara_rule_file.is_plyara_incompatible:
                try:
                    # parse it again if we can
                    # it was possible that there were dependency errors which we can handle here
                    parser = plyara.Plyara()
                    parsed_rule_list = parser.parse_string(yara_rule_file.source)
                except Exception as e:  # pragma: no cover
                    log.debug(f"yara rule {yara_rule_file.file_path} is unparsable with plyara: {e}")
                    continue
            else:
                # otherwise we can just use the parsing we did when we loaded the rules
                parsed_rule_list = [_.parsed_rule for _ in yara_rule_file.yara_rules]

            for parsed_rule in parsed_rule_list:
                # if we specified a rule to test then discard the others
                if test_config.test_rule and parsed_rule["rule_name"] != test_config.test_rule:
                    continue

                parsed_rules[parsed_rule["rule_name"]] = parsed_rule
                yara_sources[parsed_rule["rule_name"]] = yara_rule_file.source
                yara_files[parsed_rule["rule_name"]] = yara_rule_file.file_path

        if test_config.show_progress_bar:
            bar.finish()

        # did we specify an unknown rule?
        if test_config.test_rule and test_config.test_rule not in parsed_rules:
            log.error(f"unknown yara rule {test_config.test_rule}")
            return False

        steps = len(parsed_rules)

        class FancyBar(progress.bar.Bar):
            message = "testing"
            suffix = "%(percent).1f%% - %(eta_hms)s - %(rule)s (%(buffer)s)"
            rule = None
            buffer = None

            @property
            def eta_hms(self):
                seconds = self.eta
                seconds = seconds % (24 * 3600)
                hour = seconds // 3600
                seconds %= 3600
                minutes = seconds // 60
                seconds %= 60

                return "%d:%02d:%02d" % (hour, minutes, seconds)

        bar = FancyBar(max=steps)

        for rule_name in parsed_rules.keys():
            bar.rule = rule_name
            # some rules depend on other rules, so we deal with that here
            dependencies = []  # list of rule_names that this rule needs
            rule_context = None

            while True:
                # compile all the rules we've collected so far as one
                dep_source = "\n".join([plyara.utils.rebuild_yara_rule(parsed_rules[r]) for r in dependencies])
                try:
                    rule_context = yara.compile(
                        source=f"{dep_source}\n{plyara.utils.rebuild_yara_rule(parsed_rules[rule_name])}"
                    )
                    break
                except Exception as e:
                    # some rules depend on other rules
                    m = re.search(r'undefined identifier "([^"]+)"', str(e))
                    if m:
                        dependency = m.group(1)
                        if dependency in parsed_rules:
                            # add this rule to the compilation and try again
                            dependencies.insert(0, dependency)
                            continue

                    sys.stderr.write(  # pragma: no cover
                        f"rule {rule_name} in file {yara_files[rule_name]} does not compile by itself: {e}\n"
                    )
                    rule_context = None  # pragma: no cover
                    break  # pragma: no cover

            if not rule_context:  # pragma: no cover
                continue

            trigger_test_strings = False
            for buffer_name, buffer in buffers:
                try:
                    bar.buffer = buffer_name
                    if test_config.show_progress_bar:
                        bar.next()
                    start_time = time.time()
                    rule_context.match(data=buffer, timeout=5)
                    end_time = time.time()
                    total_seconds = end_time - start_time
                    execution_times.append([buffer_name, yara_files[rule_name], rule_name, total_seconds])
                    if test_config.test_strings_if and total_seconds > test_config.test_strings_threshold:
                        trigger_test_strings = True
                except Exception as e:  # pragma: no cover
                    execution_errors.append([buffer_name, yara_files[rule_name], rule_name, str(e)])
                    if test_config.test_strings_if:
                        trigger_test_strings = True

            if test_config.test_strings or trigger_test_strings:
                parser = plyara.Plyara()
                parsed_rule = None

                for _ in parser.parse_string(yara_sources[rule_name]):
                    if _["rule_name"] == rule_name:
                        parsed_rule = _

                # does this rule have any strings?
                if not "strings" in parsed_rule:
                    continue

                string_count = 1
                for string in parsed_rule["strings"]:
                    if string["type"] == "regex":
                        string_count += 1

                class FancyStringBar(progress.bar.Bar):
                    message = "processing"
                    suffix = "%(percent).1f%% - %(eta_hms)s - %(rule)s %(string)s (%(buffer)s)"
                    rule = None
                    string = None
                    buffer = None

                    @property
                    def eta_hms(self):
                        seconds = self.eta
                        seconds = seconds % (24 * 3600)
                        hour = seconds // 3600
                        seconds %= 3600
                        minutes = seconds // 60
                        seconds %= 60

                        return "%d:%02d:%02d" % (hour, minutes, seconds)

                string_bar = FancyStringBar(max=string_count * 256)
                string_bar.rule = rule_name

                for string in parsed_rule["strings"]:
                    if string["type"] == "regex":
                        string_bar.string = string["value"]
                        try:
                            string_name = string["name"]
                            string_value = string["value"]
                            temp_rule = f"""
                            rule temp_rule {{
                            strings:
                            $ = {string_value}
                            condition:
                            any of them
                            }}"""

                            string_rule_context = yara.compile(source=temp_rule)
                            for buffer_name, buffer in buffers:
                                string_bar.buffer = buffer_name
                                try:
                                    start_time = time.time()
                                    scan_result = string_rule_context.match(data=buffer, timeout=5)
                                    end_time = time.time()
                                    string_execution_times.append(
                                        [
                                            buffer_name,
                                            yara_files[rule_name],
                                            rule_name,
                                            string_name,
                                            len(scan_result),
                                            end_time - start_time,
                                        ]
                                    )
                                except Exception as e:  # pragma: no cover
                                    string_errors.append(
                                        [buffer_name, yara_files[rule_name], rule_name, string_name, str(e)]
                                    )

                                if test_config.show_progress_bar:
                                    string_bar.next()
                        except Exception as e:  # pragma: no cover
                            sys.stderr.write(f"failed to test string {string_name}: {e}\n")
                            string_errors.append(["N/A", yara_files[rule_name], rule_name, string_name, str(e)])

                if test_config.show_progress_bar:
                    string_bar.finish()

        if test_config.show_progress_bar:
            bar.finish()

        # order by execution time
        execution_times = sorted(execution_times, key=itemgetter(3), reverse=True)
        string_execution_times = sorted(string_execution_times, key=itemgetter(5), reverse=True)

        if test_config.csv or test_config.performance_csv:
            with open(test_config.csv or test_config.performance_csv, "w", newline="") as fp:
                writer = csv.writer(fp)
                writer.writerow(["buffer", "file", "rule", "time"])
                for row in execution_times:
                    writer.writerow(row)
        else:
            print("BEGIN EXECUTION TIME")
            for row in execution_times:
                print(row)
            print("END EXECUTION TIME")

        if test_config.csv or test_config.failure_csv:
            with open(test_config.csv or test_config.failure_csv, "a" if test_config.csv else "w", newline="") as fp:
                writer = csv.writer(fp)
                writer.writerow(["buffer", "file", "rule", "error"])
                for row in execution_errors:
                    writer.writerow(row)  # pragma: no cover
        else:
            print("BEGIN EXECUTION ERRORS")
            for row in execution_errors:
                print(row)  # pragma: no cover
            print("END EXECUTION ERRORS")

        if test_config.csv or test_config.string_performance_csv:
            with open(
                test_config.csv or test_config.string_performance_csv, "a" if test_config.csv else "w", newline=""
            ) as fp:
                writer = csv.writer(fp)
                writer.writerow(["buffer", "file", "rule", "string", "hits", "time"])
                for row in string_execution_times:
                    writer.writerow(row)
        else:
            print("BEGIN STRING EXECUTION TIME")
            for row in string_execution_times:
                print(row)
            print("END STRING EXECUTION TIME")

        if test_config.csv or test_config.string_failure_csv:
            with open(
                test_config.csv or test_config.string_failure_csv, "a" if test_config.csv else "w", newline=""
            ) as fp:
                writer = csv.writer(fp)
                writer.writerow(["buffer", "file", "rule", "string", "error"])
                for row in string_errors:
                    writer.writerow(row)  # pragma: no cover
        else:
            print("BEGIN STRING EXECUTION ERRORS")
            for row in string_errors:
                print(row)  # pragma: no cover
            print("END STRING EXECUTION ERRORS")

        return True

    def load_rules(self, external_vars=DEFAULT_YARA_EXTERNALS):
        return True  # pragma: no cover

    def scan(self, file_path, yara_stdout_file=None, yara_stderr_file=None, external_vars={}, timeout=None):
        """
        Scans the given file with the loaded yara rules. Returns True if at least one yara rule matches, False otherwise.

        The ``scan_results`` property will contain the results of the scan.

        :param file_path: The path to the file to scan.
        :type file_path: str
        :param yara_stdout_file: Ignored.
        :param yara_stderr_file: Ignored.
        :external_vars: dict of variables to pass to the scanner as external yara variables (typically used in the condition of the rule.)
        :type external_vars: dict
        :rtype: bool
        """

        # default external variables
        default_external_vars = {
            "filename": os.path.basename(file_path),
            "filepath": file_path,
            "filetype": "",  # get_the_file_type(),
            "extension": file_path.rsplit(".", maxsplit=1)[1] if "." in file_path else "",
        }

        # update with whatever is passed in
        default_external_vars.update(external_vars)

        if timeout is None:
            timeout = self.default_timeout

        # get the yara context to use for this target file
        self.mime_type = get_mime_type(file_path)
        log.debug(f"got mime type {self.mime_type} for {file_path}")
        yara_context = self.get_yara_context(file_path, mime_type=self.mime_type)

        match_arguments = {
            "externals": default_external_vars
        }

        if timeout != 0:
            match_arguments["timeout"] = timeout

        # is the file too large?
        file_path_size = os.path.getsize(file_path)
        if file_path_size > self.max_bytes:
            log.info(f"file {file_path} too large ({file_path_size} bytes) -- using first {self.max_bytes} bytes")
            # read the first N bytes and pass that directly 
            with open(file_path, 'rb') as fp:
                match_arguments["data"] = fp.read(self.max_bytes)
        else:
            match_arguments["filepath"] = file_path

        # scan the file
        start = datetime.datetime.now()
        yara_matches = yara_context.context.match(**match_arguments)
        end = datetime.datetime.now()
        total_ms = int((end - start).total_seconds() * 1000)
        log.info(f"scanned file {file_path} in {total_ms} ms")

        self.manage_yara_contexts()
        log.info(
            f"cache size: [{len(self.yara_contexts)}] "
            f"flushed size: [{len([_ for _ in self.yara_contexts.values() if _.is_flushed])}]"
        )

        return self.filter_scan_results(
            file_path, None, yara_matches, yara_stdout_file, yara_stderr_file, external_vars
        )

    def scan_data(self, data, yara_stdout_file=None, yara_stderr_file=None, external_vars={}, timeout=None):
        """
        Scans the given data with the loaded yara rules. ``data`` can be either a str or bytes object. Returns True if at least one yara rule matches, False otherwise.

        The ``scan_results`` property will contain the results of the scan.

        :param data: The data to scan.
        :type data: str or bytes
        :param yara_stdout_file: Ignored.
        :param yara_stderr_file: Ignored.
        :external_vars: dict of variables to pass to the scanner as external yara variables (typically used in the condition of the rule.)
        :type external_vars: dict
        :rtype: bool
        """

        if timeout is None:
            timeout = self.default_timeout

        # get the yara context to use
        self.mime_type = None
        yara_context = self.get_yara_context()

        # scan the data stream
        if timeout == 0:
            yara_matches = yara_context.context.match(data=data[:self.max_bytes], externals=external_vars)
        else:
            yara_matches = yara_context.context.match(data=data[:self.max_bytes], externals=external_vars, timeout=timeout)

        self.manage_yara_contexts()
        log.info(
            f"cache size: [{len(self.yara_contexts)}] "
            f"flushed size: [{len([_ for _ in self.yara_contexts.values() if _.is_flushed])}]"
        )

        return self.filter_scan_results(None, data, yara_matches, yara_stdout_file, yara_stderr_file, external_vars)

    def filter_scan_results(
        self, file_path, data, yara_matches, yara_stdout_file=None, yara_stderr_file=None, external_vars={}
    ):
        # similar to how we pre-filter the yara rules into multiple contexts
        # we also filter after the scanning is complete

        # if we didn't specify a file_path then we default to an empty string
        # that will be the case when we are scanning a data chunk
        if file_path is None:
            file_path = ""

        # the list of matches after we filter
        self.scan_results = []

        # if post filtering is disabled then we return all matches
        if self.disable_postfilter:
            self.scan_results.extend(yara_matches)
        else:
            for match_result in yara_matches:
                if self.filter_check(
                    extract_filters_from_metadata([match_result.meta]), file_path, mime_type=self.mime_type
                ):
                    log.debug(f"{file_path} matches post-filter for {match_result.rule}")
                    self.scan_results.append(match_result)

        # get rid of the yara object and just return dict
        # also includes a "target" (reference to what was scanned)
        self.scan_results = [
            {
                "target": file_path,
                "meta": o.meta,
                "namespace": o.namespace,
                "rule": o.rule,
                "strings": o.strings,
                "tags": o.tags,
            }
            for o in self.scan_results
        ]

        return self.has_matches

    @property
    def has_matches(self):
        return len(self.scan_results) != 0


# typically you might want to start a process, load the rules, then fork() for each client to scan
# the idea being the each child process will be reusing the same yara rules loaded in memory
# in practice, the yara rules compile into some kind of huge blob inside libyara
# and the amount of time it takes the kernel to the clone() seems to gradually increase as a result of that
# so the rules are loaded into each process and are reused until re-loaded

#
# each scanner listens on a local unix socket for new things to scan
# once connected the following protocol is observed
# client sends one byte with the following possible values
# 1) what follows is a data stream
# 2) what follows is a file path
# in either case the client sends an unsigned integer in network byte order
# that is the size of the following data (either data stream or file name)
# finally the client sends another unsigned integer in network byte order
# followed by a JSON hash of all the external variables to define for the scan
# a size of 0 would indicate an empty JSON file
#
# once received the scanner will scan the data (or the file) and submit a result back to the client
# the result will be a data block with one of the following values
# * an empty block meaning no matches
# * a pickled exception for yara scanning failures
# * a pickled result dictionary
# then the server will close the connection

COMMAND_FILE_PATH = b"1"
COMMAND_DATA_STREAM = b"2"

DEFAULT_BASE_DIR = "/opt/yara_scanner"
DEFAULT_SIGNATURE_DIR = "/opt/signatures"
DEFAULT_SOCKET_DIR = "socket"


class YaraScannerWorker:
    def __init__(
        self,
        base_dir=DEFAULT_BASE_DIR,
        signature_dir=DEFAULT_SIGNATURE_DIR,
        socket_dir=DEFAULT_SOCKET_DIR,
        update_frequency=60,
        backlog=50,
        default_timeout=DEFAULT_TIMEOUT,
        max_bytes=DEFAULT_MAX_BYTES,
        disable_signal_handling=False,
        disable_prefilter=False,
        use_threads=False,
        shutdown_event=None,
        cpu_index=None,
        context_cache_dir=None,
        max_contexts=DEFAULT_MAX_CONTEXTS,
    ):
        self.base_dir = base_dir
        self.signature_dir = signature_dir
        self.socket_dir = socket_dir
        self.update_frequency = update_frequency
        self.backlog = backlog
        self.default_timeout = default_timeout
        self.max_bytes = max_bytes
        self.disable_signal_handling = disable_signal_handling
        self.disable_prefilter = disable_prefilter
        self.use_threads = use_threads
        self.shutdown_event = shutdown_event
        self.cpu_index = cpu_index
        self.context_cache_dir = context_cache_dir
        self.max_contexts = max_contexts

        # the next time we need to update the yara rules
        self.next_rule_update_time = time.time() + self.update_frequency

        self.process_thread = None
        self.server_socket = None
        self.socket_path = None

        if self.use_threads:
            self.worker_shutdown = threading.Event()
            self.started_event = threading.Event()
        else:  # pragma: no cover
            self.worker_shutdown = multiprocessing.Event()
            self.started_event = multiprocessing.Event()

    def __str__(self):
        return f"YaraScannerWorker-{self.cpu_index}"

    def is_alive(self) -> bool:
        if self.process_thread is None:
            return True  # still initializing

        return self.process_thread.is_alive()

    def start(self):
        thread_name = f"Yara Scanner Worker {self.cpu_index}"
        if self.use_threads:
            self.process_thread = threading.Thread(name=thread_name, target=self.run)
        else:  # pragma: no cover
            self.process_thread = multiprocessing.Process(name=thread_name, target=self.run)

        self.process_thread.start()

    def wait_for_start(self, timeout=None):
        """Waits for the server to start accepting connections."""
        self.started_event.wait(timeout)

    def stop(self):
        self.worker_shutdown.set()

    def wait_for_stop(self, timeout=None):
        self.process_thread.join(timeout=timeout)

    def initialize_server_socket(self):
        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.settimeout(0.1)

        socket_dir = os.path.join(self.base_dir, self.socket_dir)
        if not os.path.isdir(socket_dir):
            os.mkdir(socket_dir)

        # the path of the unix socket will be socket_dir/cpu_index where cpu_index >= 0
        self.socket_path = os.path.join(self.base_dir, self.socket_dir, str(self.cpu_index))
        log.info(f"initializing server socket on {self.socket_path}")

        if os.path.exists(self.socket_path):
            try:
                os.remove(self.socket_path)
            except Exception as e:  # pragma: no cover
                log.error(f"unable to remove {self.socket_path}: {e}")

        self.server_socket.bind(self.socket_path)
        self.server_socket.listen(self.backlog)

    def kill_server_socket(self):
        if self.server_socket is None:
            return

        try:
            log.info("closing server socket")
            self.server_socket.close()
        except Exception as e:  # pragma: no cover
            log.error(f"unable to close server socket: {e}")

        self.server_socket = None

        try:
            if os.path.exists(self.socket_path):
                os.remove(self.socket_path)
        except Exception as e:  # pragma: no cover
            logging.error(f"unable to remove {self.socket_path}: {e}")

    def initialize_scanner(self):
        log.info("initializing scanner")
        self.scanner = YaraScanner(
            signature_dir=self.signature_dir,
            default_timeout=self.default_timeout,
            max_bytes=self.max_bytes,
            context_cache_dir=self.context_cache_dir,
            max_contexts=self.max_contexts,
            disable_prefilter=self.disable_prefilter,
        )

    def run(self):
        def _handler(signum, frame):  # pragma: no cover
            log.info("WORKER SIGNAL HANDLER")
            self.worker_shutdown.set()

        if not self.disable_signal_handling:  # pragma: no cover
            signal.signal(signal.SIGHUP, _handler)  # TODO handle this
            signal.signal(signal.SIGTERM, _handler)
            signal.signal(signal.SIGINT, _handler)

        # load up the yara scanner
        try:
            self.initialize_scanner()
        except Exception as e:  # pragma: no cover
            log.error(f"unable to initialize scanner: {e}")

        while True:
            try:
                self.execute()

                if self.worker_shutdown.is_set():
                    log.info("worker shutdown")
                    break

                if self.shutdown_event.is_set():
                    log.info("server shutdown")
                    break

            except KeyboardInterrupt:  # pragma: no cover
                log.info("caught keyboard interrupt - exiting")
                break

            except Exception as e:  # pragma: no cover
                log.error(f"uncaught exception: {e} ({type(e)})")
                self.shutdown_event.wait(1)

        self.kill_server_socket()
        self.scanner.clear_yara_contexts()
        log.info("worker exited")

    def execute(self):
        # are we listening on the socket yet?
        if not self.server_socket:
            try:
                self.initialize_server_socket()
            except Exception as e:
                self.kill_server_socket()
                # don't spin the cpu on failing to allocate the socket
                self.shutdown_event.wait(timeout=1)
                return

        # get the next client connection
        try:
            # log.debug("waiting for client")
            client_socket, _ = self.server_socket.accept()
            self.started_event.set()
        except socket.timeout as e:
            # nothing came in while we were waiting (check for shutdown and try again)
            self.started_event.set()
            return
        except Exception as e:
            log.error(f"error waiting for connection: {e}")
            return

        try:
            self.process_client(client_socket)
        except Exception as e:
            log.info(f"unable to process client request: {e}")
        finally:
            try:
                client_socket.close()
            except Exception as e:  # pragma: no cover
                log.error(f"unable to close client connection: {e}")

    def process_client(self, client_socket):
        # read the command byte
        command = client_socket.recv(1)

        data_or_file = read_data_block(client_socket).decode()
        ext_vars = read_data_block(client_socket)

        if not ext_vars:
            ext_vars = {}
        else:
            # parse the ext vars json
            ext_vars = json.loads(ext_vars.decode())

        # is it time to check for rule refresh?
        if time.time() >= self.next_rule_update_time:
            log.info("checking yara rules")
            self.next_rule_update_time = time.time() + self.update_frequency
            self.scanner.check_rules()

        try:
            matches = False
            if command == COMMAND_FILE_PATH:
                log.info(f"scanning file {data_or_file}")
                start = datetime.datetime.now()
                matches = self.scanner.scan(data_or_file, external_vars=ext_vars)
                end = datetime.datetime.now()
                total_ms = int((end - start).total_seconds() * 1000)
                log.info(f"scanned file {data_or_file} in {total_ms} ms")
            elif command == COMMAND_DATA_STREAM:
                log.info(f"scanning {len(data_or_file)} byte data stream")
                matches = self.scanner.scan_data(data_or_file, external_vars=ext_vars)
            else:
                log.error(f"invalid command {command}")
                return
        except Exception as e:
            log.info(f"scanning failed: {e}")
            send_data_block(client_socket, pickle.dumps(e))
            return

        if not matches:
            # a data lenghth of 0 means we didn't match anything
            send_data_block(client_socket, b"")
        else:
            # encode and submit the JSON result of the client
            # print(self.scanner.scan_results)
            send_data_block(client_socket, pickle.dumps(self.scanner.scan_results))


class YaraScannerServer:
    def __init__(
        self,
        base_dir=DEFAULT_BASE_DIR,
        signature_dir=DEFAULT_SIGNATURE_DIR,
        socket_dir=DEFAULT_SOCKET_DIR,
        update_frequency=60,
        backlog=50,
        default_timeout=DEFAULT_TIMEOUT,
        max_bytes=DEFAULT_MAX_BYTES,
        max_workers=None,
        disable_signal_handling=False,
        use_threads=False,
        disable_prefilter=False,
        context_cache_dir=None,
        max_contexts=DEFAULT_MAX_CONTEXTS,
    ):
        # primary scanner controller
        self.process_manager = None

        # list of YaraScannerServer Process objects
        # there will be one per cpu available as returned by max_workers or multiprocessing.cpu_count()
        self.workers = [None for _ in range(multiprocessing.cpu_count() if max_workers is None else max_workers)]

        self.context_cache_dir = context_cache_dir
        self.max_contexts = max_contexts

        # base directory of yara scanner
        self.base_dir = base_dir

        # the directory that contains the signatures to load
        self.signature_dir = signature_dir

        # the directory that contains the unix sockets
        self.socket_dir = socket_dir

        # how often do we check to see if the yara rules changed? (in seconds)
        self.update_frequency = update_frequency

        # parameter to the socket.listen() function (how many connections to backlog)
        self.backlog = backlog

        #
        # the following variables are specific to the child proceses
        #

        # the "cpu index" of this process (used to determine the name of the unix socket)
        self.cpu_index = None

        # the path to the unix socket this process is using
        self.socket_path = None

        # the socket we are listening on for scan requests
        self.server_socket = None

        # the scanner we're using for this process
        self.scanner = None

        # set to True when we receive a SIGUSR1
        self.sigusr1 = False

        # set to True when we receive a SIGTERM
        self.sigterm = False

        # save default timeout to use for scanner
        self.default_timeout = default_timeout

        # the maximum number of bytes to scan for a single file
        self.max_bytes = max_bytes

        # disable pre-filtering capabilities
        self.disable_prefilter = disable_prefilter

        # test support functions
        # disable signal handling
        self.disable_signal_handling = disable_signal_handling

        # multiprocessing mode
        # if this is set to True then we use threading.Thread instead of multiprocessing.Process
        self.use_threads = use_threads

        if self.use_threads:
            # set when the server has fully started
            self.started_event = threading.Event()
            # set when the server needs to shut down
            self.shutdown_event = threading.Event()
        else:  # pragma: no cover
            self.started_event = multiprocessing.Event()
            self.shutdown_event = multiprocessing.Event()

    def execute(self):
        def _handler(signum, frame):  # pragma: no cover
            log.info("SIGNAL HANDLER CALLED")
            self.sigterm = True

        if not self.disable_signal_handling:  # pragma: no cover
            signal.signal(signal.SIGTERM, _handler)

        while True:
            try:
                self.execute_process_manager()
                # if this is the first time then we wait for the workers to start
                if not self.shutdown_event.is_set() and not self.started_event.is_set():
                    for worker in self.workers:
                        log.info(f"waiting for worker {worker} to start")
                        worker.wait_for_start()
                        log.info(f"worker {worker} started")

                    # let controlling process know we started
                    self.started_event.set()

                self.shutdown_event.wait(1)
                if self.shutdown_event.is_set():
                    break

                if self.sigterm:  # pragma: no cover
                    self.shutdown_event.set()
                    break

            except KeyboardInterrupt:  # pragma: no cover
                log.info("got keyboard interrupt")
                self.shutdown_event.set()
                break
            except Exception as e:  # pragma: no cover
                log.error(f"uncaught exception: {e}")
                time.sleep(1)

        # wait for all the scanners to die...
        for worker in self.workers:
            if worker:
                log.info(f"waiting for scanner {worker} to exit...")
                worker.stop()
                worker.wait_for_stop()

        log.info("exiting")

    def execute_process_manager(self):
        for i, p in enumerate(self.workers):
            if self.workers[i] is not None:
                if not self.workers[i].is_alive():
                    log.info(f"detected dead scanner {self.workers[i]}")
                    self.workers[i].stop()
                    self.workers[i] = None

        for i, worker in enumerate(self.workers):
            if worker is None:
                logging.info(f"starting scanner on cpu {i}")
                self.workers[i] = YaraScannerWorker(
                    base_dir=self.base_dir,
                    signature_dir=self.signature_dir,
                    socket_dir=self.socket_dir,
                    update_frequency=self.update_frequency,
                    backlog=self.backlog,
                    default_timeout=self.default_timeout,
                    max_bytes=self.max_bytes,
                    disable_signal_handling=self.disable_signal_handling,
                    disable_prefilter=self.disable_prefilter,
                    use_threads=self.use_threads,
                    shutdown_event=self.shutdown_event,
                    cpu_index=i,
                    context_cache_dir=self.context_cache_dir,
                    max_contexts=self.max_contexts,
                )

                self.workers[i].start()
                log.info(f"started scanner on cpu {i} with pid {self.workers[i]}")

    def start(self):
        if self.use_threads:
            self.process_manager = threading.Thread(name="Process Manager", target=self.execute)
        else:  # pragma: no cover
            self.process_manager = multiprocessing.Process(name="Process Manager", target=self.execute)

        self.process_manager.start()

    def wait_for_start(self, timeout: int = None):
        self.started_event.wait(timeout=timeout)

    def stop(self):
        self.shutdown_event.set()

    def wait_for_stop(self, timeout: int = None):
        self.process_manager.join(timeout=timeout)

    # added for backwards compat
    def wait(self):  # pragma: no cover
        self.wait_for_stop()


def _scan(
    command, data_or_file, ext_vars={}, base_dir=DEFAULT_BASE_DIR, socket_dir=DEFAULT_SOCKET_DIR, max_workers=None
):
    # pick a random scanner
    # it doesn't matter which one, as long as the load is evenly distributed
    starting_index = scanner_index = random.randrange(
        multiprocessing.cpu_count() if max_workers is None else max_workers
    )

    while True:
        socket_path = os.path.join(base_dir, socket_dir, str(scanner_index))

        ext_vars_json = b""
        if ext_vars:
            ext_vars_json = json.dumps(ext_vars).encode()

        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        try:
            client_socket.connect(socket_path)
            client_socket.sendall(command)

            if isinstance(data_or_file, str):
                data_or_file = data_or_file.encode(errors="ignore")

            send_data_block(client_socket, data_or_file)
            send_data_block(client_socket, ext_vars_json)

            result = read_data_block(client_socket)
            if result == b"":
                return {}

            result = pickle.loads(result)

            if isinstance(result, BaseException):
                raise result

            return result

        except socket.error as e:
            log.debug(f"possible restarting scanner: {e}")
            # in the case where a scanner is restarting (when loading rules)
            # we will receive a socket error when we try to connect
            # just move on to the next socket and try again
            scanner_index += 1
            if scanner_index >= multiprocessing.cpu_count() if max_workers is None else max_workers:
                scanner_index = 0

            # if we've swung back around wait for a few seconds and try again
            if scanner_index == starting_index:
                log.info("no scanners available")
                raise

            continue


def scan_file(path, base_dir=None, socket_dir=DEFAULT_SOCKET_DIR, ext_vars={}):
    return _scan(COMMAND_FILE_PATH, path, ext_vars=ext_vars, base_dir=base_dir, socket_dir=socket_dir)


def scan_data(data, base_dir=None, socket_dir=DEFAULT_SOCKET_DIR, ext_vars={}):
    return _scan(COMMAND_DATA_STREAM, data, ext_vars=ext_vars, base_dir=base_dir, socket_dir=socket_dir)


#
# protocol routines
#


def read_n_bytes(s, n):
    """Reads n bytes from socket s.  Returns the bytearray of the data read."""
    bytes_read = 0
    _buffer = []
    while bytes_read < n:
        data = s.recv(n - bytes_read)
        if data == b"":
            break

        bytes_read += len(data)
        _buffer.append(data)

    result = b"".join(_buffer)
    if len(result) != n:
        log.debug(f"expected {n} bytes but read {len(result)}")

    return b"".join(_buffer)


def read_data_block(s):
    """Reads the next data block from socket s. Returns the bytearray of the data portion of the block."""
    # read the size of the data block (4 byte network order integer)
    size = struct.unpack("!I", read_n_bytes(s, 4))
    size = size[0]
    # log.debug("read command block size {}".format(size))
    # read the data portion of the data block
    return read_n_bytes(s, size)


def send_data_block(s, data):
    """Writes the given data to the given socket as a data block."""
    message = b"".join([struct.pack("!I", len(data)), data])
    # log.debug("sending data block length {} ({})".format(len(message), message[:64]))
    s.sendall(message)


@dataclass
class TestConfig:
    __test__ = False
    test: bool = False
    test_rule: bool = None
    test_strings: bool = False
    test_strings_if: bool = False
    test_strings_threshold: float = 0.1
    test_data: str = None
    csv: str = None
    performance_csv: str = None
    failure_csv: str = None
    string_performance_csv: str = None
    string_failure_csv: str = None
    show_progress_bar: bool = False


def main():  # pragma: no cover
    import argparse
    import pprint
    import sys

    parser = argparse.ArgumentParser(description="Scan the given file with yara using all available rulesets.")
    parser.add_argument("paths", metavar="PATHS", nargs="*", help="One or more files or directories to scan with yara.")
    parser.add_argument(
        "-r",
        "--recursive",
        required=False,
        default=False,
        action="store_true",
        dest="recursive",
        help="Recursively scan directories.",
    )
    parser.add_argument(
        "--from-stdin",
        required=False,
        default=False,
        action="store_true",
        dest="from_stdin",
        help="Read the list of files to scan from stdin.",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity. Can specify multiple times for more verbose output",
    )
    parser.add_argument(
        "-j",
        "--dump-json",
        required=False,
        default=False,
        action="store_true",
        dest="dump_json",
        help="Dump JSON details of matches.  Otherwise just list the rules that hit.",
    )

    parser.add_argument(
        "-t",
        "--test",
        required=False,
        default=False,
        action="store_true",
        dest="test",
        help="Test each yara file separately against different types of buffers for performance issues.",
    )
    parser.add_argument("--test-rule", required=False, default=None, dest="test_rule", help="Tests a specific rule.")
    parser.add_argument(
        "--test-strings",
        required=False,
        default=False,
        action="store_true",
        dest="test_strings",
        help="Tests the performance all the strings individually in the selected yara rules.",
    )
    parser.add_argument(
        "--test-strings-if",
        required=False,
        default=False,
        action="store_true",
        dest="test_strings_if",
        help="""Tests the performance all the strings individually in rules
        that take longer than N seconds to complete or rules that fail for any
        reason.""",
    )
    parser.add_argument(
        "--test-strings-threshold",
        required=False,
        default=0.1,
        type=float,
        dest="test_strings_threshold",
        help="The threshold (in seconds) for the --test-strings-if option. Defaults to 0.1 seconds.",
    )
    parser.add_argument(
        "--test-data",
        required=False,
        default=None,
        dest="test_data",
        help="Use the given file as the buffer of random data for the test data.",
    )
    parser.add_argument("--csv", help="Write performance results to the given CSV file.")
    parser.add_argument(
        "--performance-csv",
        required=False,
        default=None,
        dest="performance_csv",
        help="Write the performance results of string testing to the given csv formatted file. Defaults to stdout.",
    )
    parser.add_argument(
        "--failure-csv",
        required=False,
        default=None,
        dest="failure_csv",
        help="Write the failure results of string testing to the given csv formatted file. Defaults to stdout.",
    )
    parser.add_argument(
        "--string-performance-csv",
        required=False,
        default=None,
        dest="string_performance_csv",
        help="Write the performance results of string testing to the given csv formatted file. Defaults to stdout.",
    )
    parser.add_argument(
        "--string-failure-csv",
        required=False,
        default=None,
        dest="string_failure_csv",
        help="Write the failure results of string testing to the given csv formatted file. Defaults to stdout.",
    )
    parser.add_argument(
        "--no-progress-bar", default=False, action="store_true", help="Disable the progress bar shown during testing."
    )

    parser.add_argument(
        "-y",
        "--yara-rules",
        required=False,
        default=[],
        action="append",
        dest="yara_rules",
        help="One yara rule to load.  You can specify more than one of these.",
    )
    parser.add_argument(
        "-Y",
        "--yara-dirs",
        required=False,
        default=[],
        action="append",
        dest="yara_dirs",
        help="One directory containing yara rules to load.  You can specify more than one of these.",
    )
    parser.add_argument(
        "-G",
        "--yara-repos",
        required=False,
        default=[],
        action="append",
        dest="yara_repos",
        help="One directory that is a git repository that contains yara rules to load. You can specify more than one of these.",
    )

    parser.add_argument(
        "-c",
        "--compile-only",
        required=False,
        default=False,
        action="store_true",
        dest="compile_only",
        help="Compile the rules and exit.",
    )

    parser.add_argument(
        "-d",
        "--signature-dir",
        dest="signature_dir",
        default=None,
        help="DEPRECATED: Use a different signature directory than the default.",
    )

    parser.add_argument(
        "--enable-prefilter",
        dest="enable_prefilter",
        action="store_true",
        default=False,
        help="Enable prefiltering rules. WARNING: This slows down the initialization process.",
    )

    parser.add_argument(
        "--disable-postfilter",
        dest="disable_postfilter",
        action="store_true",
        default=False,
        help="Disable postfiltering.",
    )

    parser.add_argument(
        "-a",
        "--auto-compile-rules",
        default=False,
        action="store_true",
        help="""Automatically saved the compiled yara rules to disk.
        Automatically loads pre-compiled rules based on SHA2 hash of rule
        content.""",
    )
    parser.add_argument(
        "--auto-compiled-rules-dir",
        help="""Specifies the directory to use to store automatically compiled
        yara rules. Defaults to ~/.yara_scanner.""",
    )

    # resource constraints
    parser.add_argument(
        "-T",
        "--timeout",
        default=DEFAULT_TIMEOUT,
        type=int,
        help="""Maximum amount of time (in seconds) a single scan is allowed to take.
        Passed directly to libyara.""")

    parser.add_argument(
        "-M",
        "--max-bytes",
        default=DEFAULT_MAX_BYTES,
        type=int,
        help="""Only the first N bytes of a file are scanned.""")

    args = parser.parse_args()

    if (
        len(args.yara_rules) == 0
        and len(args.yara_dirs) == 0
        and len(args.yara_repos) == 0
        and args.signature_dir is None
    ):
        args.signature_dir = "/opt/signatures"

    log_levels = {0: logging.ERROR, 1: logging.WARNING, 2: logging.INFO, 3: logging.DEBUG}
    log_level = min(max(args.verbose, 0), 3)  # clamp to 0-3 inclusive
    logging.getLogger("plyara").setLevel(logging.ERROR)
    logging.basicConfig(level=log_levels[log_level])

    compiled_rules_dir = None
    if args.auto_compiled_rules_dir:
        compiled_rules_dir = args.auto_compiled_rules_dir
    elif args.auto_compile_rules and not args.auto_compiled_rules_dir:
        compiled_rules_dir = os.path.join(str(Path.home()), ".yara_scanner")

    if compiled_rules_dir:
        os.makedirs(compiled_rules_dir, exist_ok=True)

    # if we're checking the syntax then we don't want to do any pre-filtering
    if args.compile_only:
        args.disable_prefilter = True

    scanner = YaraScanner(
        signature_dir=args.signature_dir,
        default_timeout=args.timeout,
        disable_prefilter=not args.enable_prefilter,
        disable_postfilter=args.disable_postfilter,
        compiled_rules_dir=compiled_rules_dir,
        max_bytes=args.max_bytes,
    )

    for file_path in args.yara_rules:
        scanner.track_yara_file(file_path)

    for dir_path in args.yara_dirs:
        scanner.track_yara_dir(dir_path)

    for repo_path in args.yara_repos:
        scanner.track_yara_repository(repo_path)

    if args.test:
        test_config = TestConfig()
        test_config.test = args.test
        test_config.test_rule = args.test_rule
        test_config.test_strings = args.test_strings
        test_config.test_strings_if = args.test_strings_if
        test_config.test_strings_threshold = args.test_strings_threshold
        if args.test_data:
            with open(args.test_data, "rb") as fp:
                test_config.test_data = fp.read()
        test_config.csv = args.csv
        test_config.performance_csv = args.performance_csv
        test_config.failure_csv = args.failure_csv
        test_config.string_performance_csv = args.string_performance_csv
        test_config.string_failure_csv = args.string_failure_csv
        test_config.show_progress_bar = not args.no_progress_bar
        scanner.test_rules(test_config)
        sys.exit(0)

    if args.compile_only:
        context - scanner.get_yara_context()
        sys.exit(0)

    exit_result = 0

    def scan_file(file_path):
        global exit_result
        try:
            if scanner.scan(file_path):
                if args.dump_json:
                    json.dump(scanner.scan_results, sys.stdout, sort_keys=True, indent=4, cls=YaraJSONEncoder)
                else:
                    print(file_path)
                    for match in scanner.scan_results:
                        print(f"\t{match['rule']}")
        except Exception as e:
            log.error(f"scan failed for {file_path}: {e}")
            exit_result = 1

    def scan_dir(dir_path):
        for file_path in os.listdir(dir_path):
            file_path = os.path.join(dir_path, file_path)
            if os.path.isdir(file_path):
                if args.recursive:
                    scan_dir(file_path)
            else:
                scan_file(file_path)

    if args.from_stdin:
        for line in sys.stdin:
            line = line.strip()
            scan_file(line)
    else:
        for path in args.paths:
            if os.path.isdir(path):
                scan_dir(path)
            else:
                scan_file(path)

    sys.exit(exit_result)


if __name__ == "__main__":  # pragma: no cover
    main()
