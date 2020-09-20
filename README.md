# Yara Scanner

[![ace-ecosystem](https://circleci.com/gh/ace-ecosystem/yara_scanner.svg?style=svg)](https://circleci.com/gh/ace-ecosystem/yara_scanner)

A wrapper around the [yara-python](https://github.com/VirusTotal/yara-python) project the provides the following capabilities.

- Change tracking of yara files, directories of yara files, or git repositories of yara files.
- File and data scanning with the ability to filter based on meta data matching.
- Distributed scanning processes that maximize the use of multi-core systems.
- Command line interface.

## Python Examples

Loading a single yara file and then scanning data.

```python
from pprint import pprint
from yara_scanner import YaraScanner

scanner = YaraScanner()
# tells the scanner to start tracking this yara file
scanner.track_yara_file('my_rules.yar')
scanner.load_rules()
if scanner.scan('/path/to/scan_target.txt'):
   pprint(scanner.scan_results)
   
# this returns True if any tracked yara files have changed
if scanner.check_rules():
   scanner.load_rules()
```

## Installation Instructions

```bash
pip install yara-scanner
```

## Yara Signature Locations

The default global pattern for loading rules is 

```
/opt/signatures/*/*.yar
```

You can use the `-d` option to specified a different default location, or, you can use the `-y`, `-Y`, `-G`, and `-z` options to specify specific locations.

## Command Line Options

   ```
   usage: scan [-h] [-r] [--from-stdin] [-v] [-j] [-t] [--test-rule TEST_RULE] [--test-strings] [--test-strings-if] [--test-strings-threshold TEST_STRINGS_THRESHOLD] [--test-data TEST_DATA] [--csv CSV]
            [--performance-csv PERFORMANCE_CSV] [--failure-csv FAILURE_CSV] [--string-performance-csv STRING_PERFORMANCE_CSV] [--string-failure-csv STRING_FAILURE_CSV] [-y YARA_RULES] [-Y YARA_DIRS] [-G YARA_REPOS]
            [-z COMPILED_YARA_RULES] [-c] [-C COMPILE_TO] [-b BLACKLISTED_RULES] [-B BLACKLISTED_RULES_PATH] [-a] [--auto-compiled-rules-dir AUTO_COMPILED_RULES_DIR] [-d SIGNATURE_DIR]
            [PATHS [PATHS ...]]

Scan the given file with yara using all available rulesets.

positional arguments:
  PATHS                 One or more files or directories to scan with yara.

optional arguments:
  -h, --help            show this help message and exit
  -r, --recursive       Recursively scan directories.
  --from-stdin          Read the list of files to scan from stdin.
  -v, --verbose         Increase verbosity. Can specify multiple times for more verbose output
  -j, --dump-json       Dump JSON details of matches. Otherwise just list the rules that hit.
  -t, --test            Test each yara file separately against different types of buffers for performance issues.
  --test-rule TEST_RULE
                        Tests a specific rule.
  --test-strings        Tests the performance all the strings individually in the selected yara rules.
  --test-strings-if     Tests the performance all the strings individually in rules that take longer than N seconds to complete or rules that fail for any reason.
  --test-strings-threshold TEST_STRINGS_THRESHOLD
                        The threshold (in seconds) for the --test-strings-if option. Defaults to 0.1 seconds.
  --test-data TEST_DATA
                        Use the given file as the buffer of random data for the test data.
  --csv CSV             Write performance results to the given CSV file.
  --performance-csv PERFORMANCE_CSV
                        Write the performance results of string testing to the given csv formatted file. Defaults to stdout.
  --failure-csv FAILURE_CSV
                        Write the failure results of string testing to the given csv formatted file. Defaults to stdout.
  --string-performance-csv STRING_PERFORMANCE_CSV
                        Write the performance results of string testing to the given csv formatted file. Defaults to stdout.
  --string-failure-csv STRING_FAILURE_CSV
                        Write the failure results of string testing to the given csv formatted file. Defaults to stdout.
  -y YARA_RULES, --yara-rules YARA_RULES
                        One yara rule to load. You can specify more than one of these.
  -Y YARA_DIRS, --yara-dirs YARA_DIRS
                        One directory containing yara rules to load. You can specify more than one of these.
  -G YARA_REPOS, --yara-repos YARA_REPOS
                        One directory that is a git repository that contains yara rules to load. You can specify more than one of these.
  -z COMPILED_YARA_RULES, --compiled-yara-rules COMPILED_YARA_RULES
                        Load compiled yara rules from the specified files. This option cannot be combined with -y, -Y, or -G
  -c, --compile-only    Compile the rules and exit.
  -C COMPILE_TO, --compile-to COMPILE_TO
                        Compile the rules into the given file path.
  -b BLACKLISTED_RULES, --blacklist BLACKLISTED_RULES
                        A rule to blacklist (remove from the results.) You can specify more than one of these options.
  -B BLACKLISTED_RULES_PATH, --blacklist-path BLACKLISTED_RULES_PATH
                        Path to a file that contains a list of rules to blacklist, one per line.
  -a, --auto-compile-rules
                        Automatically saved the compiled yara rules to disk. Automatically loads pre-compiled rules based on MD5 hash of rule content.
  --auto-compiled-rules-dir AUTO_COMPILED_RULES_DIR
                        Specifies the directory to use to store automatically compiled yara rules. Defaults to the system temp dir.
  -d SIGNATURE_DIR, --signature-dir SIGNATURE_DIR
                        DEPRECATED: Use a different signature directory than the default.
   ```

## Command Line Examples

scan a single file using the default rules
   ```bash
   scan ms0day.ppsx
   ```

scan a single file and generate JSON output with default rules
   ```bash
   scan -j ms0day.ppsx
   scan -j ms0day.ppsx | json_pp
   ```  

scan multiple files with default rules
   ```bash
   scan file1 file2 file3
   ```

scan all files in a directory and all sub-directories with default rules
   ```bash
   scan -r dir
   ```

scan a list of files passed in on standard input with default rules
   ``` bash
   find dridex -type f | scan --from-stdin
   ```

scan a single file with a single yara rule
   ```bash
   scan -y myrule.yar target_file
   ```

scan a single file with all rules in a given directory
  ```bash
  scan -Y my_rule_dir target_file
  ```

check the syntax of all the rules in a given directory
   ```bash
   scan -c -Y my_rule_dir
   ```

## Filtering Rule Results

The scan tool also supports filtering out specific rules **before they are loaded**. These are specified by using the -b and -B command line options. This is useful for tuning open source repositories of yara rules.

## Rule Output Selection

You can specify when a rule match should (or should not) be reported. This allows you to prevent some rules from matching against certain kinds of files, or for a rule to be matched against only one specific file.

The rules are specified as metadata name and value pairs. (example rule syntax)

```yara
rule html_rule: odd html
{
meta:
   mime_type = "text/html"
strings:
   ...
condition:
   ...
}
```

### Metadata Names and Descriptions

```
file_ext   | Matches everything past the first period in the file name.
file_name  | Matches the full name of the file (not including the path.)
full_path  | Matches against the full path of the file, if one was specified.
mime_type  | Matches against the output of file -b --mime-type.
```

The value of the metadata variable is a **comma separated list** of values to match. By default the library matches as is, but special modifiers can be used to perform sub string matching and regular expressions. **Special modifiers are applied to all comma separated values in the string.**

### Matching Modifiers

```
!     | negation    | Negates the match. This can be placed before other modifiers.
sub:  | sub-search  | Match if this string appears anywhere.
re:   | regex       | Match if the regular expression is satisfied.
```

Values can be a comma separated list of values, regardless of the modifiers. Therefor, commas cannot be used in the patterns.

### Rule Selection Examples

Only match files the end with the .exe extension.

``` 
file_ext = "exe"
```

Only match files that end with .exe, .dll or .ocx extension.

```
file_ext = "exe, dll, ocx"
```

Only match files that do not end with .exe, .dll or .ocx extension.

```
file_ext = "!exe, dll, ocx"
```

Only matches files that do not end with .bmp.

```
file_ext = "!bmp"
```

Only match files identified as PDF despite the file name.

```
mime_type = "application/pdf"
```

Only match files not identified as images.

```
mime_type = "!sub:image/"
```

Only match files that look like an invoice phish.

```
file_name = "re:invoice[0-9]+\\.doc$"
```

Only match files in a subdirectory called /ole.

```
full_path = "sub:/ole/"
```

## Yara Rule Performance Testing

It's often useful to know not only what rules have poor performance, but also what strings inside of those rules are causing the issue. This library has special support for this.

### How Performance Testing Works

Each yara rule is extracted and tested on its own against the following sets of data.

- random data (either a 1MB random sequence of bytes or the contents of a file specified by the `--test-data` option.)
- repeating byte patterns (1MB of repeating bytes of the same value.)

In total there are 256 buffers to test against for each test (one random and 255 repeating byte buffers.)

You can optionally also extract each regular expression from specified rules and test them by themselves against the same buffers. This allows you to determine which string is causing the issue.

## Executing Performance Tests

Testing all rules but not strings.

```bash
scan -t
```

Testing all rules and the strings of rules that take longer than 0.1 seconds to scan any buffer.

```bash
scan -t --test-strings-if --test-strings-threshold 0.1
```

Test a specific rule and all the strings inside of it.

```bash
scan -t --test-rule MyYaraRule --test-strings
```

Test all rules against the file `sample.dat`.

```bash
scan -t --test-data sample.dat
```

## CSV Output

The output of the test can be saved to CSV files using the following options.

`--csv` saves all performance data to the given file.

`--performance-csv` saves the performance data of entire yara files.

`--failure-csv` saves any rules that fail under performance testing.

`--string-performance-csv` saves the performance data of individual yara strings.

`--string-failure-csv` save any strings that fail under performance testing.

Note that if you do not specify these options the output is sent to standard out.

## Output Format (Performance Data)

Performance data has the following format.

`buffer_name, file_path, rule_name, total_seconds`

`buffer_name` a description of the buffer that was used by the test, either **random** for random (or file) data, or **chr(*n*)** where *n* is the byte that was used for the buffer.

`file_path` the path to the file that contains the yara rule.

`rule_name` the name of the yara rule.

`total_seconds` the total amount of time it took the yara rule to scan the given buffer.

String performance data is similar but contains two additional fields.

`buffer_name, file_path, rule_name, string_name, result_count, total_seconds`

`string_name` is the name of the string inside the yara rule.

`result_count` is the total number of times the string matched inside the buffer.

## Output Format (Error Data)

Error data has a format that is similar to the performance data but inside of **total_seconds** you will see the error message that occurred when the given yara rule or string was used to scan the given buffer.

## Error 30

If you see "Error 30" is means your rule, or strings inside of a rule, matched too many times.
