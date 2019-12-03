A Python wrapper library for libyara and a local server for fully utilizing the CPUs of the system to scan with yara...with additional capabilities.

### yara_scanner ###

install
- **pip3 option**

   pip3 install yara_scanner
- **git clone option**

   git clone https://github.com/ace-ecosystem/yara_scanner.git

   cd yara_scanner

   sudo python3 setup.py install

- **ready to scan**

   scan --help
   ```
   usage: scan [-h] [-r] [--from-stdin] [--debug] [-j] [-t] [-y YARA_RULES]
               [-Y YARA_DIRS] [-G YARA_REPOS] [-c] [-b BLACKLISTED_RULES]
               [-B BLACKLISTED_RULES_PATH] [-d SIGNATURE_DIR]
               [PATHS [PATHS ...]]

   Scan the given file with yara using all available rulesets.

   positional arguments:
     PATHS                 One or more files or directories to scan with yara.

   optional arguments:
     -h, --help            show this help message and exit
     -r, --recursive       Recursively scan directories.
     --from-stdin          Read the list of files to scan from stdin.
     --debug               Log debug level messages.
     -j, --dump-json       Dump JSON details of matches. Otherwise just list the
                           rules that hit.
     -t, --test            Test each yara file separately against different types
                           of buffers for performance issues.
     -y YARA_RULES, --yara-rules YARA_RULES
                           One yara rule to load. You can specify more than one
                           of these.
     -Y YARA_DIRS, --yara-dirs YARA_DIRS
                           One directory containing yara rules to load. You can
                           specify more than one of these.
     -G YARA_REPOS, --yara-repos YARA_REPOS
                           One directory that is a git repository that contains
                           yara rules to load. You can specify more than one of
                           these.
     -c, --compile-only    Compile the rules and exit.
     -b BLACKLISTED_RULES, --blacklist BLACKLISTED_RULES
                           A rule to blacklist (remove from the results.) You can
                           specify more than one of these options.
     -B BLACKLISTED_RULES_PATH, --blacklist-path BLACKLISTED_RULES_PATH
                           Path to a file that contains a list of rules to
                           blacklist, one per line.
   ```
   
- **example usage:**
   - scan a single file
      ```
      scan ms0day.ppsx
      ```
   - scan a single file and generate JSON output
      ```
      scan -j ms0day.ppsx
      scan -j ms0day.ppsx | json_pp
      ```  
   - scan multiple files
      ```
      scan file1 file2 file3
      ```
   - scan all files in a directory and all sub-directories
      ```
      scan -r dir
      ```
   - scan a list of files passed in on standard input
      ``` 
      find dridex -type f | scan --from-stdin
      ```
   - scan a single file with a single yara rule
      ```   
      scan -y myrule.yar target_file
      ```
   - scan a single file with all rules in a given directory
     ```
     scan -Y my_rule_dir target_file
     ```
   - check the syntax of all the rules in a given directory
      ```
      scan -c -Y my_rule_dir
      ```
- ## additional features: ##

- **Blacklisting**
   
   The scan tool also supports "blacklisting" rules. These are specified by using the -b and -B command line options. These allow you to exclude certain rules from the search results rather than making changes to the rules themselves. We use this technique to allow us to use the open source yara repository as-is, rather than trying to maintain a modified branch.       
  
  
- **Tagging**
   ```
   Any tags specified in the rules will end up as tags in ACE. All tags should be lower case.

   Some tags can influence a specific behavior within our tools. For example, using the tag 'informational' will mark a rule as such and may not actually generate an alert if it is detected.

   To add tags to a yara rule, use a space-separated list after the rule name.

      rule shellcode_1: shellcode informational
      {
          ...
   In the above example, "shellcode", and "informational" are all tags.
   ```
- **Rule Output Selection**

   You can specify when a rule should (or should not) be displayed. This allows you to prevent some rules from matching against certain kinds of files, or for a rule to be matched against only one specific file.

   The rules are specified as metadata name and value pairs. (example rule syntax)
   ```
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
   - Metadata Names and Descriptions
      ```
      file_ext   | Matches everything past the first period in the file name.
      file_name  | Matches the full name of the file (not including the path.)
      full_path  | Matches against the full path of the file, if one was specified.
      mime_type  | Matches against the output of file -b --mime-type.
      ```
      The value of the metadata variable is the string to match. By default the library matches as is, but special modifiers can be used to perform sub string matching and regular expressions. ** Special modifiers are added to the beginning of the value (or list of values) and apply to all values in the string. **
      
   - Matching Modifiers
      ```
      !     | negation    | Negates the match. This can be placed before other modifiers.
      sub:  | sub-search  | Match if this string appears anywhere.
      re:   | regex       | Match if the regular expression is satisfied.
      ```
      Values can be a comma separated list of values, regardless of the modifiers. Therefor, commas cannot be used in the patterns.

   - Rule Selection Examples

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
   - Modifiers
   
      Yara rules can contain the special meta value of modifiers that changes the way our tools interprets the results of the yara scan.  This is currently only supported by the ACE platform.  The value takes the form of a comma separated list of key=value pairs.  The following values are currently supported.
      ```
      no_alert | Causes the yara rule to not trigger an alert by itself. Normally any match of a yara would become a detection point and trigger an alert.
      ```
      ```
      directive=VALUE	| Causes the given directive to be applied to the file being scanned. This can be used to trigger other actions on the file.
      ```
