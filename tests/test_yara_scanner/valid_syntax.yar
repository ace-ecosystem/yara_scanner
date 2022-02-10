rule valid_yara_rule {
    strings:
        $ = "test"
    condition:
        all of them
}
