rule invalid_syntax {
    strings:
        $ = "test"
    condition:
        any of them
