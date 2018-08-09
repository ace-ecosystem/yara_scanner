rule test {
    strings:
        $a = "abc"

    condition:
        any of them
}
