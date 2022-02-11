rule test {
    meta:
        file_ext = "txt"
    strings:
        $a = "abc"

    condition:
        any of them
}

rule other {
    meta:
        file_ext = "bas"
    strings:
        $ = "abc"
    condition:
        any of them
}
