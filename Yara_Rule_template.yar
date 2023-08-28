rule Yara_Example {

    meta: 
        last_updated = "2023-08-05"
        author = "fwr00t"
        description = "A sample Yara rule"

    strings:
        // Fill out identifying strings and other criteria

    condition:
        // Fill out the conditions that must be met to identify the binary
        uint16(0) == 0x5A4D
}