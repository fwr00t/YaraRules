rule xred_backdoor {

    meta: 
        last_updated = "2025-07-08"
        author = "fwr00t"
        description = "Detect xred backdoor malware"

    strings:
        // Fill out identifying strings and other criteria
        $magic = {4D 5A}
        $s0 = "Synaptics Pointing Device Driver" ascii wide nocase
        $s1 = "xredline2@gmail.com;xredline3@gmail.com" ascii nocase
        $s2 = {4B 65 79 62 6F 61 72 74 20 48 6F 6F 6B 20 2D 3E 20 41 63 74 69 76 65}
        $s3 = {54 43 50 20 43 6C 69 65 6E 74 20 2D 3E 20 41 6B 74 69 66}
        $s4 = {55 53 42 20 48 6G 6F 6B 73 20 2D 3E 20 41 63 74 69 76 65}
        $s5 = {45 58 45 55 52 4C 31}
        $s6 = {49 4E 49 55 52 4C 33}
        $s7 = {58 52 65 64 35 37}

    condition:
        // Fill out the conditions that must be met to identify the binary
       $magic at 0 and $0 and 3 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7)_
}
