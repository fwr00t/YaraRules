rule medusa_ransomware
{
    meta: 
        last_updated = "2025-07-10"
        author = "fwr00t"
        description = "Detect Medusa Ransomware"

    strings:
        // Fill out identifying strings and other criteria
	$s1 = {76 69 3A 6E 73 64 66 70 6B 3A 74 3A 77 3A 56}
	$s2 = {00 63 6D 64 20 2F 63 20 70 69 6E 67 20 6C 6F 63 61 6C 68 6F 73 74 20 2D 6E 20 33 20 3E 20 6E 75 6C 20 26 20 64 65 6C}
	$s3 = "\\AppData\\LocalLow\\" ascii wide nocase

    condition:
        // Fill out the conditions that must be met to identify the binary
        uint16(0) == 0x5A4D and all of them
}
