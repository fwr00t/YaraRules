rule wannacry_ransomware
{
    meta: 
        last_updated = "2025-07-10"
        author = "fwr00t"
        description = "Detect WannaCry Ransomware"

    strings:
        // Fill out identifying strings and other criteria
	$s1 = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide nocase
	$s2 = { 43 72 65 61 74 65 53 65 72 76 69 63 65 41 }
	$s3 = "mssecsvc2.0" ascii wide nocase

    condition:
        // Fill out the conditions that must be met to identify the binary
        uint16(0) == 0x5A4D and all of them
}
