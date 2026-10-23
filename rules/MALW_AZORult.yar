rule MALW_AZORult {
    meta:
        description = "Detects AZORult info stealer malware"
        author = "Yara-Rules / yaracop"
        severity = "high"
        mitre = "T1555"
    strings:
        $s1 = "AZORult" ascii wide
        $s2 = "passwords.txt" ascii wide
        $s3 = "cookie_list.txt" ascii wide
        $s4 = "Browsers\\Cookies" ascii wide
    condition:
        2 of them
}
