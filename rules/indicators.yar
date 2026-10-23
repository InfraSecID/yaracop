rule Suspicious_API_Chain {
    meta:
        description = "Detects suspicious Windows API chain (malware indicators)"
        author = "CodeX"
        severity = "high"
        mitre = "T1055"
    strings:
        $api1 = "LoadLibraryA"
        $api2 = "GetProcAddress"
        $api3 = "VirtualProtect"
        $api4 = "IsDebuggerPresent"
        $api5 = "NtUnmapViewOfSection"
        $api6 = "URLDownloadToFileA"
        $api7 = "WinExec"
        $api8 = "ShellExecuteA"
        $api9 = "RegSetValueExA"
        $api10 = "OpenProcessToken"
        $api11 = "AdjustTokenPrivileges"
        $api12 = "LookupPrivilegeValueA"
        $api13 = "CreateMutexA"
        $api14 = "GetTempPathA"
        $hex1 = { 90 90 90 90 }
        $hex2 = { DE AD BE EF }
        $hex3 = { 41 41 41 41 }
    condition:
        5 of ($api*) or any of ($hex*)
}
