rule ChromeAppDataAccess {
    meta:
        description = "Detects potential access to Google Chrome AppData"
        author = "Ashish Singh"
        date = "2024-07-15"

    strings:
        // Refined strings that might indicate access to Chrome's AppData
        $path_ascii = /.*AppData.{0,50}Local.{0,50}Google.{0,50}Chrome/i
        $path_unicode = /.*\x00A\x00p\x00p\x00D\x00a\x00t\x00a.{0,100}\x00L\x00o\x00c\x00a\x00l.{0,100}\x00G\x00o\x00o\x00g\x00l\x00e.{0,100}\x00C\x00h\x00r\x00o\x00m\x00e/  // Unicode with limited wildcard matches
        $path_obfuscated1 = /.*A.{0,5}p.{0,5}p.{0,5}D.{0,5}a.{0,5}t.{0,5}a.{0,5}L.{0,5}o.{0,5}c.{0,5}a.{0,5}l.{0,5}G.{0,5}o.{0,5}o.{0,5}g.{0,5}l.{0,5}e.{0,5}C.{0,5}h.{0,5}r.{0,5}o.{0,5}m.{0,5}e/  // Spaces between characters with limited wildcards
        $path_obfuscated2 = /.*%41%70%70%44%61%74%61.{0,100}%4C%6F%63%61%6C.{0,100}%47%6F%6F%67%6C%65.{0,100}%43%68%72%6F%6D%65/  // URL encoded with limited wildcard matches

        // Strings that might indicate file access operations (no changes needed here)
        $open_ascii = "open" nocase
        $open_unicode = { 6F 00 70 00 65 00 6E 00 }  // Unicode "open"
        $open_obfuscated = "o p e n"  // Spaces between characters

        $read_ascii = "read" nocase
        $read_unicode = { 72 00 65 00 61 00 64 00 }  // Unicode "read"
        $read_obfuscated = "r e a d"  // Spaces between characters

        $write_ascii = "write" nocase
        $write_unicode = { 77 00 72 00 69 00 74 00 65 00 }  // Unicode "write"
        $write_obfuscated = "w r i t e"  // Spaces between characters

        $create_ascii = "create" nocase
        $create_unicode = { 63 00 72 00 65 00 61 00 74 00 65 00 }  // Unicode "create"
        $create_obfuscated = "c r e a t e"  // Spaces between characters

        $delete_ascii = "delete" nocase
        $delete_unicode = { 64 00 65 00 6C 00 65 00 74 00 65 00 }  // Unicode "delete"
        $delete_obfuscated = "d e l e t e"  // Spaces between characters

    condition:
        ($path_ascii or $path_unicode or $path_obfuscated1 or $path_obfuscated2) and (
            $open_ascii or $open_unicode or $open_obfuscated or
            $read_ascii or $read_unicode or $read_obfuscated or
            $write_ascii or $write_unicode or $write_obfuscated or
            $create_ascii or $create_unicode or $create_obfuscated or
            $delete_ascii or $delete_unicode or $delete_obfuscated
        )
}

rule DetectNetUserCommandAdvanced {
    meta:
        description = "Detects the use of the 'net user' command with variations"
        author = "Ashish Singh"
        date = "2024-07-15"
        version = "1.1"

    strings:
        $net_user_ascii = "net user" nocase
        $net_user_unicode = { 6E 00 65 00 74 00 20 00 75 00 73 00 65 00 72 00 }  // Unicode "net user"
        $net_user_obfuscated1 = "n e t u s e r"  // Spaces between characters
        $net_user_obfuscated2 = "n%20user"  // URL encoded

    condition:
        $net_user_ascii or $net_user_unicode or $net_user_obfuscated1 or $net_user_obfuscated2
}

rule DetectCredentialManagerAccess {
    meta:
        description = "Detects access to Windows Credential Manager"
        author = "Ashish Singh"
        date = "2024-07-15"

    strings:
        $credui = "credui.dll" nocase
        $vaultcli = "vaultcli.dll" nocase
        $cmdkey = "cmdkey" nocase
        $rundll32_credui = "rundll32.exe keymgr.dll,KRShowKeyMgr" nocase
        $rundll32_vaultcli = "rundll32.exe vaultcli.dll,VaultEnumerateItems" nocase

    condition:
        $credui or $vaultcli or $cmdkey or $rundll32_credui or $rundll32_vaultcli
}

rule DetectPasswordDumping {
    meta:
        description = "Detects common methods of password dumping on Windows"
        author = "Ashish Singh"
        date = "2024-07-15"

    strings:
        $mimikatz = "mimikatz" nocase
        $sekurlsa = "sekurlsa" nocase
        $lsadump = "lsadump" nocase
        $dumpcreds = "dumpcreds" nocase
        $procdump = "procdump" nocase
        $samdump = "samdump" nocase
        $ntdsutil = "ntdsutil" nocase

        $mimikatz_unicode = { 6D 00 69 00 6D 00 69 00 6B 00 61 00 74 00 7A 00 }  // Unicode "mimikatz"
        $sekurlsa_unicode = { 73 00 65 00 6B 00 75 00 72 00 6C 00 73 00 61 00 }  // Unicode "sekurlsa"
        $lsadump_unicode = { 6C 00 73 00 61 00 64 00 75 00 6D 00 70 00 }  // Unicode "lsadump"
        $dumpcreds_unicode = { 64 00 75 00 6D 00 70 00 63 00 72 00 65 00 64 00 73 00 }  // Unicode "dumpcreds"
        $procdump_unicode = { 70 00 72 00 6F 00 63 00 64 00 75 00 6D 00 70 00 }  // Unicode "procdump"
        $samdump_unicode = { 73 00 61 00 6D 00 64 00 75 00 6D 00 70 00 }  // Unicode "samdump"
        $ntdsutil_unicode = { 6E 00 74 00 64 00 73 00 75 00 74 00 69 00 6C 00 }  // Unicode "ntdsutil"

        $mimikatz_obfuscated = "m i m i k a t z"  // Spaces between characters
        $sekurlsa_obfuscated = "s e k u r l s a"  // Spaces between characters
        $lsadump_obfuscated = "l s a d u m p"  // Spaces between characters
        $dumpcreds_obfuscated = "d u m p c r e d s"  // Spaces between characters
        $procdump_obfuscated = "p r o c d u m p"  // Spaces between characters
        $samdump_obfuscated = "s a m d u m p"  // Spaces between characters
        $ntdsutil_obfuscated = "n t d s u t i l"  // Spaces between characters

    condition:
        any of them
}

rule NonPyPIURL {
    meta:
        description = "Detects potential non-PyPI URL calls"
        author = "Ashish Singh"
        date = "2024-07-15"

    strings:
        // Match any URL
        $any_url = /http[s]?:\/\/[^\s]*\.[^\s]*/ nocase
        
        // Match PyPI URL
        $pypi_url = /http[s]?:\/\/[^\s]*pypi[^\s]*\.[^\s]*/ nocase

        // Match single-line comments (// or #)
        $single_line_comment = /#.*http[s]?:\/\/[^\s#]+/ nocase

        // Match multi-line comments (/* */)
        $multi_line_comment = /\"\"\".*http[s]?:\/\/[^\s\"\"\"]+.*\"\"\"/s nocase

        // Match Python file extension
        $python_file = /\.py$/ nocase

    condition:
        // The file should be a Python file and contain URLs that are not in comments
        $python_file and $any_url and not ($pypi_url or $single_line_comment or $multi_line_comment)
}

rule DetectSystemInfoAndEventLogTampering {
    meta:
        description = "Detects the use of 'systeminfo' and 'wevtutil' commands for reconnaissance and event log tampering"
        author = "Ashish Singh"
        date = "2024-07-15"

    strings:
        $systeminfo = "systeminfo" nocase
        $wevtutil_clear = "wevtutil cl" nocase
        $wevtutil_export = "wevtutil epl" nocase

    condition:
        $systeminfo or $wevtutil_clear or $wevtutil_export
}

rule DetectWMIandPowerShellDataAccess {
    meta:
        description = "Detects the use of WMI and PowerShell for accessing user data"
        author = "Ashish Singh"
        date = "2024-07-15"

    strings:
        // WMI Queries
        $wmi_useraccount = "wmic useraccount get" nocase
        $wmi_computersystem = "wmic computersystem get" nocase

        // PowerShell Commands
        $ps_getwmiobject = "Get-WmiObject" nocase
        $ps_getaduser = "Get-ADUser" nocase
        $ps_getciminstance = "Get-CimInstance" nocase

        // PowerShell Script Examples
        $ps_script_userinfo = /Get-WmiObject -Class Win32_UserAccount/ nocase
        $ps_script_compsysinfo = /Get-CimInstance -ClassName Win32_ComputerSystem/ nocase

    condition:
        any of them
}
rule DetectNetViewUsage {
    meta:
        description = "Detects the use of 'net view' command for network reconnaissance"
        author = "Ashish Singh"
        date = "2024-07-15"

    strings:
        $net_view = "net view" nocase

    condition:
        $net_view
}

rule DetectTaskSchedulerManipulation {
    meta:
        description = "Detects manipulation of Task Scheduler, which can be used for persistence or executing malicious tasks"
        author = "Ashish Singh"
        date = "2024-07-15"

    strings:
        $schtasks_create = "schtasks /create" nocase
        $schtasks_delete = "schtasks /delete" nocase
        $schtasks_modify = "schtasks /change" nocase
        $schtasks_query = "schtasks /query" nocase

    condition:
        any of them
}

rule DetectNetLocalgroupUsage {
    meta:
        description = "Detects the use of 'net localgroup' command for enumerating or modifying local group memberships"
        author = "Ashish Singh"
        date = "2024-07-15"

    strings:
        $net_localgroup_add = "net localgroup add" nocase
        $net_localgroup_delete = "net localgroup delete" nocase
        $net_localgroup_members = "net localgroup members" nocase
        $net_localgroup_administrators = "net localgroup administrators" nocase

    condition:
        any of them
}

rule DetectSuspiciousAccessToUserDirectories {
    meta:
        description = "Detects suspicious access to user directories potentially for data exfiltration"
        author = "Ashish Singh"
        date = "2024-07-15"

    strings:
        $temp_files = "%TEMP%\\" nocase
        $appdata_files = "%APPDATA%\\" nocase

    condition:
        any of them
}