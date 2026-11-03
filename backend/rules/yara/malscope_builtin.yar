/*
   MalScope 内置 YARA 规则集
   用途：静态分析阶段的恶意特征匹配
   说明：规则以行为/能力特征为主，避免使用过宽泛的字节串导致误报
*/

rule MalScope_UPX_Packed
{
    meta:
        description = "检测 UPX 加壳的可执行文件"
        severity = "medium"
        author = "MalScope"
        reference = "https://upx.github.io/"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx_sig = "UPX!" ascii
        $upx_hdr = { 55 50 58 30 }   // "UPX0"
    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($upx0, $upx1, $upx_sig))
            or $upx_hdr
        )
}

rule MalScope_Process_Injection_APIs
{
    meta:
        description = "包含进程注入典型 API 组合（WriteProcessMemory + CreateRemoteThread）"
        severity = "high"
        author = "MalScope"
        attack = "T1055"
    strings:
        $a = "WriteProcessMemory" ascii
        $b = "CreateRemoteThread" ascii
        $c = "VirtualAllocEx" ascii
        $d = "NtCreateThreadEx" ascii
        $e = "QueueUserAPC" ascii
        $f = "SetThreadContext" ascii
    condition:
        uint16(0) == 0x5A4D and
        (
            ($a and ($b or $d))
            or ($c and $e)
            or ($f and $b)
        )
}

rule MalScope_Anti_Debug_Checks
{
    meta:
        description = "包含反调试检测特征"
        severity = "medium"
        author = "MalScope"
        attack = "T1622"
    strings:
        $a = "IsDebuggerPresent" ascii
        $b = "CheckRemoteDebuggerPresent" ascii
        $c = "NtQueryInformationProcess" ascii
        $d = "OutputDebugString" ascii
        $e = "BeingDebugged" ascii
        $f = "PEB" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule MalScope_Anti_VM_Sandbox
{
    meta:
        description = "包含反虚拟机/反沙箱探测字符串"
        severity = "medium"
        author = "MalScope"
        attack = "T1497"
    strings:
        $vm1 = "VMware" ascii nocase
        $vm2 = "VirtualBox" ascii nocase
        $vm3 = "VBoxService" ascii nocase
        $vm4 = "qemu" ascii nocase
        $vm5 = "Xen" ascii nocase
        $vm6 = "sandbox" ascii nocase
        $vm7 = "SbieDll" ascii nocase
        $vm8 = "wine_get_unix_file_name" ascii nocase
        $vm9 = "VMTools" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule MalScope_Ransomware_Note
{
    meta:
        description = "包含勒索信文本特征"
        severity = "critical"
        author = "MalScope"
        attack = "T1486"
    strings:
        $n1 = "your files have been encrypted" ascii nocase wide
        $n2 = "all your files are encrypted" ascii nocase wide
        $n3 = "your personal files are encrypted" ascii nocase wide
        $n4 = "to decrypt your files" ascii nocase wide
        $n5 = "recover your files" ascii nocase wide
        $n6 = "bitcoin" ascii nocase wide
        $n7 = "payment" ascii nocase wide
        $n8 = "decryption key" ascii nocase wide
    condition:
        3 of them
}

rule MalScope_Ransomware_Crypto_APIs
{
    meta:
        description = "勒索加密 API 组合（CryptEncrypt + 批量文件枚举）"
        severity = "high"
        author = "MalScope"
        attack = "T1486"
    strings:
        $a = "CryptEncrypt" ascii
        $b = "CryptGenKey" ascii
        $c = "BCryptEncrypt" ascii
        $d = "FindFirstFile" ascii
        $e = "FindNextFile" ascii
        $f = "EncryptFile" ascii
        $g = "vssadmin" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        ((($a or $b or $c) and ($d or $e)) or $f or $g)
}

rule MalScope_Shadow_Copy_Deletion
{
    meta:
        description = "删除卷影副本命令（勒索软件常见前置动作）"
        severity = "high"
        author = "MalScope"
        attack = "T1490"
    strings:
        $a = "vssadmin delete shadows" ascii nocase wide
        $b = "wmic shadowcopy delete" ascii nocase wide
        $c = "shadowcopy delete" ascii nocase wide
        $d = "bcdedit /set {default} recoveryenabled no" ascii nocase wide
    condition:
        any of them
}

rule MalScope_PowerShell_Encoded
{
    meta:
        description = "PowerShell 编码执行命令"
        severity = "high"
        author = "MalScope"
        attack = "T1059.001"
    strings:
        $a = "-EncodedCommand" ascii nocase wide
        $b = "-enc " ascii nocase wide
        $c = "FromBase64String" ascii nocase wide
        $d = "powershell" ascii nocase wide
    condition:
        $d and ($a or ($b and $c))
}

rule MalScope_Credential_Dumping
{
    meta:
        description = "凭据转储特征（LSASS / Mimikatz）"
        severity = "critical"
        author = "MalScope"
        attack = "T1003"
    strings:
        $a = "MiniDumpWriteDump" ascii
        $b = "lsass.exe" ascii nocase wide
        $c = "sekurlsa" ascii nocase
        $d = "mimikatz" ascii nocase
        $e = "CredEnumerate" ascii
        $f = "LsaEnumerateLogonSessions" ascii
    condition:
        ($a and $b) or $c or $d or ($e and $f)
}

rule MalScope_Keylogger
{
    meta:
        description = "键盘记录/截屏行为特征"
        severity = "high"
        author = "MalScope"
        attack = "T1056.001"
    strings:
        $a = "GetAsyncKeyState" ascii
        $b = "GetKeyboardState" ascii
        $c = "SetWindowsHookEx" ascii
        $d = "GetForegroundWindow" ascii
        $e = "GetClipboardData" ascii
        $f = "BitBlt" ascii
    condition:
        uint16(0) == 0x5A4D and (($a and ($d or $c)) or ($b and $e) or $f)
}

rule MalScope_Persistence_Registry
{
    meta:
        description = "自启动注册表持久化"
        severity = "high"
        author = "MalScope"
        attack = "T1547.001"
    strings:
        $a = "CurrentVersion\\Run" ascii wide
        $b = "CurrentVersion\\RunOnce" ascii wide
        $c = "Winlogon\\Shell" ascii wide
        $d = "Image File Execution Options" ascii wide
        $e = "CurrentVersion\\Explorer\\Shell Folders" ascii wide
    condition:
        any of them
}

rule MalScope_LOLBin_Download
{
    meta:
        description = "使用系统自带程序下载/执行载荷（LOLBin）"
        severity = "high"
        author = "MalScope"
        attack = "T1218"
    strings:
        $a = "certutil" ascii nocase wide
        $b = "-urlcache" ascii nocase wide
        $c = "bitsadmin" ascii nocase wide
        $d = "mshta" ascii nocase wide
        $e = "regsvr32" ascii nocase wide
        $f = "rundll32" ascii nocase wide
        $g = "http://" ascii wide
        $h = "https://" ascii wide
    condition:
        (($a and $b) or $c or ($d and ($g or $h)) or ($e and $g) or ($f and $g))
}

rule MalScope_Common_Mutex
{
    meta:
        description = "常见恶意软件互斥体命名特征"
        severity = "low"
        author = "MalScope"
    strings:
        $m1 = "Global\\" ascii wide
        $m2 = "Local\\" ascii wide
        $m3 = "Mutex" ascii nocase wide
        $m4 = "mutex" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule MalScope_Office_Macro_AutoExec
{
    meta:
        description = "Office 文档包含自动执行宏"
        severity = "critical"
        author = "MalScope"
        attack = "T1204.002"
    strings:
        $a = "AutoOpen" ascii nocase wide
        $b = "Document_Open" ascii nocase wide
        $c = "Workbook_Open" ascii nocase wide
        $d = "Auto_Open" ascii nocase wide
        $e = "CreateObject" ascii nocase wide
        $f = "WScript.Shell" ascii nocase wide
        $g = "powershell" ascii nocase wide
    condition:
        (uint16(0) == 0x4D5A or uint32(0) == 0xE011CFD0 or uint32(0) == 0x04034B50) and
        ($a or $b or $c or $d) and ($e or $f or $g)
}

rule MalScope_Embedded_PE
{
    meta:
        description = "非 PE 文件中嵌入 PE 载荷（释放器/捆绑器）"
        severity = "high"
        author = "MalScope"
        attack = "T1027"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        uint16(0) != 0x5A4D and
        #mz > 1 and $pe
}

rule MalScope_Suspicious_UserAgent
{
    meta:
        description = "硬编码可疑 User-Agent（C2 通信特征）"
        severity = "medium"
        author = "MalScope"
        attack = "T1071.001"
    strings:
        $ua1 = "Mozilla/5.0 (Windows NT 6.1; WOW64)" ascii
        $ua2 = "Mozilla/4.0 (compatible; MSIE 7.0" ascii
        $ua3 = "Mozilla/5.0 (compatible; MSIE 10.0" ascii
        $ua4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" ascii
    condition:
        any of them and uint16(0) == 0x5A4D
}

rule MalScope_Base64_Exec
{
    meta:
        description = "Base64 解码后执行（无文件攻击特征）"
        severity = "high"
        author = "MalScope"
        attack = "T1027"
    strings:
        $a = "FromBase64String" ascii nocase wide
        $b = "base64_decode" ascii nocase
        $c = "eval(" ascii
        $d = "Invoke-Expression" ascii nocase wide
        $e = "IEX " ascii nocase wide
    condition:
        ($a and ($c or $d or $e)) or ($b and $c)
}

rule MalScope_Defense_Evasion_Disable
{
    meta:
        description = "关闭安全防护/篡改安全策略"
        severity = "high"
        author = "MalScope"
        attack = "T1562"
    strings:
        $a = "DisableRealtimeMonitoring" ascii nocase
        $b = "Set-MpPreference" ascii nocase wide
        $c = "netsh advfirewall set" ascii nocase wide
        $d = "sc stop" ascii nocase wide
        $e = "TerminateProcess" ascii
        $f = "taskkill" ascii nocase wide
    condition:
        2 of them
}

rule MalScope_Shellcode_Exec
{
    meta:
        description = "Shellcode 执行特征（VirtualAlloc + 回调/APC）"
        severity = "high"
        author = "MalScope"
        attack = "T1055"
    strings:
        $a = "VirtualAlloc" ascii
        $b = "VirtualProtect" ascii
        $c = "EnumDesktops" ascii
        $d = "EnumWindows" ascii
        $e = "CallWindowProc" ascii
        $f = "RtlMoveMemory" ascii
    condition:
        uint16(0) == 0x5A4D and $a and ($b or $f) and ($c or $d or $e)
}

rule MalScope_Network_Beacon
{
    meta:
        description = "网络心跳/远控通信特征"
        severity = "medium"
        author = "MalScope"
        attack = "T1071"
    strings:
        $a = "WinHttpOpen" ascii
        $b = "WinHttpSendRequest" ascii
        $c = "InternetOpenUrl" ascii
        $d = "URLDownloadToFile" ascii
        $e = "/gate.php" ascii
        $f = "/panel/" ascii
        $g = "cmd=ping" ascii
        $h = "User-Agent:" ascii
    condition:
        uint16(0) == 0x5A4D and (($a and $b) or $c or $d or $e or $f or $g or ($h and ($e or $f)))
}

rule MalScope_UPX_Signature_Bytes
{
    meta:
        description = "UPX 特征字节序列"
        severity = "low"
        author = "MalScope"
    strings:
        $upx = { 55 50 58 21 }   // "UPX!"
    condition:
        uint16(0) == 0x5A4D and $upx
}
