rule FOG_Ransomware_A

{

    meta:

        description = "FOG Ransomware A"
        author = "Sam Mayers | Beazley Security Labs"
        date = "2024-10-22"
        rule_version = "v1"
        malware_type = "ransomware"
        actor_group = "Fog"
        target_entity = "file"        
        hash1 = "64f43b57800752c824e6f918ee3e496d9ba894f777df3bb65bc90e5529444ac7"
        hash2 = "e67260804526323484f564eebeb6c99ed021b960b899ff788aed85bb7a9d75c3"    

    strings:

        $a0 = {8B 10 8D 40 04 8B 70 C8 8B FA 8B CA C1 CF 13 C1 C9 11 33 F9 C1 EA 0A 33 FA 8B CE 8B D6 C1 C9 07 C1 CA 12 33 D1 C1 EE 03 33 D6 03 FA 03 78 C4 03 78 E8 03 FB 43 89 78 04 81 FB 10 02 00 00 72 C0} 
        $a1 = {8B 53 34 8D 5B 04 8B 73 FC 8B FA 8B CA C1 CF 13 C1 C9 11 33 F9 C1 EA 0A 33 FA 8B CE C1 C9 07 8B D6 C1 CA 12 33 CA C1 EE 03 33 CE 81 C1 F0 05 00 00 03 CF 03 4B 1C 03 4B F8 03 C8 40 89 4B 38 83 F8}
        $a2 = {8B 53 34 8D 5B 04 8B 73 FC 8B FA 8B CA C1 CF 13 C1 C9 11 33 F9 C1 EA 0A 33 FA 8B CE C1 C9 07 8B D6 C1 CA 12 33 CA C1 EE 03 33 CE 81 C1 00 06 00 00 03 CF 03 4B 1C 03 4B F8 03 C8 40 89 4B 38 3D 00}
        $a3 = {7B 10 8D 5B 04 8B 4B FC 8B F7 33 7B FC C1 CE 17 81 E7 FF 03 00 00 C1 C9 0A 33 F1 03 34 B8 03 73 E0 01 73 08 83 6D 08 01 75 D5 }

        $b1 = "[-] error call GetDiskFreeSpaceExA(%ws), code %d\n"
        $b2 = "Start encrypt file: %ws\n"
        $b3 = "[-] MoveFileW(%ws) error, code: %d\n"
        $b4 = "[!] File %ws is locked by another process. Try unlock\n"
        $b5 = "[-] CreateFileW(%ws) error, code: %d\n"
        $b6 = "[-] GetFileSizeEx(%ws) error, code %d\n"
        $b7 = "[-] ReadFile(%ws) error, code %d\n"
        $b8 = "[-] WriteFile(%ws) error, code %d\n"
        $b9 = "[-] FindFirstFileW(%ws) call error, code: %d\n"
        $b10 = "Find dir: %ws\n"
        $b11 = "Find file: %ws\n"
        $b12 = "[-] WriteFile(Note) failed, erorr code %d\n"
        $b13 = "[-] Error create Note file %s, error code %d\n"
        $b14 = "[=] thread %d created\n"
        $b15 = "[=] Checking mutex...\n"
        $b16 = "[!] Skip mutex check by -nomutex param.\n"
        $b17 = "[-] Exiting by mutext check\n"
        $b18 = "[=] Decrypting json config\n"
        $b19 = "[+] Defined mutex name: %s\n"
        $b20 = "[-] Error call CommandLineToArgvW, code: %d\n"
        $b21 = "[-] Error call AllocConsole, code: %d\n"
        $b22 = "[-] Error call GetStdHandle, code: %d\n"
        $b23 = "[-] Error load array: %s\n"
        $b24 = "[-] error load value: RSAPubKey\n"
        $b25 = "[-] error load value: LockedExt\n"
        $b26 = "[-] error load value: NoteFileName\n"
        $b27 = "[=] %s: %ws\n"
        $b28 = "[-] CryptStringToBinaryA() error, code: %d\n"
        $b29 = "[=] Init prgn data...\n"
        $b30 = "[-] WnetOpenEnumA failed with error %d\n"
        $b31 = "[-] WnetOpenEnumA extended error code: %d (%d)\n Description: %s\nProvider: %s\n"
        $b32 = "[-] WNetEnumResource failed with error %d\n"
        $b33 = "WNetCloseEnum failed with error %d\n"
        $b34 = "Error threads count (<=1), set to 2\n"
        $b35 = "Uknonwn DrvType (%d) of root: %s, skipped\n"
        $b36 = "Found disk # %d (%s), type: %d\n"
        $b37 = "[-] error call FindFirstVolumeA(), code: %d\n"
        $b38 = "[-] FindFirstVolumeW/FindNextVolumeW returned a bad path: %s\n"
        $b39 = "[-] error call QueryDosDeviceA(), code: %d\n"
        $b40 = "[-] error call FindNextVolumeA(), code %d\n"
        $b41 = "%s %s"
        $b42 = "[-] Init error - config signature not found.\n"
        $b43 = "Program started.\n"
        $b44 = "[-] Error parsing and loading config - exiting.\n"
        $b45 = "[+] JSON config loaded successfully\n"
        $b46 = "[!] All task finished, locker exiting.\n"
        $b47 = "[-] CryptAcquireContextA error, code: %d\n"
        $b48 = "[-] CryptImportKey(Public) error, code: %d\n"
        $b49 = "[-] [%d] CryptReleaseContext() error, code %d\n"
        $b50 = "[-] CryptEncrypt() error, code: %d\n"
        $b51 = "[+] Thread TID %d done and exiting.\n"
        $b52 = "IsWow64Process"
        $b53 = "[-] IsWow64Process() call error, code %d\n"
        $b54 = "[=] Start clear backups..\n"
        $b55 = "%s%s\\vssadmin.exe delete shadows /all /quiet"
        $b56 = "[=] Try to run command: %s\n"
        $b57 = "[-] CreateProcessA(vssadmin) error, code %d\n"
        $b58 = "[-] SHEmptyRecycleBinA() call error, code %d\n"
        $b59 = "[-] call OpenSCManagerA() failed, code %d\n"
        $b60 = "[-] call EnumServicesStatusA() failed, code %d\n"
        $b61 = "[!] Repeat cycle second time...\n"
        $b62 = "[-] call OpenServiceA(%s) failed, error %d\n"
        $b63 = "[!] Send SERVICE_CONTROL_STOP to Svc [%s]\n"
        $b64 = "[-] call ControlService(%s) failed, error %d\n"
        $b65 = "[-] call CreateToolhelp32Snapshot() failed, code %d\n"
        $b66 = "[-] call Process32First() failed, code %d\n"
        $b67 = "[-] call OpenProcess(%s) failed, code %d\n"
        $b68 = "[-] NtQuerySystemInformation() failed, result code %d\n"
        $b69 = "he maximum number of processes has been reached!\n"
        $b70 = "[!] Process PID %d possibly lock file, try terminate\n"
    
  condition:

    (3 of ($a*) or (30 of ($b*)) and filesize < 2MB) 
    
}