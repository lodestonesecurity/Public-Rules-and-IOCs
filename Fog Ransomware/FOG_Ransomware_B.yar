rule FOG_Ransomware_B

{

    meta:

        description = "FOG Ransomware B"
        author = "Bobby Venal | Beazley Security Labs"
        date = "2024-10-22"
        rule_version = "v1"
        malware_type = "ransomware"
        actor_group = "Fog"
        target_entity = "file"
        hash1 = "64f43b57800752c824e6f918ee3e496d9ba894f777df3bb65bc90e5529444ac7"
        hash2 = "e67260804526323484f564eebeb6c99ed021b960b899ff788aed85bb7a9d75c3"    

  strings:

    $a0 = { 8B 10 8D 40 04 8B 70 C8 8B FA 8B CA C1 CF 13 C1 C9 11 33 F9 C1 EA 0A 33 FA 8B CE 8B D6 C1 C9 07 C1 CA 12 33 D1 C1 EE 03 33 D6 03 FA 03 78 C4 03 78 E8 03 FB 43 89 78 04 81 FB 10 02 00 00 72 C0 }
    $a1 = { 8B 53 34 8D 5B 04 8B 73 FC 8B FA 8B CA C1 CF 13 C1 C9 11 33 F9 C1 EA 0A 33 FA 8B CE C1 C9 07 8B D6 C1 CA 12 33 CA C1 EE 03 33 CE 81 C1 F0 05 00 00 03 CF 03 4B 1C 03 4B F8 03 C8 40 89 4B 38 83 F8 }
    $a2 = { 8B 53 34 8D 5B 04 8B 73 FC 8B FA 8B CA C1 CF 13 C1 C9 11 33 F9 C1 EA 0A 33 FA 8B CE C1 C9 07 8B D6 C1 CA 12 33 CA C1 EE 03 33 CE 81 C1 00 06 00 00 03 CF 03 4B 1C 03 4B F8 03 C8 40 89 4B 38 3D 00 }
    $a3 = { 7B 10 8D 5B 04 8B 4B FC 8B F7 33 7B FC C1 CE 17 81 E7 FF 03 00 00 C1 C9 0A 33 F1 03 34 B8 03 73 E0 01 73 08 83 6D 08 01 75 D5 }

  condition:

    (all of ($a*) and filesize < 2MB) 

}