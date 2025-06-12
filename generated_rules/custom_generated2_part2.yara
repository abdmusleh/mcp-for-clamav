// Part 2 of 554 rules


rule SuspiciousStrings_d12cd9490fd75e192ea053a05e869e_8783ac3c
{
    meta:
        description = "Detects suspicious strings in d12cd9490fd75e192ea053a05e869ed2f3f9748bf1563e6e496e7153fb4e6c98"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d2cc1135c314f526f88fbe19f25d94_80c32b29
{
    meta:
        description = "Detects suspicious strings in d2cc1135c314f526f88fbe19f25d94899d52de7e3422f334437f32388d040d71"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d30f306d4d866a07372b94f7657a7a_6f11a678
{
    meta:
        description = "Detects suspicious strings in d30f306d4d866a07372b94f7657a7a2b0500137fe7ef51678d0ef4249895c2c5"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "Temp\\" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d43c10a2c983049d4a32487ab1e8fe_b61068f8
{
    meta:
        description = "Detects suspicious strings in d43c10a2c983049d4a32487ab1e8fe7727646052228554e0112f6651f4833d2c"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "downloadfile" nocase
        $s3 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d5c57788cf12b020c4083eb2289112_85f5feee
{
    meta:
        description = "Detects suspicious strings in d5c57788cf12b020c4083eb228911260b744a2a67c88662c9bab8faebca98fa2"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d86af736644e20e62807f03c49f4d0_c0321a1a
{
    meta:
        description = "Detects suspicious strings in d86af736644e20e62807f03c49f4d0ad7de9cbd0723049f34ec79f8c7308fdd5"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".exe" nocase
        $s3 = ".dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "downloadfile" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d8a849654ab97debaf28ae5b749c3b_a6dcae1c
{
    meta:
        description = "Detects suspicious strings in d8a849654ab97debaf28ae5b749c3b1ff1812ea49978713853333db48c3972c3"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_decrypted_ex_f593d4ea
{
    meta:
        description = "Detects suspicious strings in decrypted.ex_"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".exe" nocase
        $s3 = ".dll" nocase
        $s4 = "user32.dll" nocase
        $s5 = "kernel32.dll" nocase
        $s6 = "advapi32.dll" nocase
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        $s9 = "shell" nocase
        $s10 = "encrypt" nocase
        $s11 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_dircrypt_deobf_d224637a
{
    meta:
        description = "Detects suspicious strings in dircrypt.deobf"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "AppData" nocase
        $s6 = "regopenkey" nocase
        $s7 = "shell" nocase
        $s8 = "encrypt" nocase
        $s9 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_dropper_ex_01818502
{
    meta:
        description = "Detects suspicious strings in dropper.ex_"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_dump1_exe_4ef5f0a6
{
    meta:
        description = "Detects suspicious strings in dump1.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "createprocess" nocase
        $s6 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_dumped_dll_fe756584
{
    meta:
        description = "Detects suspicious strings in dumped.dll"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "C:\\Windows\\" nocase
        $s5 = "regopenkey" nocase
        $s6 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e049d8f69ddee0c2d360c27b98fa9e_994bd0b2
{
    meta:
        description = "Detects suspicious strings in e049d8f69ddee0c2d360c27b98fa9e61b7202bb0d3884dd3ca63f8aa288422dc"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "advapi32.dll" nocase
        $s3 = "downloadfile" nocase
        $s4 = "regopenkey" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e1ba03a10a40aab909b2ba58dcdfd3_6662c390
{
    meta:
        description = "Detects suspicious strings in e1ba03a10a40aab909b2ba58dcdfd378b4d264f1f4a554b669797bbb8c8ac902"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e83c6c36dbd143ee0fd36aff30fb43_85675248
{
    meta:
        description = "Detects suspicious strings in e83c6c36dbd143ee0fd36aff30fb43529a34129817dc2530f251121527cbf4b4"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e89614e3b0430d706bef2d1f13b30b_9f9723c5
{
    meta:
        description = "Detects suspicious strings in e89614e3b0430d706bef2d1f13b30b43e5c53db9a477e2ff60ef5464e1e9add4.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "createprocess" nocase
        $s5 = "regopenkey" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e93d6f4ce34d4f594d7aed76cfde0f_e93d6f4c
{
    meta:
        description = "Detects suspicious strings in e93d6f4ce34d4f594d7aed76cfde0fad"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_eac776c3c83c9db1a770ffaf6df9e9_518f52aa
{
    meta:
        description = "Detects suspicious strings in eac776c3c83c9db1a770ffaf6df9e94611c8293cbd41cb9257148603b8f2be0b"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ebdf3d3e0867b29e66d8b7570be4e6_e7417613
{
    meta:
        description = "Detects suspicious strings in ebdf3d3e0867b29e66d8b7570be4e6619c64fae7e1fbd052be387f736c980c8e"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_eefa052da01c3faa1d1f516ddfefa8_8ed9a601
{
    meta:
        description = "Detects suspicious strings in eefa052da01c3faa1d1f516ddfefa8ceb8a5185bb9b5368142ffdf839aea4506"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ef47aaf4e964e1e1b7787c480e60a7_22872f40
{
    meta:
        description = "Detects suspicious strings in ef47aaf4e964e1e1b7787c480e60a744550de847618510d2bf54bbc5bda57470"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".exe" nocase
        $s2 = ".dll" nocase
        $s3 = "rundll32.exe" nocase
        $s4 = "user32.dll" nocase
        $s5 = "kernel32.dll" nocase
        $s6 = "advapi32.dll" nocase
        $s7 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f152ed03e4383592ce7dd548c34f73_43451a16
{
    meta:
        description = "Detects suspicious strings in f152ed03e4383592ce7dd548c34f73da53fc457ce8f26d165155a331cde643a9"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f1d903251db466d35533c28e3c032b_06665b96
{
    meta:
        description = "Detects suspicious strings in f1d903251db466d35533c28e3c032b7212aa43c8d64ddf8c5521b43031e69e1e"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f60b29cfb7eab3aeb391f46e94d4d8_9a6e4b8a
{
    meta:
        description = "Detects suspicious strings in f60b29cfb7eab3aeb391f46e94d4d8efadde5498583a2f5c71bd8212d8ae92da"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".exe" nocase
        $s2 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f6e5a3a32fb3aaf3f2c56ee482998b_2ec79d06
{
    meta:
        description = "Detects suspicious strings in f6e5a3a32fb3aaf3f2c56ee482998b09a6ced0a60c38088e7153f3ca247ab1cc"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f_mydoom_exe_91800f7d
{
    meta:
        description = "Detects suspicious strings in f-mydoom.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "virus" nocase
        $s5 = "regopenkey" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_fa5390bbcc4ab768dd81f31eac0950_fa5390bb
{
    meta:
        description = "Detects suspicious strings in fa5390bbcc4ab768dd81f31eac0950f6"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_fc75410aa8f76154f5ae8fe035b9a1_5e8e046c
{
    meta:
        description = "Detects suspicious strings in fc75410aa8f76154f5ae8fe035b9a13c76f6e132077346101a0d673ed9f3a0dd"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "downloadfile" nocase
        $s3 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_fef436e4196ae779ec1d6dd6dcfeec_6aa3115f
{
    meta:
        description = "Detects suspicious strings in fef436e4196ae779ec1d6dd6dcfeec045bc1f848efed5b24e287354a18c6dd85"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_file_4571518150a8181b403df4ae7_1c837a8f
{
    meta:
        description = "Detects suspicious strings in file_4571518150a8181b403df4ae7ad54ce8b16ded0c.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_fm_dll_51c2ee93
{
    meta:
        description = "Detects suspicious strings in fm.dll"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "ProgramData" nocase
        $s2 = "AppData" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_hV46VA_dll_eb1ef1b9
{
    meta:
        description = "Detects suspicious strings in hV46VA.dll"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "rundll32.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_hostr_exe_5a559b6d
{
    meta:
        description = "Detects suspicious strings in hostr.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_jpeg1x32_dll_C2BA81C0DE01038A5_c2ba81c0
{
    meta:
        description = "Detects suspicious strings in jpeg1x32.dll_C2BA81C0DE01038A54703DE26B18E9EE"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "regopenkey" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_linux_chapros__E022DE72CCE8129_e022de72
{
    meta:
        description = "Detects suspicious strings in linux-chapros_ E022DE72CCE8129BD5AC8A0675996318"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "inject" nocase
        $s1 = "encrypt" nocase
        $s2 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_loader_00400000_Embedded01_DLL_9a6598ac
{
    meta:
        description = "Detects suspicious strings in loader_00400000.Embedded01.DLL"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".exe" nocase
        $s2 = ".dll" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "regopenkey" nocase
        $s7 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_loader_00400000_Embedded01_SYS_f60f2d93
{
    meta:
        description = "Detects suspicious strings in loader_00400000.Embedded01.SYS"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_lwxtbjqm_cpp_8334d269
{
    meta:
        description = "Detects suspicious strings in lwxtbjqm.cpp"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_malware_exe_4a5e58d6
{
    meta:
        description = "Detects suspicious strings in malware.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_malware_exe_76101675
{
    meta:
        description = "Detects suspicious strings in malware.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "createprocess" nocase
        $s6 = "regopenkey" nocase
        $s7 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_payload_dll_d6725d6f
{
    meta:
        description = "Detects suspicious strings in payload.dll"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_php_5c4dc9e4
{
    meta:
        description = "Detects suspicious strings in php"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "shell" nocase
        $s1 = "encrypt" nocase
        $s2 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_pw_dll_db87daf7
{
    meta:
        description = "Detects suspicious strings in pw.dll"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "AppData" nocase
        $s6 = "regopenkey" nocase
        $s7 = "encrypt" nocase
        $s8 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_sc2_dll_be128028
{
    meta:
        description = "Detects suspicious strings in sc2.dll"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_scanslam_exe_e7486668
{
    meta:
        description = "Detects suspicious strings in scanslam.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_signed_exe_e904bf93
{
    meta:
        description = "Detects suspicious strings in signed.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".exe" nocase
        $s2 = ".dll" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_slide_exe_06f46062
{
    meta:
        description = "Detects suspicious strings in slide.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_stabuniq_F31B797831B36A4877AA0_f31b7978
{
    meta:
        description = "Detects suspicious strings in stabuniq_F31B797831B36A4877AA0FD173A7A4A2"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_the_zeus_binary_chapros_3840a650
{
    meta:
        description = "Detects suspicious strings in the_zeus_binary_chapros"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "cmd.exe" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_unpacked_dropper_ex_c042511d
{
    meta:
        description = "Detects suspicious strings in unpacked_dropper.ex_"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".exe" nocase
        $s2 = ".dll" nocase
        $s3 = "powershell.exe" nocase
        $s4 = "rundll32.exe" nocase
        $s5 = "user32.dll" nocase
        $s6 = "kernel32.dll" nocase
        $s7 = "advapi32.dll" nocase
        $s8 = "createprocess" nocase
        $s9 = "regopenkey" nocase
        $s10 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_win32_duqu_c9a31ea1
{
    meta:
        description = "Detects suspicious strings in win32.duqu"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_win32_exe_c9a31ea1
{
    meta:
        description = "Detects suspicious strings in win32.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_wmighost_dll_0df40b22
{
    meta:
        description = "Detects suspicious strings in wmighost.dll"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "C:\\Windows\\" nocase
        $s4 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ydrHrp_One_dll_eb1ef1b9
{
    meta:
        description = "Detects suspicious strings in ydrHrp_One.dll"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "rundll32.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}

