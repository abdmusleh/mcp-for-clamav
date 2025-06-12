// Part 1 of 554 rules


rule SuspiciousStrings_03254e6240c35f7d787ca5175ffc36_390f1382
{
    meta:
        description = "Detects suspicious strings in 03254e6240c35f7d787ca5175ffc36818185e62bdfc4d88d5b342451a747156d"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".exe" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_0468127a19daf4c7bc41015c5640fe_0468127a
{
    meta:
        description = "Detects suspicious strings in 0468127a19daf4c7bc41015c5640fe1f"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".dll" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_0581a38d1dc61e0da50722cb6c4253_39192da3
{
    meta:
        description = "Detects suspicious strings in 0581a38d1dc61e0da50722cb6c4253d603cc7965c87e1e42db548460d4abdcae.bin"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_084a220ba90622cc223b93f32130e9_11b8142c
{
    meta:
        description = "Detects suspicious strings in 084a220ba90622cc223b93f32130e9f2d072679f66d1816775bf14832d492b8a"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "C:\\Windows\\" nocase
        $s4 = "Temp\\" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_08fd696873ed9df967a991fb397fe1_c4de3fea
{
    meta:
        description = "Detects suspicious strings in 08fd696873ed9df967a991fb397fe11e54a4367c81c6660575e1413b440c3af2"
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


rule SuspiciousStrings_0cfc34fa76228b1afc7ce63e284a23_34409aba
{
    meta:
        description = "Detects suspicious strings in 0cfc34fa76228b1afc7ce63e284a23ce1cd2927e6159b9dea9702ad9cb2a6300"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "C:\\Windows\\" nocase
        $s4 = "AppData" nocase
        $s5 = "Temp\\" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_0d7d4dc173c88c4f72c8f9f419ae84_60d083b7
{
    meta:
        description = "Detects suspicious strings in 0d7d4dc173c88c4f72c8f9f419ae8473d044f4b3e8f32e4a0f34fe4bbc698776"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".exe" nocase
        $s3 = ".dll" nocase
        $s4 = "cmd.exe" nocase
        $s5 = "user32.dll" nocase
        $s6 = "kernel32.dll" nocase
        $s7 = "C:\\Windows\\" nocase
        $s8 = "backdoor" nocase
        $s9 = "downloadfile" nocase
        $s10 = "createprocess" nocase
        $s11 = "shell" nocase
        $s12 = "inject" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_0d8c2bcb575378f6a88d17b5f6ce70_cc1db536
{
    meta:
        description = "Detects suspicious strings in 0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".exe" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_0ff80e4db32d1d45a0c2afdfd7a1be_549d5b93
{
    meta:
        description = "Detects suspicious strings in 0ff80e4db32d1d45a0c2afdfd7a1be961c0fbd9d43613a22a989f9024cc1b1e9"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_1002_exe_829dde70
{
    meta:
        description = "Detects suspicious strings in 1002.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "shell" nocase
        $s5 = "encrypt" nocase
        $s6 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_119_unp_1d79ad83
{
    meta:
        description = "Detects suspicious strings in 119.unp"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".exe" nocase
        $s3 = ".dll" nocase
        $s4 = "cmd.exe" nocase
        $s5 = "user32.dll" nocase
        $s6 = "kernel32.dll" nocase
        $s7 = "advapi32.dll" nocase
        $s8 = "ProgramData" nocase
        $s9 = "AppData" nocase
        $s10 = "regopenkey" nocase
        $s11 = "shell" nocase
        $s12 = "encrypt" nocase
        $s13 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_1215584b4fa69130799f6cf5efe467_f44b0436
{
    meta:
        description = "Detects suspicious strings in 1215584b4fa69130799f6cf5efe467f380dc68b14ed2c76f63ca6b461ad57246"
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
        $s7 = "virus" nocase
        $s8 = "regopenkey" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_129b8825eaf61dcc2321aad7b84632_c4141ee8
{
    meta:
        description = "Detects suspicious strings in 129b8825eaf61dcc2321aad7b84632233fa4bbc7e24bdf123b507157353930f0"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_131_exe_409d80bb
{
    meta:
        description = "Detects suspicious strings in 131.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "cmd.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "createprocess" nocase
        $s7 = "shell" nocase
        $s8 = "encrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_15540D149889539308135FA12BEDBC_15540d14
{
    meta:
        description = "Detects suspicious strings in 15540D149889539308135FA12BEDBCBF"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".exe" nocase
        $s2 = ".dll" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_1635ec04f069ccc8331d01fdf31132_f8153747
{
    meta:
        description = "Detects suspicious strings in 1635ec04f069ccc8331d01fdf31132a4bc8f6fd3830ac94739df95ee093c555c"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".exe" nocase
        $s3 = ".dll" nocase
        $s4 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_1874b20e3e802406c594341699c586_7bbfe1dd
{
    meta:
        description = "Detects suspicious strings in 1874b20e3e802406c594341699c5863a2c07c4c79cf762888ee28142af83547f"
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


rule SuspiciousStrings_1D34D800AA3320DC17A5786F8EEC16_1d34d800
{
    meta:
        description = "Detects suspicious strings in 1D34D800AA3320DC17A5786F8EEC16EE"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_1b893ca3b782679b1e5d1afecb75be_7a1f2675
{
    meta:
        description = "Detects suspicious strings in 1b893ca3b782679b1e5d1afecb75be7bcc145b5da21a30f6c18dbddc9c6de4e7"
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


rule SuspiciousStrings_1d3d460b22f70cc26252673e12dfd8_6c23ce58
{
    meta:
        description = "Detects suspicious strings in 1d3d460b22f70cc26252673e12dfd85da988f69046d6b94602576270df590b2c"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_1ee894c0b91f3b2f836288c22ebeab_76e94e52
{
    meta:
        description = "Detects suspicious strings in 1ee894c0b91f3b2f836288c22ebeab44798f222f17c255f557af2260b8c6a32d"
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


rule SuspiciousStrings_2094d105ec70aa98866a83b38a2261_5381aa6c
{
    meta:
        description = "Detects suspicious strings in 2094d105ec70aa98866a83b38a22614cff906b2cf0a08970ed59887383ee7b70"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_222d68c03d96d230bc3829e86be882_fdf67793
{
    meta:
        description = "Detects suspicious strings in 222d68c03d96d230bc3829e86be8821f32960375b70388028a705a4986b8d9c6"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_23eeb35780faf868a7b17b8e8da364_f2a5bea9
{
    meta:
        description = "Detects suspicious strings in 23eeb35780faf868a7b17b8e8da364d71bae0e46c1ababddddddecbdbd2c2c64"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "Temp\\" nocase
        $s3 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_23f12c28515e7b9d8b2dd60ef66029_4d6c045c
{
    meta:
        description = "Detects suspicious strings in 23f12c28515e7b9d8b2dd60ef660290ae32434bb50d56a8c8259df4881800971"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_2779937398506e8ad207f5b291ae53_a41843d3
{
    meta:
        description = "Detects suspicious strings in 2779937398506e8ad207f5b291ae53d8af82b9f2739b0508ae3e0cfc40ced092"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_2796a119171328e91648a73d95eb29_c04724af
{
    meta:
        description = "Detects suspicious strings in 2796a119171328e91648a73d95eb297edc220e8768f4bbba5fb7237122a988fc"
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


rule SuspiciousStrings_29D6161522C7F7F21B35401907C702_8baa9b80
{
    meta:
        description = "Detects suspicious strings in 29D6161522C7F7F21B35401907C702BDDB05ED47.bin"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_2A6E_tmp_8102aef5
{
    meta:
        description = "Detects suspicious strings in ___2A6E.tmp"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".dll" nocase
        $s3 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_2_dll_eb1ef1b9
{
    meta:
        description = "Detects suspicious strings in 2.dll"
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


rule SuspiciousStrings_2a9a5afc342cde12c6eb9a91ad29f7_acbf2d1f
{
    meta:
        description = "Detects suspicious strings in 2a9a5afc342cde12c6eb9a91ad29f7afdfd8f0fb17b983dcfddceccfbc17af69"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_2c9c3ddd4d93e687eb095444cef766_7699d7e0
{
    meta:
        description = "Detects suspicious strings in 2c9c3ddd4d93e687eb095444cef7668b21636b364bff55de953bdd1df40071da"
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


rule SuspiciousStrings_2ecb26021d21fcef3d8bba63de0c88_84c2e7ff
{
    meta:
        description = "Detects suspicious strings in 2ecb26021d21fcef3d8bba63de0c888499110a2b78e4caa6fa07a2b27d87f71b"
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


rule SuspiciousStrings_301210D5557D9BA34F401D3EF7A727_301210d5
{
    meta:
        description = "Detects suspicious strings in 301210D5557D9BA34F401D3EF7A7276F"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_30964541572f322a20b541e2e5eeda_fed166a6
{
    meta:
        description = "Detects suspicious strings in 30964541572f322a20b541e2e5eedaa5f20f118995d4b9d4c5d5dda98f09f3d2"
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
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        $s9 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_323CANON_EXE_WORM_VOBFUS_SM01_70f0b7bd
{
    meta:
        description = "Detects suspicious strings in 323CANON.EXE_WORM_VOBFUS.SM01"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "C:\\Windows\\" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_3536df7379660d931256b3cf49be81_26c48a03
{
    meta:
        description = "Detects suspicious strings in 3536df7379660d931256b3cf49be810c0d931c3957c464d75e4cba78ba3b92e3"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_3564ceb9251eccd82d0c060c0dca83_70a64ae4
{
    meta:
        description = "Detects suspicious strings in 3564ceb9251eccd82d0c060c0dca83c9812f72c5fb72b5c25443dfd8a780c734"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_366affd094cc63e2c19c5d57a6866b_c8eb6040
{
    meta:
        description = "Detects suspicious strings in 366affd094cc63e2c19c5d57a6866b487889dab5d1b07c084fff94262d8a390b"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "regopenkey" nocase
        $s5 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_3c2fe308c0a563e06263bbacf793bb_6983f700
{
    meta:
        description = "Detects suspicious strings in 3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_3f2781d44c71a2c0509173118dd97e_f44b7142
{
    meta:
        description = "Detects suspicious strings in 3f2781d44c71a2c0509173118dd97e5196db510a65c9f659dc2366fa315fe5e5"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_40accff9b9d71053d4d6f95e6efd7e_6e67fb38
{
    meta:
        description = "Detects suspicious strings in 40accff9b9d71053d4d6f95e6efd7eca1bb1ef5af77c319fe5a4b429eb373990"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_40c46bcab9acc0d6d235491c01a66d_4b6b86c7
{
    meta:
        description = "Detects suspicious strings in 40c46bcab9acc0d6d235491c01a66d4c6f35d884c19c6f410901af6d1e33513b"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_4529f3751102e7c0a6ec05c6a987d0_f4693d79
{
    meta:
        description = "Detects suspicious strings in 4529f3751102e7c0a6ec05c6a987d0cc5edc08f75f287dd6ac189abbd1282014"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_48b1024f599c3184a49c0d66c56003_0e83b186
{
    meta:
        description = "Detects suspicious strings in 48b1024f599c3184a49c0d66c5600385265b9868d0936134185326e2db0ab441"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_4bfe2216ee63657312af1b2507c8f2_f8c8f645
{
    meta:
        description = "Detects suspicious strings in 4bfe2216ee63657312af1b2507c8f2bf362fdf1d63c88faba397e880c2e39430"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "C:\\Windows\\" nocase
        $s4 = "createprocess" nocase
        $s5 = "inject" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_4cb020a66fdbc99b0bce2ae24d5684_d02abcea
{
    meta:
        description = "Detects suspicious strings in 4cb020a66fdbc99b0bce2ae24d5684685e2b1e9219fbdfda56b3aace4e8d5f66"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".exe" nocase
        $s3 = ".dll" nocase
        $s4 = "cmd.exe" nocase
        $s5 = "Temp\\" nocase
        $s6 = "downloadfile" nocase
        $s7 = "shell" nocase
        $s8 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_4cef5835072bb0290a05f9c5281d4a_c6206b8e
{
    meta:
        description = "Detects suspicious strings in 4cef5835072bb0290a05f9c5281d4a614733f480ba7f1904ae91325a10a15a04"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_4e39bc95e35323ab586d740725a1c8_b505d657
{
    meta:
        description = "Detects suspicious strings in 4e39bc95e35323ab586d740725a1c8cbcde01fe453f7c4cac7cced9a26e42cc9"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_5001793790939009355ba841610412_ba7bb656
{
    meta:
        description = "Detects suspicious strings in 5001793790939009355ba841610412e0f8d60ef5461f2ea272ccf4fd4c83b823"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_51B4EF5DC9D26B7A26E214CEE90598_6e080aa0
{
    meta:
        description = "Detects suspicious strings in 51B4EF5DC9D26B7A26E214CEE90598631E2EAA67"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "createprocess" nocase
        $s3 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_52fe506928b0262f10de31e783af85_3f52ea94
{
    meta:
        description = "Detects suspicious strings in 52fe506928b0262f10de31e783af8540b6a0b232b15749d647847488acd0e17a"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "advapi32.dll" nocase
        $s3 = "regopenkey" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_54c6107c09f591a11e5e347acad5b4_b63e8d42
{
    meta:
        description = "Detects suspicious strings in 54c6107c09f591a11e5e347acad5b47c70ff5d5641a01647854643e007177dab"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "https://" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_5559fcc93eef38a1c22db66a3e0f9e_16ed7909
{
    meta:
        description = "Detects suspicious strings in 5559fcc93eef38a1c22db66a3e0f9e9f026c99e741cc8b1a4980d166f2696188"
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


rule SuspiciousStrings_58bfb9fa8889550d13f42473956dc2_e01e11dc
{
    meta:
        description = "Detects suspicious strings in 58bfb9fa8889550d13f42473956dc2a7ec4f3abb18fd3faeaa38089d513c171f"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "https://" nocase
        $s1 = ".exe" nocase
        $s2 = ".dll" nocase
        $s3 = "cmd.exe" nocase
        $s4 = "user32.dll" nocase
        $s5 = "kernel32.dll" nocase
        $s6 = "advapi32.dll" nocase
        $s7 = "ProgramData" nocase
        $s8 = "AppData" nocase
        $s9 = "downloadfile" nocase
        $s10 = "shell" nocase
        $s11 = "encrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_5a310669920099cd51f82bc9eb5459_7031426f
{
    meta:
        description = "Detects suspicious strings in 5a310669920099cd51f82bc9eb5459e9889b6357a21f7ce95ac961e053c79acb"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "Temp\\" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_5ba187106567e8d036edd5ddb6763f_cc68fcc0
{
    meta:
        description = "Detects suspicious strings in 5ba187106567e8d036edd5ddb6763f89774c158d2a571e15d76572d8604c22a0"
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


rule SuspiciousStrings_5d40615701c48a122e44f831e7c864_be60e389
{
    meta:
        description = "Detects suspicious strings in 5d40615701c48a122e44f831e7c8643d07765629a83b15d090587f469c77693d"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "cmd.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "trojan" nocase
        $s7 = "downloadfile" nocase
        $s8 = "shell" nocase
        $s9 = "encrypt" nocase
        $s10 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_60C01A897DD8D60D3FEA002ED3A4B7_60c01a89
{
    meta:
        description = "Detects suspicious strings in 60C01A897DD8D60D3FEA002ED3A4B764"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_6217cebf11a76c888cc6ae94f54597_96695303
{
    meta:
        description = "Detects suspicious strings in 6217cebf11a76c888cc6ae94f54597a877462ed70da49a88589a9197173cc072"
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


rule SuspiciousStrings_63e6b8136058d7a06dfff4034b4ab1_1e17d819
{
    meta:
        description = "Detects suspicious strings in 63e6b8136058d7a06dfff4034b4ab17a261cdf398e63868a601f77ddd1b32802"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".exe" nocase
        $s3 = ".dll" nocase
        $s4 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_64442cceb7d618e70c62d461cfaafd_3771b975
{
    meta:
        description = "Detects suspicious strings in 64442cceb7d618e70c62d461cfaafdb8e653b8d98ac4765a6b3d8fd1ea3bce15"
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


rule SuspiciousStrings_6674ffe375f8ab54cfa2a276e4a39b_826b772c
{
    meta:
        description = "Detects suspicious strings in 6674ffe375f8ab54cfa2a276e4a39b414cf327e0b00733c215749e8a94385c63"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "rundll32.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "AppData" nocase
        $s7 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_67E4F5301851646B10A95F65A0B3BA_67e4f530
{
    meta:
        description = "Detects suspicious strings in 67E4F5301851646B10A95F65A0B3BACB"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_67ad30c3359b377d1964a5add97d2d_caee691f
{
    meta:
        description = "Detects suspicious strings in 67ad30c3359b377d1964a5add97d2dc96b855940685131b302d5ba2c907ef355"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".exe" nocase
        $s3 = ".dll" nocase
        $s4 = "cmd.exe" nocase
        $s5 = "downloadfile" nocase
        $s6 = "shell" nocase
        $s7 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_683a09da219918258c58a7f61f7dc4_46bfd4f1
{
    meta:
        description = "Detects suspicious strings in 683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96.bin"
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


rule SuspiciousStrings_6B97B3CD2FCFB4B749851432304414_6b97b3cd
{
    meta:
        description = "Detects suspicious strings in 6B97B3CD2FCFB4B74985143230441463_Gadget.exe_"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".dll" nocase
        $s3 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_6b146e3a59025d7085127b552494e8_089a14f6
{
    meta:
        description = "Detects suspicious strings in 6b146e3a59025d7085127b552494e8aaf76450a19c249bfed0b4c09f328e564f"
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


rule SuspiciousStrings_6bc73659a9f251eef5c4e4e4aa7c05_7215ff96
{
    meta:
        description = "Detects suspicious strings in 6bc73659a9f251eef5c4e4e4aa7c05ff95b3df58cde829686ceee8bd845f3442"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "cmd.exe" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "downloadfile" nocase
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_6c006620062b40b22d00e7e73a93e6_4c368fd1
{
    meta:
        description = "Detects suspicious strings in 6c006620062b40b22d00e7e73a93e6a7fa66ce720093b44b4a0f3ef809fa2716"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".exe" nocase
        $s3 = ".dll" nocase
        $s4 = "cmd.exe" nocase
        $s5 = "ProgramData" nocase
        $s6 = "downloadfile" nocase
        $s7 = "shell" nocase
        $s8 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_6c803aac51038ce308ee085f2cd82a_48fb0166
{
    meta:
        description = "Detects suspicious strings in 6c803aac51038ce308ee085f2cd82a055aaa9ba24d08a19efb2c0fcfde936c34"
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


rule SuspiciousStrings_6de1bb58ae3c37876c6372208366f5_520cd9ee
{
    meta:
        description = "Detects suspicious strings in 6de1bb58ae3c37876c6372208366f5548fcc647ffd19ad1d31cebd9069b8a559"
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


rule SuspiciousStrings_6e09e1a4f56ea736ff21ad5e188845_a14a6fb6
{
    meta:
        description = "Detects suspicious strings in 6e09e1a4f56ea736ff21ad5e188845615b57e1a5168f4bdaebe7ddc634912de9"
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


rule SuspiciousStrings_70A1C4ED3A09A44A41D54C4FD4B409_4fe4b956
{
    meta:
        description = "Detects suspicious strings in 70A1C4ED3A09A44A41D54C4FD4B409A5FC3159F6_XAgent_OSX"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "downloadfile" nocase
        $s1 = "shell" nocase
        $s2 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_70f8789b03e38d07584f57581363af_37fc7c5d
{
    meta:
        description = "Detects suspicious strings in 70f8789b03e38d07584f57581363afa848dd5c3a197f2483c6dfa4f3e7f78b9b"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".exe" nocase
        $s3 = ".dll" nocase
        $s4 = "cmd.exe" nocase
        $s5 = "user32.dll" nocase
        $s6 = "kernel32.dll" nocase
        $s7 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_7249b1a5082c9d9654d9fac3bb5e96_71661cb0
{
    meta:
        description = "Detects suspicious strings in 7249b1a5082c9d9654d9fac3bb5e965ea23e395554d3351b77dd4f29677426fe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_73ebf8c9571f00c9923c87e7442f3d_41859ac8
{
    meta:
        description = "Detects suspicious strings in 73ebf8c9571f00c9923c87e7442f3d9132627163c5a64e40ad4eb1a1f2266de9"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_773635768e738bec776dfd7504164b_c40a2f5f
{
    meta:
        description = "Detects suspicious strings in 773635768e738bec776dfd7504164b3596e5eee344757dd1ac9a1ad19b452c86"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_78201fd42dfc65e94774d8a9b87293_29eca628
{
    meta:
        description = "Detects suspicious strings in 78201fd42dfc65e94774d8a9b87293c19044ad93edf59d3ff6846766ed4c3e2e"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_798_abroad_exe_f88e9b74
{
    meta:
        description = "Detects suspicious strings in 798_abroad.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".exe" nocase
        $s2 = ".dll" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_7ZipSetup_exe_02e0b78e
{
    meta:
        description = "Detects suspicious strings in 7ZipSetup.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".exe" nocase
        $s2 = ".dll" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_7d38eb24cf5644e090e45d5efa923a_2c8b9d28
{
    meta:
        description = "Detects suspicious strings in 7d38eb24cf5644e090e45d5efa923aff0e69a600fb0ab627e8929bb485243926"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_81cdbe905392155a1ba8b687a02e65_c7c647a1
{
    meta:
        description = "Detects suspicious strings in 81cdbe905392155a1ba8b687a02e65d611b60aac938e470a76ef518e8cffd74d"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_82f7bcda95fcc0e690159a2fbd7b3e_dd4a8156
{
    meta:
        description = "Detects suspicious strings in 82f7bcda95fcc0e690159a2fbd7b3e38ef3ff9105496498f86d1fa9ff4312846"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".exe" nocase
        $s3 = ".dll" nocase
        $s4 = "cmd.exe" nocase
        $s5 = "downloadfile" nocase
        $s6 = "shell" nocase
        $s7 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_8390e210162d9b14d5b0b1ef9746c1_e1068cac
{
    meta:
        description = "Detects suspicious strings in 8390e210162d9b14d5b0b1ef9746c16853aa2d29d1dfc4eab6a051885e0333ed"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "encrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_86bb737bd9a508be2ff9dc0dee7e7c_6eb39bd2
{
    meta:
        description = "Detects suspicious strings in 86bb737bd9a508be2ff9dc0dee7e7c40abea215088c61788a368948f9250fa4c"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "C:\\Windows\\" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_8953398DE47344E9C2727565AF8D6F_8953398d
{
    meta:
        description = "Detects suspicious strings in 8953398DE47344E9C2727565AF8D6F31"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_8c213b3707b0b042d769fdf543c6e8_e63fead9
{
    meta:
        description = "Detects suspicious strings in 8c213b3707b0b042d769fdf543c6e8bd7c127cea6a9bc989eaf241a1505d1ed9"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_8d7be9ed64811ea7986d788a75cbc4_bfbe8c3e
{
    meta:
        description = "Detects suspicious strings in 8d7be9ed64811ea7986d788a75cbc4ca166702c6ff68c33873270d7c6597f5db"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_8dfaa1f579de14bca8bb27c54a57dd_b162026b
{
    meta:
        description = "Detects suspicious strings in 8dfaa1f579de14bca8bb27c54a57dd87646a835969766ca9ddb81ecd9329f4e4"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_8e97c371633d285cd8fc842f458270_e8eaec1f
{
    meta:
        description = "Detects suspicious strings in 8e97c371633d285cd8fc842f4582705052a9409149ee67d97de545030787a192"
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


rule SuspiciousStrings_901FA02FFD43DE5B2D7C8C6B8C2F6A_901fa02f
{
    meta:
        description = "Detects suspicious strings in 901FA02FFD43DE5B2D7C8C6B8C2F6A43_SideBar.dll_"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_94189147ba9749fd0f184fe94b345b_496131b9
{
    meta:
        description = "Detects suspicious strings in 94189147ba9749fd0f184fe94b345b7385348361480360a59f12adf477f61c97"
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


rule SuspiciousStrings_9900c91f6d754f15f73729ce5a4333_a6b2ac3e
{
    meta:
        description = "Detects suspicious strings in 9900c91f6d754f15f73729ce5a4333a718463e24aa7e6192c7527ec5c80dac42"
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


rule SuspiciousStrings_9A0E765EECC5433AF3DC726206ECC5_9a0e765e
{
    meta:
        description = "Detects suspicious strings in 9A0E765EECC5433AF3DC726206ECC56E"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "downloadfile" nocase
        $s2 = "shell" nocase
        $s3 = "encrypt" nocase
        $s4 = "decrypt" nocase
        $s5 = "payload" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_9a776b895e93926e2a758c09e341ac_97aaf130
{
    meta:
        description = "Detects suspicious strings in 9a776b895e93926e2a758c09e341accb9333edc1243d216a5e53f47c6043c852"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "https://" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_9b3c6fd39b2809e388255c56519532_d9940a3d
{
    meta:
        description = "Detects suspicious strings in 9b3c6fd39b2809e388255c5651953251920c5c7d5e77da1070ab3c127e8bdc11"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_9bd32162e0a50f8661fd19e3b26ff6_b7cf3852
{
    meta:
        description = "Detects suspicious strings in 9bd32162e0a50f8661fd19e3b26ff65868ab5ea636916bd54c244b0148bd9c1b"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "downloadfile" nocase
        $s5 = "regopenkey" nocase
        $s6 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_9c17f267f79597ee01515f5ef92537_a0e874f0
{
    meta:
        description = "Detects suspicious strings in 9c17f267f79597ee01515f5ef925375d8a19844830cc46917a3d1b5bcb0ba4c3"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "cmd.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_9cd5127ef31da0e8a4e36292f2af5a_d240f06e
{
    meta:
        description = "Detects suspicious strings in 9cd5127ef31da0e8a4e36292f2af5a9ec1de3b294da367d7c05786fe2d5de44f"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ArdamaxKeylogger_E33AF9E602CBB_e33af9e6
{
    meta:
        description = "Detects suspicious strings in ArdamaxKeylogger_E33AF9E602CBB7AC3634C2608150DD18"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_BOTBINARY_EXE_9b9e083a
{
    meta:
        description = "Detects suspicious strings in BOTBINARY.EXE"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".exe" nocase
        $s2 = ".dll" nocase
        $s3 = "cmd.exe" nocase
        $s4 = "user32.dll" nocase
        $s5 = "kernel32.dll" nocase
        $s6 = "advapi32.dll" nocase
        $s7 = "C:\\Windows\\" nocase
        $s8 = "createprocess" nocase
        $s9 = "regopenkey" nocase
        $s10 = "shell" nocase
        $s11 = "inject" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Backdoor_MSIL_Tyupkin_a_ViR_af945758
{
    meta:
        description = "Detects suspicious strings in Backdoor.MSIL.Tyupkin.a.ViR"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "regopenkey" nocase
        $s1 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Backdoor_MSIL_Tyupkin_c_ViR_700e91a2
{
    meta:
        description = "Detects suspicious strings in Backdoor.MSIL.Tyupkin.c.ViR"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "regopenkey" nocase
        $s2 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Backdoor_Win32_Tyupkin_c2_ViR_162ad6db
{
    meta:
        description = "Detects suspicious strings in Backdoor.Win32.Tyupkin.c2.ViR"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "regopenkey" nocase
        $s2 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Backdoor_Win32_Tyupkin_h_exe_V_250b77df
{
    meta:
        description = "Detects suspicious strings in Backdoor.Win32.Tyupkin.h.exe.ViR"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "regopenkey" nocase
        $s2 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_C116CD083284CC599C024C3479CA9B_c116cd08
{
    meta:
        description = "Detects suspicious strings in C116CD083284CC599C024C3479CA9B70_2.tmp_"
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


rule SuspiciousStrings_C3B48DB40CF810CB63BF36262B7C5B_c3b48db4
{
    meta:
        description = "Detects suspicious strings in C3B48DB40CF810CB63BF36262B7C5B19"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_D048F7AE2D244A264E58AF67B1A20D_d048f7ae
{
    meta:
        description = "Detects suspicious strings in D048F7AE2D244A264E58AF67B1A20DB0"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_D883DC7ACC192019F220409EE2CADD_d883dc7a
{
    meta:
        description = "Detects suspicious strings in D883DC7ACC192019F220409EE2CADD64"
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


rule SuspiciousStrings_DELLXT_dll_4fe6f465
{
    meta:
        description = "Detects suspicious strings in DELLXT.dll"
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


rule SuspiciousStrings_DF5A394AD60512767D375647DBB829_df5a394a
{
    meta:
        description = "Detects suspicious strings in DF5A394AD60512767D375647DBB82994"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_DoubleFantasy_2A12630FF976BA09_2a12630f
{
    meta:
        description = "Detects suspicious strings in DoubleFantasy_2A12630FF976BA0994143CA93FECD17F"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "createprocess" nocase
        $s6 = "regopenkey" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Dyre_Unpacked_file_4d1d4378
{
    meta:
        description = "Detects suspicious strings in Dyre_Unpacked.file"
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


rule SuspiciousStrings_E906FA3D51E86A61741B3499145A11_6d3d62a4
{
    meta:
        description = "Detects suspicious strings in E906FA3D51E86A61741B3499145A114E9BFB7C56"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "createprocess" nocase
        $s4 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_F1E546FE9D51DC96EB766EC61269ED_f1e546fe
{
    meta:
        description = "Detects suspicious strings in F1E546FE9D51DC96EB766EC61269EDFB"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "regopenkey" nocase
        $s6 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_F77DB63CBED98391027F2525C14E16_f77db63c
{
    meta:
        description = "Detects suspicious strings in F77DB63CBED98391027F2525C14E161F"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_F897A65B_exe_a99afd20
{
    meta:
        description = "Detects suspicious strings in F897A65B.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "createprocess" nocase
        $s6 = "regopenkey" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FancyBear_GermanParliament_77e7fb6b
{
    meta:
        description = "Detects suspicious strings in FancyBear.GermanParliament"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "advapi32.dll" nocase
        $s3 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_002F5E401F705FE91F44_002f5e40
{
    meta:
        description = "Detects suspicious strings in FannyWorm_002F5E401F705FE91F44263E49D6C216"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_0047C4A00161A8478DF3_0047c4a0
{
    meta:
        description = "Detects suspicious strings in FannyWorm_0047C4A00161A8478DF31DBDEA44A19E"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "rundll32.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "C:\\Windows\\" nocase
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        $s9 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_00535DCA6D6DB97128F6_00535dca
{
    meta:
        description = "Detects suspicious strings in FannyWorm_00535DCA6D6DB97128F6E12451C1E04E"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_0063BF5852FFB5BAABCD_0063bf58
{
    meta:
        description = "Detects suspicious strings in FannyWorm_0063BF5852FFB5BAABCDC34AD4F8F0BF"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_00F5F27098D25A1961DF_00f5f270
{
    meta:
        description = "Detects suspicious strings in FannyWorm_00F5F27098D25A1961DF56A1C58398E2"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_00FAE15224F3A3C46D20_00fae152
{
    meta:
        description = "Detects suspicious strings in FannyWorm_00FAE15224F3A3C46D20F2667FB1ED89"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_02D5EB43F5FC03F7ABC8_02d5eb43
{
    meta:
        description = "Detects suspicious strings in FannyWorm_02D5EB43F5FC03F7ABC89C57B82C75F8"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_0333F6533573D7A08B4D_0333f653
{
    meta:
        description = "Detects suspicious strings in FannyWorm_0333F6533573D7A08B4DE47BD186EC65"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_038E4FFBDF9334DD0B96_038e4ffb
{
    meta:
        description = "Detects suspicious strings in FannyWorm_038E4FFBDF9334DD0B96F92104C4A5C0"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_03A5AE64C62EB66DD730_03a5ae64
{
    meta:
        description = "Detects suspicious strings in FannyWorm_03A5AE64C62EB66DD7303801785D3F7B"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_03A64049747B2544A5EE_03a64049
{
    meta:
        description = "Detects suspicious strings in FannyWorm_03A64049747B2544A5EE08A2520495D8"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_04DDB75038698F66B9C4_04ddb750
{
    meta:
        description = "Detects suspicious strings in FannyWorm_04DDB75038698F66B9C43304A2C92240"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_05187AA4D312FF06187C_05187aa4
{
    meta:
        description = "Detects suspicious strings in FannyWorm_05187AA4D312FF06187C93D12DD5F1D0"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_053895AE9A145A74738B_053895ae
{
    meta:
        description = "Detects suspicious strings in FannyWorm_053895AE9A145A74738BA85667AE2CD1"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_05A0274DDEA1D4E2D938_05a0274d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_05A0274DDEA1D4E2D938EE0804DA41DB"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_05E58526F763F069B4C8_05e58526
{
    meta:
        description = "Detects suspicious strings in FannyWorm_05E58526F763F069B4C86D209416F50A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_063AD1284A8DFB82965B_063ad128
{
    meta:
        description = "Detects suspicious strings in FannyWorm_063AD1284A8DFB82965B539EFD965547"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_06A1824482848997877D_06a18244
{
    meta:
        description = "Detects suspicious strings in FannyWorm_06A1824482848997877DA3F5CB83F196"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_07988B3B1AF58A47F7EE_07988b3b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_07988B3B1AF58A47F7EE884E734D9A45"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_0915237A0B1F095AACE0_0915237a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_0915237A0B1F095AACE0A50B82356571"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_09344144F44E598E5167_09344144
{
    meta:
        description = "Detects suspicious strings in FannyWorm_09344144F44E598E516793B36DE7822A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "rundll32.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "C:\\Windows\\" nocase
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        $s9 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_0A704348BD37EA5CCD2E_0a704348
{
    meta:
        description = "Detects suspicious strings in FannyWorm_0A704348BD37EA5CCD2E0A540EB010C2"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_0A78F4F0C5FC09C08DC1_0a78f4f0
{
    meta:
        description = "Detects suspicious strings in FannyWorm_0A78F4F0C5FC09C08DC1B54D7412BC58"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_0ACBDD008B62CD40BB14_0acbdd00
{
    meta:
        description = "Detects suspicious strings in FannyWorm_0ACBDD008B62CD40BB1434ACA7500D5B"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_0B5F75E67B78D34DC420_0b5f75e6
{
    meta:
        description = "Detects suspicious strings in FannyWorm_0B5F75E67B78D34DC4206BF49C7F09E9"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_0C4BD72BD7119C562F81_0c4bd72b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_0C4BD72BD7119C562F81588978AC9DEF"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_0D1248BD21BA2487C086_0d1248bd
{
    meta:
        description = "Detects suspicious strings in FannyWorm_0D1248BD21BA2487C08691EE60B8D80E"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_0E2313835CA0FA52D955_0e231383
{
    meta:
        description = "Detects suspicious strings in FannyWorm_0E2313835CA0FA52D95500F83FE9F5D2"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_0F256B5884F46A15B80B_0f256b58
{
    meta:
        description = "Detects suspicious strings in FannyWorm_0F256B5884F46A15B80B60BBA8876966"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_0FD329C0ECC34C45A874_0fd329c0
{
    meta:
        description = "Detects suspicious strings in FannyWorm_0FD329C0ECC34C45A87414E3DAAD5819"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_101BC932D760F12A308E_101bc932
{
    meta:
        description = "Detects suspicious strings in FannyWorm_101BC932D760F12A308E450EB97EFFA5"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_102A411051EF606241FB_102a4110
{
    meta:
        description = "Detects suspicious strings in FannyWorm_102A411051EF606241FBDC4361E55301"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_10A9CAA724AE8EDC30C0_10a9caa7
{
    meta:
        description = "Detects suspicious strings in FannyWorm_10A9CAA724AE8EDC30C09F8372241C32"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1163AD598B617EF336DD_1163ad59
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1163AD598B617EF336DD75D119182AD4"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1173639E045C32755496_1173639e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1173639E045C327554962500B6240EEB"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_12298EF995A76C71FA54_12298ef9
{
    meta:
        description = "Detects suspicious strings in FannyWorm_12298EF995A76C71FA54CBF279455A14"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_13429F4899618F352966_13429f48
{
    meta:
        description = "Detects suspicious strings in FannyWorm_13429F4899618F3529669A8CE850B512"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1355C1F173E78D3C1317_1355c1f1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1355C1F173E78D3C1317EE2FB5CD95F1"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_13B67C888EFEAF60A9A4_13b67c88
{
    meta:
        description = "Detects suspicious strings in FannyWorm_13B67C888EFEAF60A9A4FB1E4E182F2D"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_149B980E2495DF13EDCE_149b980e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_149B980E2495DF13EDCEFED78716BA8D"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_151C7DA8C611BF9795D8_151c7da8
{
    meta:
        description = "Detects suspicious strings in FannyWorm_151C7DA8C611BF9795D813A5806D6364"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_152AD931B42A8DA9149D_152ad931
{
    meta:
        description = "Detects suspicious strings in FannyWorm_152AD931B42A8DA9149DD73A8BFCFF69"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1643B9B5861CA495F83E_1643b9b5
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1643B9B5861CA495F83ED2DA14480728"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_168AF91D1BA92A41679D_168af91d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_168AF91D1BA92A41679D5B5890DC71E7"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "rundll32.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "C:\\Windows\\" nocase
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        $s9 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_17D287E868AB1DBAFCA8_17d287e8
{
    meta:
        description = "Detects suspicious strings in FannyWorm_17D287E868AB1DBAFCA87EB48B0F848F"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_18CB3574825FA409D5CB_18cb3574
{
    meta:
        description = "Detects suspicious strings in FannyWorm_18CB3574825FA409D5CBC0F67E8CC162"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1925B30A657EA0B5BFC6_1925b30a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1925B30A657EA0B5BFC62D3914F7855F"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_194686907B35B69C508A_19468690
{
    meta:
        description = "Detects suspicious strings in FannyWorm_194686907B35B69C508AE1A82D105ACD"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_19507F6ADFAD9E754C3D_19507f6a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_19507F6ADFAD9E754C3D26695DD61993"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_199E39BDA0AF0A062CCC_199e39bd
{
    meta:
        description = "Detects suspicious strings in FannyWorm_199E39BDA0AF0A062CCC734FACCF9213"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_19EB57E93ED64F2BB9AA_19eb57e9
{
    meta:
        description = "Detects suspicious strings in FannyWorm_19EB57E93ED64F2BB9AAB0307ECE4291"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1B27AC722847F5A3304E_1b27ac72
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1B27AC722847F5A3304E3896F0528FA4"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1B9901D0F5F28C9275A6_1b9901d0
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1B9901D0F5F28C9275A697134D6E487A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1CB7AE1BC76E139C8968_1cb7ae1b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1CB7AE1BC76E139C89684F7797F520A1"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1D6C98E55203F0C51C08_1d6c98e5
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1D6C98E55203F0C51C0821FE52218DD8"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1DD86B28A2BC986B069C_1dd86b28
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1DD86B28A2BC986B069C75BF5C6787B9"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1EF39EB63DDFF30A3E37_1ef39eb6
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1EF39EB63DDFF30A3E37FEEFFB8FC712"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1F1DC3CF1D769D464DB9_1f1dc3cf
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1F1DC3CF1D769D464DB9752C8CECC872"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "rundll32.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "C:\\Windows\\" nocase
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        $s9 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1F69160F1D91BF9A0EDA_1f69160f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1F69160F1D91BF9A0EDA93829B75C583"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1FD210BA936FD11B4678_1fd210ba
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1FD210BA936FD11B46781E04BBC0F8B5"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_205FB6034381DFD9D19D_205fb603
{
    meta:
        description = "Detects suspicious strings in FannyWorm_205FB6034381DFD9D19D076141397CF6"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2062D7B0D9145ADBE013_2062d7b0
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2062D7B0D9145ADBE0131CF1FB1FC35A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_21A6959A33909E3CDF27_21a6959a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_21A6959A33909E3CDF27A455064D4D4D"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_21A9C4073DBB1CB6127F_21a9c407
{
    meta:
        description = "Detects suspicious strings in FannyWorm_21A9C4073DBB1CB6127FDB932C95372C"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2249D5577D2C84BA1043_2249d557
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2249D5577D2C84BA1043376B77E6C24D"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_22DB66045FA1E39B5BF1_22db6604
{
    meta:
        description = "Detects suspicious strings in FannyWorm_22DB66045FA1E39B5BF16FC63A850098"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_24132E1E00071F33221C_24132e1e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_24132E1E00071F33221C405399271B74"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_242A7137788B0F0AEFCE_242a7137
{
    meta:
        description = "Detects suspicious strings in FannyWorm_242A7137788B0F0AEFCEA5C233C951B7"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_246272DD6E9193E31745_246272dd
{
    meta:
        description = "Detects suspicious strings in FannyWorm_246272DD6E9193E31745AD54138F875D"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_263B761FCEA771137F2E_263b761f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_263B761FCEA771137F2EA9918E381B47"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_26C46A09CF1BDFF5AF50_26c46a09
{
    meta:
        description = "Detects suspicious strings in FannyWorm_26C46A09CF1BDFF5AF503A406575809D"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_27C5D028EE23A515DF42_27c5d028
{
    meta:
        description = "Detects suspicious strings in FannyWorm_27C5D028EE23A515DF4203EA6026E23E"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2822D46611AD7FD71DFE_2822d466
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2822D46611AD7FD71DFE5A1F4C79AB4B"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_29F2AB09FDFFC4006A44_29f2ab09
{
    meta:
        description = "Detects suspicious strings in FannyWorm_29F2AB09FDFFC4006A4407C05BA11B65"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_29FDEC2FD992C2AB38E1_29fdec2f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_29FDEC2FD992C2AB38E1DD41500190B9"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2BB52B4C1BC0788BF701_2bb52b4c
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2BB52B4C1BC0788BF701E6F5EE761A9B"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2C029BE8E3B0C9448ED5_2c029be8
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2C029BE8E3B0C9448ED5E88B52852ADE"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2C35ED272225B4E13433_2c35ed27
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2C35ED272225B4E134333BEA2B657A3F"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "rundll32.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "C:\\Windows\\" nocase
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        $s9 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2C6595834DD5528235E8_2c659583
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2C6595834DD5528235E8A9815276563E"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2C87A3442C60C72F639C_2c87a344
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2C87A3442C60C72F639CA7EB6754746A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2D088E08FD1B90342CAE_2d088e08
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2D088E08FD1B90342CAE128770063DBE"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2DA059A8BF3BC00BB809_2da059a8
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2DA059A8BF3BC00BB809B28770044FF6"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2E0E43F2B0499D631EDF_2e0e43f2
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2E0E43F2B0499D631EDF1DD92F09BD2C"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2E208B3D5953BD92C840_2e208b3d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2E208B3D5953BD92C84031D3A7B8A231"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2EBD5BD711CEB8D6B4F6_2ebd5bd7
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2EBD5BD711CEB8D6B4F6EBA38D087BC9"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2F2A8DECA2539923B489_2f2a8dec
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2F2A8DECA2539923B489D51DE9A278F4"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_303B7527DB5B417719DA_303b7527
{
    meta:
        description = "Detects suspicious strings in FannyWorm_303B7527DB5B417719DAF9B0AE5B89AA"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "rundll32.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "C:\\Windows\\" nocase
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        $s9 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_31457CB30CCAD20CDBC7_31457cb3
{
    meta:
        description = "Detects suspicious strings in FannyWorm_31457CB30CCAD20CDBC77B8C4B6F9B3F"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_318D5E8B3DA6C6F5E504_318d5e8b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_318D5E8B3DA6C6F5E5041250CEB5D836"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_38430B3311314A4DC01C_38430b33
{
    meta:
        description = "Detects suspicious strings in FannyWorm_38430B3311314A4DC01C2CDCD29A0D10"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3A3FEE2E8E1ABDD99A02_3a3fee2e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3A3FEE2E8E1ABDD99A020EEB8EE2D271"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3A431D965B9537721BE7_3a431d96
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3A431D965B9537721BE721A48CCCDF0A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3A57ADB8740DA3EBEC16_3a57adb8
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3A57ADB8740DA3EBEC1673D21F20D0FE"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3A71446564B4C060D99A_3a714465
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3A71446564B4C060D99A8CCD2EB5D161"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3AC8BC5E416D59666905_3ac8bc5e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3AC8BC5E416D59666905489AEA3BE51E"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3B496B8CD19789FABF00_3b496b8c
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3B496B8CD19789FABF00584475B607C7"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3DE3419F6441A7F4D664_3de3419f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3DE3419F6441A7F4D664077A43FB404B"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "rundll32.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "C:\\Windows\\" nocase
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        $s9 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3FBD798BCD7214FCBF5F_3fbd798b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3FBD798BCD7214FCBF5FAB05FAF9FD71"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_40000B4F52DCDEDB1E1D_40000b4f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_40000B4F52DCDEDB1E1D3BFD5C185CEC"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_40FEE20FE98995ACBDA8_40fee20f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_40FEE20FE98995ACBDA82DBCDE0B674B"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_41D1E22FABD1CE4D21F5_41d1e22f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_41D1E22FABD1CE4D21F5F7BE352B3A07"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "rundll32.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "C:\\Windows\\" nocase
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        $s9 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_44BD4CF5E28D78CC66B8_44bd4cf5
{
    meta:
        description = "Detects suspicious strings in FannyWorm_44BD4CF5E28D78CC66B828A57C99CA74"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4509385E247EF538CFB8_4509385e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4509385E247EF538CFB8CD42944EE480"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_450A3EDECE8808F48320_450a3ede
{
    meta:
        description = "Detects suspicious strings in FannyWorm_450A3EDECE8808F483203FE8988C4437"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4605A7396D892BBA0646_4605a739
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4605A7396D892BBA0646BC73A02B28E9"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4810559ED364A1884317_4810559e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4810559ED364A18843178F1C4FCA49FC"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_487E79347D92F4450720_487e7934
{
    meta:
        description = "Detects suspicious strings in FannyWorm_487E79347D92F44507200792A7795C7B"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "rundll32.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "C:\\Windows\\" nocase
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        $s9 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_48BC620F4C5B14E30F17_48bc620f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_48BC620F4C5B14E30F173B0D02887840"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_48E958E3785BE0D5E074_48e958e3
{
    meta:
        description = "Detects suspicious strings in FannyWorm_48E958E3785BE0D5E074AD2CFCF2FEE4"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4902CD32C4AE98008BA2_4902cd32
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4902CD32C4AE98008BA24C0F40189E51"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_49622DDF195628F7A340_49622ddf
{
    meta:
        description = "Detects suspicious strings in FannyWorm_49622DDF195628F7A3400B7A9F98E60A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4984608139E2C5430A87_49846081
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4984608139E2C5430A87028F84A2BBB7"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_49CB69039308B2613664_49cb6903
{
    meta:
        description = "Detects suspicious strings in FannyWorm_49CB69039308B2613664515C5FA323E1"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4A3B537879F3F29CD8D4_4a3b5378
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4A3B537879F3F29CD8D446C53E6B06C3"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4AD2F62CE2EB72EFF45C_4ad2f62c
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4AD2F62CE2EB72EFF45C61699BDCB1E3"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4C31FE56FF4A46FBCD87_4c31fe56
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4C31FE56FF4A46FBCD87B28651235177"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4E58BD45A388E458C9F8_4e58bd45
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4E58BD45A388E458C9F8FF09EB905CC0"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4EA931A432BB9555483B_4ea931a4
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4EA931A432BB9555483B41B3BC8E78E4"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "cmd.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "C:\\Windows\\" nocase
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        $s9 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4F79981D1F7091BE6AAD_4f79981d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4F79981D1F7091BE6AADCC4595EF5F76"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4FD969CEFB161CBBFE26_4fd969ce
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4FD969CEFB161CBBFE26897F097EDA71"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5118F69983A1544CAF4E_5118f699
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5118F69983A1544CAF4E3D244E195304"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5328361825D0B1CCB0B1_53283618
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5328361825D0B1CCB0B157CEFF4E883E"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_545BEE90A5F356B114CA_545bee90
{
    meta:
        description = "Detects suspicious strings in FannyWorm_545BEE90A5F356B114CA3A4823F14990"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_54C7657B4D19C6AFAAF0_54c7657b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_54C7657B4D19C6AFAAF003A332704907"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_54D7826F13C1116B0BE9_54d7826f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_54D7826F13C1116B0BE9077334713F1A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_564950A5F4B3CA0E6ADE_564950a5
{
    meta:
        description = "Detects suspicious strings in FannyWorm_564950A5F4B3CA0E6ADE94C5CA5D8DE1"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5686E5CDB415F7FB65A4_5686e5cd
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5686E5CDB415F7FB65A4A3D971F24E1C"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_56897704C43DBFB60847_56897704
{
    meta:
        description = "Detects suspicious strings in FannyWorm_56897704C43DBFB60847A6DCA00DE2B0"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_56D85656C527242B493D_56d85656
{
    meta:
        description = "Detects suspicious strings in FannyWorm_56D85656C527242B493D9B19CB95370E"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_56FF71E1F28E1F149E0E_56ff71e1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_56FF71E1F28E1F149E0E4CF8CE9811D1"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_57B64A212B4B39827939_57b64a21
{
    meta:
        description = "Detects suspicious strings in FannyWorm_57B64A212B4B3982793916A18FA4F489"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5821380182C7BFAA6646_58213801
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5821380182C7BFAA6646DB4313449917"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_58786E35FA1D61D1BCD6_58786e35
{
    meta:
        description = "Detects suspicious strings in FannyWorm_58786E35FA1D61D1BCD671987D103957"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_58EF8790939FCA73A20C_58ef8790
{
    meta:
        description = "Detects suspicious strings in FannyWorm_58EF8790939FCA73A20C6A04717A2659"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_595B08353458A0749D29_595b0835
{
    meta:
        description = "Detects suspicious strings in FannyWorm_595B08353458A0749D292E0E81C0FC01"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5A5BED7FAE336B93C44B_5a5bed7f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5A5BED7FAE336B93C44B370A955182DA"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5A723D3EF02DB234061C_5a723d3e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5A723D3EF02DB234061C2F61A6E3B6A4"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5A7DACC0C0F34005AB97_5a7dacc0
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5A7DACC0C0F34005AB9710E666128500"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5B0F5F62EF3AE981FE48_5b0f5f62
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5B0F5F62EF3AE981FE48B6C29D7BEAB2"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5BEC4783C551C46B15F7_5bec4783
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5BEC4783C551C46B15F7C5B20F94F4B9"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5DC172E2C96B79EA7D85_5dc172e2
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5DC172E2C96B79EA7D855339F1B2403C"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5E171B3A31279F9FCF21_5e171b3a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5E171B3A31279F9FCF21888AC0034B06"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5F5ABBE2E637D4F0B8AF_5f5abbe2
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5F5ABBE2E637D4F0B8AFE7F2342C2942"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5FF0E69BF258375E7EEF_5ff0e69b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5FF0E69BF258375E7EEFCC5AC3BDCF24"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_600984D541D399B18947_600984d5
{
    meta:
        description = "Detects suspicious strings in FannyWorm_600984D541D399B1894745B917E5380B"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_60D21EE6548DE4673CBD_60d21ee6
{
    meta:
        description = "Detects suspicious strings in FannyWorm_60D21EE6548DE4673CBDDEF2D779ED24"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_63B2F98548174142F92F_63b2f985
{
    meta:
        description = "Detects suspicious strings in FannyWorm_63B2F98548174142F92FDFD995A2C70A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_63ECB7FE79A5B541C357_63ecb7fe
{
    meta:
        description = "Detects suspicious strings in FannyWorm_63ECB7FE79A5B541C35765CAF424A021"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_6436A4FB7A8F37AC934C_6436a4fb
{
    meta:
        description = "Detects suspicious strings in FannyWorm_6436A4FB7A8F37AC934C275D325208E6"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_64A58CF7E810A77A5105_64a58cf7
{
    meta:
        description = "Detects suspicious strings in FannyWorm_64A58CF7E810A77A5105D56B81AE8200"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_66A2A7AC521BE856DEED_66a2a7ac
{
    meta:
        description = "Detects suspicious strings in FannyWorm_66A2A7AC521BE856DEED54FD8072D0E8"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_6814B21455DEB552DF3B_6814b214
{
    meta:
        description = "Detects suspicious strings in FannyWorm_6814B21455DEB552DF3B452EF0551EC1"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_682C987506651FCAE56C_682c9875
{
    meta:
        description = "Detects suspicious strings in FannyWorm_682C987506651FCAE56C32FFA1F70170"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_687F8BEC948425750097_687f8bec
{
    meta:
        description = "Detects suspicious strings in FannyWorm_687F8BEC9484257500976C336E103A08"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_688526EDBEA2D61664EC_688526ed
{
    meta:
        description = "Detects suspicious strings in FannyWorm_688526EDBEA2D61664EC629F6558365C"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_68892E329FA28FE751B9_68892e32
{
    meta:
        description = "Detects suspicious strings in FannyWorm_68892E329FA28FE751B9EB16928EA98D"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_68E6EE88BA44ED0B9DE9_68e6ee88
{
    meta:
        description = "Detects suspicious strings in FannyWorm_68E6EE88BA44ED0B9DE93D6812B5255E"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_6DA22F42139A4A2365E7_6da22f42
{
    meta:
        description = "Detects suspicious strings in FannyWorm_6DA22F42139A4A2365E7A9068D7B908A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_6DE614AD2B4D03F9DFCD_6de614ad
{
    meta:
        description = "Detects suspicious strings in FannyWorm_6DE614AD2B4D03F9DFCDF0251737D33D"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_6E4F77DCDBB034CB4073_6e4f77dc
{
    meta:
        description = "Detects suspicious strings in FannyWorm_6E4F77DCDBB034CB4073D8C46BF23AE3"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_6F073003704CC5B5265A_6f073003
{
    meta:
        description = "Detects suspicious strings in FannyWorm_6F073003704CC5B5265A0A9F8EE851D1"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_70B0214530810773E46A_70b02145
{
    meta:
        description = "Detects suspicious strings in FannyWorm_70B0214530810773E46AFA469A723CE3"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_72312F1E2AE6900F169A_72312f1e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_72312F1E2AE6900F169A2B7A88E14D93"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_72B16929F43533AC4BF9_72b16929
{
    meta:
        description = "Detects suspicious strings in FannyWorm_72B16929F43533AC4BF953D90A52EB37"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_72F244452DF28865B373_72f24445
{
    meta:
        description = "Detects suspicious strings in FannyWorm_72F244452DF28865B37317369C33927D"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_74621A05BAFB868BDA8A_74621a05
{
    meta:
        description = "Detects suspicious strings in FannyWorm_74621A05BAFB868BDA8AEB6562DD36DF"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_74AD35F0F4342F450388_74ad35f0
{
    meta:
        description = "Detects suspicious strings in FannyWorm_74AD35F0F4342F45038860CA0564AB8B"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_75AC44F173AF6ACE7CC0_75ac44f1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_75AC44F173AF6ACE7CC06E8406B03D33"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_769C62FDD6E1D2C5D510_769c62fd
{
    meta:
        description = "Detects suspicious strings in FannyWorm_769C62FDD6E1D2C5D51094E2882886B0"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_7808586DEC24D0456758_7808586d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_7808586DEC24D04567582F9CBD26EAD8"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_782E5C2D319063405414_782e5c2d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_782E5C2D319063405414D4E55D3DCFB3"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_78B1FF3B04FAC35C8904_78b1ff3b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_78B1FF3B04FAC35C890462225C5FBC49"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_7CCCAF9B08301D2C2ACB_7cccaf9b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_7CCCAF9B08301D2C2ACB647EA04CA8E1"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_7E6348F56508E43C9002_7e6348f5
{
    meta:
        description = "Detects suspicious strings in FannyWorm_7E6348F56508E43C900265EE5297B577"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_7FAABCE7D25641764807_7faabce7
{
    meta:
        description = "Detects suspicious strings in FannyWorm_7FAABCE7D2564176480769A9D7B34A2C"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8010AF50404647200A7B_8010af50
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8010AF50404647200A7BB51DE08AB960"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8051E04BAB3A6DB6226C_8051e04b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8051E04BAB3A6DB6226CC4D08890E934"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8568A1CFA314525F49C9_8568a1cf
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8568A1CFA314525F49C98FAFBF85D14B"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_85CEE5AAA59CACAD80BF_85cee5aa
{
    meta:
        description = "Detects suspicious strings in FannyWorm_85CEE5AAA59CACAD80BF9792869845BA"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_86D89BAC8A165FCE9142_86d89bac
{
    meta:
        description = "Detects suspicious strings in FannyWorm_86D89BAC8A165FCE91426BF84EB7B7FC"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "rundll32.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "C:\\Windows\\" nocase
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        $s9 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_872E8E7C381FB805B87B_872e8e7c
{
    meta:
        description = "Detects suspicious strings in FannyWorm_872E8E7C381FB805B87B88F31F77A772"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "rundll32.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "C:\\Windows\\" nocase
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        $s9 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8738E487218905E86BF6_8738e487
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8738E487218905E86BF6AD7988929ECB"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_878A3D4B91875E10F032_878a3d4b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_878A3D4B91875E10F032B58D5DA3DDF1"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_88E4147EFABA886FF16D_88e4147e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_88E4147EFABA886FF16D6F058E8A25A6"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_89C216DF6B2B1A335738_89c216df
{
    meta:
        description = "Detects suspicious strings in FannyWorm_89C216DF6B2B1A335738847A1F1A6CBC"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8A41A5AD3AE353F16FF2_8a41a5ad
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8A41A5AD3AE353F16FF2FD92E8046AC3"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8AD46BB2D0BEF97548EB_8ad46bb2
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8AD46BB2D0BEF97548EBBED2F6EEA2E1"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8B1FE26A399F54CEE444_8b1fe26a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8B1FE26A399F54CEE44493859C6E82AC"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8BAADB392A85A187360F_8baadb39
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8BAADB392A85A187360FCA5A4E56E6CF"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8BB0C5181D8AB57B879D_8bb0c518
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8BB0C5181D8AB57B879DEA3F987FBEDF"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "rundll32.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "C:\\Windows\\" nocase
        $s7 = "createprocess" nocase
        $s8 = "regopenkey" nocase
        $s9 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8C7EF91A96E75C3D05EA_8c7ef91a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8C7EF91A96E75C3D05EA5E54A0E9356C"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8E555220BD7F8C183ABF_8e555220
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8E555220BD7F8C183ABF58071851E2B4"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8FE19689CC16FEA06BDF_8fe19689
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8FE19689CC16FEA06BDFC9C39C515FA3"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_90C8A317CBA47D7E3525_90c8a317
{
    meta:
        description = "Detects suspicious strings in FannyWorm_90C8A317CBA47D7E3525B69862DDEF58"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_9120C2A26E1F4DC362CA_9120c2a2
{
    meta:
        description = "Detects suspicious strings in FannyWorm_9120C2A26E1F4DC362CA338B8E014B20"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_91B1F4A4FA5C26473AB6_91b1f4a4
{
    meta:
        description = "Detects suspicious strings in FannyWorm_91B1F4A4FA5C26473AB678408EDCB913"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_939706730193E6BCFEB9_93970673
{
    meta:
        description = "Detects suspicious strings in FannyWorm_939706730193E6BCFEB991DE4387BD3F"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_93B22ECC56A91F251D5E_93b22ecc
{
    meta:
        description = "Detects suspicious strings in FannyWorm_93B22ECC56A91F251D5E023A5C20B3A4"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_94271AE895E359B60625_94271ae8
{
    meta:
        description = "Detects suspicious strings in FannyWorm_94271AE895E359B606252395DF952F5F"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_948603BD138DD8487FAA_948603bd
{
    meta:
        description = "Detects suspicious strings in FannyWorm_948603BD138DD8487FAAB3C0DA5EB573"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_9563FD4AB7D619D565B4_9563fd4a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_9563FD4AB7D619D565B47CD16104DC66"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_963A24B864524DFA64BA_963a24b8
{
    meta:
        description = "Detects suspicious strings in FannyWorm_963A24B864524DFA64BA4310537CE0E1"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_97B0A0EF6CB6B1EB8E32_97b0a0ef
{
    meta:
        description = "Detects suspicious strings in FannyWorm_97B0A0EF6CB6B1EB8E325EB20BA0A8E3"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_98E6B678B40329DAC41D_98e6b678
{
    meta:
        description = "Detects suspicious strings in FannyWorm_98E6B678B40329DAC41D8F42652C17A2"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_99E8D4F1D2069EF84D97_99e8d4f1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_99E8D4F1D2069EF84D9725AA206D6BA7"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_9A7165D3C7B84FE0E228_9a7165d3
{
    meta:
        description = "Detects suspicious strings in FannyWorm_9A7165D3C7B84FE0E22881F653EADF7F"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_9FB98B0D1A5B38B6A89C_9fb98b0d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_9FB98B0D1A5B38B6A89CB478943C285B"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_9FC2AA4D538B34651705_9fc2aa4d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_9FC2AA4D538B34651705B904C7823C6F"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A00101CFC1EDD423CB34_a00101cf
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A00101CFC1EDD423CB34F758F8D0C62E"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A2C52AD8F66A14F7979C_a2c52ad8
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A2C52AD8F66A14F7979C6BAFC4978142"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A397A581C20BF93EB5C2_a397a581
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A397A581C20BF93EB5C22CAD5A2AFCDD"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A43F67AF43730552864F_a43f67af
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A43F67AF43730552864F84E2B051DEB4"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A498FCAC85DC2E972817_a498fcac
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A498FCAC85DC2E97281781A08B1C1041"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A4E2ED5FF620A786C2F2_a4e2ed5f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A4E2ED5FF620A786C2F2E15A5F8A2D2F"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A5E169E47BA828DD6841_a5e169e4
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A5E169E47BA828DD68417875AA8C0C94"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A5F2C5CA6B51A6BF48D7_a5f2c5ca
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A5F2C5CA6B51A6BF48D795FB5AE63203"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A5F389947F03902A5ABD_a5f38994
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A5F389947F03902A5ABD742B61637363"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A62BE32440D0602C76A7_a62be324
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A62BE32440D0602C76A72F96235567AC"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A67E937C6C33B0A9CD83_a67e937c
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A67E937C6C33B0A9CD83946CCFA666CA"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A68A56B4B3412E07436C_a68a56b4
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A68A56B4B3412E07436C7D195891E8BE"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A76DC2F716AA5ED5CBBD_a76dc2f7
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A76DC2F716AA5ED5CBBD23BBF1DE3005"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A7F4EEE46463BE306159_a7f4eee4
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A7F4EEE46463BE30615903E395A323C5"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A801668543B30FCC3A25_a8016685
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A801668543B30FCC3A254DE8183B2BA5"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A82D41CFC3EE376D9252_a82d41cf
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A82D41CFC3EE376D9252DD4912E35894"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A84FD0164200AD1AD0E3_a84fd016
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A84FD0164200AD1AD0E34EEE9C663949"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A8A973B3861C8D2F1803_a8a973b3
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A8A973B3861C8D2F18039432B9F38335"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A95B2EC5B67F8FDDA547_a95b2ec5
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A95B2EC5B67F8FDDA547A4A5A4B85543"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A96DC17D52986BB9BA20_a96dc17d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A96DC17D52986BB9BA201550D5D41186"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AAA06C8458F01BEDCAC5_aaa06c84
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AAA06C8458F01BEDCAC5EC638C5C8B24"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AB75C7BF5AD32AF82D33_ab75c7bf
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AB75C7BF5AD32AF82D331B5EE76F2ECA"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_ABFF989FBA8B34539CDD_abff989f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_ABFF989FBA8B34539CDDBDFF0A79EE8D"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AC50C31D680C763CCE26_ac50c31d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AC50C31D680C763CCE26B4D979A11A5C"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AC7A5C23B475E8BF54A1_ac7a5c23
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AC7A5C23B475E8BF54A1E60AE1A85F67"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AE58E6C03D7339DA70D0_ae58e6c0
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AE58E6C03D7339DA70D061399F6DEFF3"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AF426F4980CE7E2F7717_af426f49
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AF426F4980CE7E2F771742BEE1CC43DF"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AF8F1BFCCB6530E41B2F_af8f1bfc
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AF8F1BFCCB6530E41B2F19FF0DE8BAB5"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AFF10DD15B2D39C18AE9_aff10dd1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AFF10DD15B2D39C18AE9EE96511A9D83"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B11DBC0C4E98B4CA224C_b11dbc0c
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B11DBC0C4E98B4CA224C18344CC5191D"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B1C4ED725CB3443D16BE_b1c4ed72
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B1C4ED725CB3443D16BE55EE5F00DCBD"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B1CCEB79F74D48C94CA7_b1cceb79
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B1CCEB79F74D48C94CA7E680A609BC65"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B322FB54B5E53F4EA93E_b322fb54
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B322FB54B5E53F4EA93E04E5A2ABCCBC"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B38A91B1A5D23D418C5C_b38a91b1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B38A91B1A5D23D418C5C6D6A0B066C30"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B4B05BB97521494B342D_b4b05bb9
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B4B05BB97521494B342DA8524A6181ED"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B5738307BAB3FBF4CF2B_b5738307
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B5738307BAB3FBF4CF2BDD652B0AC88A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B59F5C408FBA0E2CF503_b59f5c40
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B59F5C408FBA0E2CF503E0942AC46C56"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B747BB2EDC15A07CE61B_b747bb2e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B747BB2EDC15A07CE61BCE4FD1A33EAD"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B78E9C9A49AA507CB1F9_b78e9c9a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B78E9C9A49AA507CB1F905FDD455CA35"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BA38163FC6E75BB6ACD7_ba38163f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BA38163FC6E75BB6ACD73BC7CF89089B"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BA43976BB23531A9D4DC_ba43976b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BA43976BB23531A9D4DC5F0AFD07327A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BAC9A35D7CDF8C217B51_bac9a35d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BAC9A35D7CDF8C217B51C189A7B7B2FD"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BB5AA3E042C802C294FA_bb5aa3e0
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BB5AA3E042C802C294FA233C4DB41393"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BCC5D198A60878C03A11_bcc5d198
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BCC5D198A60878C03A114E45ACDFE417"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BD7A693767DE2EAE08B4_bd7a6937
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BD7A693767DE2EAE08B4C63AAA84DB43"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BD9E6F35DC7FE987EEFA_bd9e6f35
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BD9E6F35DC7FE987EEFA048ADC94D346"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BDC3474D7A5566916DC0_bdc3474d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BDC3474D7A5566916DC0A2B3075D10BE"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BED58D25C152BD5B4A9C_bed58d25
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BED58D25C152BD5B4A9C022B5B863C72"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BFDE4B5CD6CC89C6996C_bfde4b5c
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BFDE4B5CD6CC89C6996C5E30C36F0273"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_C05255625BB00EB12EAF_c0525562
{
    meta:
        description = "Detects suspicious strings in FannyWorm_C05255625BB00EB12EAF95CB41FCC7F5"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_C1F171A7689958EB5000_c1f171a7
{
    meta:
        description = "Detects suspicious strings in FannyWorm_C1F171A7689958EB500079AB0185915F"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_C303AFE1648D3B70591F_c303afe1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_C303AFE1648D3B70591FEEFFE78125ED"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_C3DA3234A3764CA81D69_c3da3234
{
    meta:
        description = "Detects suspicious strings in FannyWorm_C3DA3234A3764CA81D694C3935BF55CF"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Fanny_0A209AC0DE4AC033F31D6BA9_0a209ac0
{
    meta:
        description = "Detects suspicious strings in Fanny_0A209AC0DE4AC033F31D6BA9191A8F7A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "C:\\Windows\\" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Install_LiveManagerPlayer_exe__845b5484
{
    meta:
        description = "Detects suspicious strings in Install_LiveManagerPlayer.exe.vir"
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


rule SuspiciousStrings_Locky_b06d9dd1
{
    meta:
        description = "Detects suspicious strings in Locky"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "createprocess" nocase
        $s5 = "regopenkey" nocase
        $s6 = "inject" nocase
        $s7 = "encrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_MacSecurity_88cee1ab
{
    meta:
        description = "Detects suspicious strings in MacSecurity"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "malware" nocase
        $s2 = "virus" nocase
        $s3 = "backdoor" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Matsnu_MBRwipingRansomware_1B2_1b2d2a4b
{
    meta:
        description = "Detects suspicious strings in Matsnu-MBRwipingRansomware_1B2D2A4B97C7C2727D571BBF9376F54F_Inkasso Rechnung vom 27.05.2013 .com_"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "cmd.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_MiniConfigBuilder_exe_65e15129
{
    meta:
        description = "Detects suspicious strings in MiniConfigBuilder.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Mono_Cecil_dll_851ec9d8
{
    meta:
        description = "Detects suspicious strings in Mono.Cecil.dll"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_NAudio_dll_422193aa
{
    meta:
        description = "Detects suspicious strings in NAudio.dll"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_1stVersion_3B7D88A069631_3b7d88a0
{
    meta:
        description = "Detects suspicious strings in Potao_1stVersion_3B7D88A069631111D5585B1B10CCCC86"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_1stVersion_502F35002B1A9_502f3500
{
    meta:
        description = "Detects suspicious strings in Potao_1stVersion_502F35002B1A95F1AE135BAFF6CFF836"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_1stVersion_A446CED5DB1DE_a446ced5
{
    meta:
        description = "Detects suspicious strings in Potao_1stVersion_A446CED5DB1DE877CF78F77741E2A804"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_1stVersion_AC854A3C91D52_ac854a3c
{
    meta:
        description = "Detects suspicious strings in Potao_1stVersion_AC854A3C91D52BFC09605506E76975AE"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_DebugVersion_5199FCD0319_5199fcd0
{
    meta:
        description = "Detects suspicious strings in Potao_DebugVersion_5199FCD031987834ED3121FB316F4970"
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


rule SuspiciousStrings_Potao_DebugVersion_7263A328F0D_7263a328
{
    meta:
        description = "Detects suspicious strings in Potao_DebugVersion_7263A328F0D47C76B4E103546B648484"
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


rule SuspiciousStrings_Potao_DebugVersion_BDC9255DF53_bdc9255d
{
    meta:
        description = "Detects suspicious strings in Potao_DebugVersion_BDC9255DF5385F534FEA83B497C371C8"
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


rule SuspiciousStrings_Potao_Droppersfrompostalsites__07e99b2f
{
    meta:
        description = "Detects suspicious strings in Potao_Droppersfrompostalsites_07E99B2F572B84AF5C4504C23F1653BB"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Droppersfrompostalsites__1927a80c
{
    meta:
        description = "Detects suspicious strings in Potao_Droppersfrompostalsites_1927A80CD45F0D27B1AE034C11DDEDB0"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Droppersfrompostalsites__579ad4a5
{
    meta:
        description = "Detects suspicious strings in Potao_Droppersfrompostalsites_579AD4A596602A10B7CF4659B6B6909D"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Droppersfrompostalsites__65f49458
{
    meta:
        description = "Detects suspicious strings in Potao_Droppersfrompostalsites_65F494580C95E10541D1F377C0A7BD49"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Droppersfrompostalsites__a4b0615c
{
    meta:
        description = "Detects suspicious strings in Potao_Droppersfrompostalsites_A4B0615CB639607E6905437DD900C059"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Droppersfrompostalsites__e64eb8b5
{
    meta:
        description = "Detects suspicious strings in Potao_Droppersfrompostalsites_E64EB8B571F655B744C9154D8032CAEF"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Dropperswdecoy_5A24A7370_5a24a737
{
    meta:
        description = "Detects suspicious strings in Potao_Dropperswdecoy_5A24A7370F35DBDBB81ADF52E769A442"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Dropperswdecoy_73E7EE831_73e7ee83
{
    meta:
        description = "Detects suspicious strings in Potao_Dropperswdecoy_73E7EE83133A175B815059F1AF79AB1B"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "createprocess" nocase
        $s5 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Dropperswdecoy_B4D909077_b4d90907
{
    meta:
        description = "Detects suspicious strings in Potao_Dropperswdecoy_B4D909077AA25F31386722E716A5305C"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "createprocess" nocase
        $s5 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Dropperswdecoy_D755E52BA_d755e52b
{
    meta:
        description = "Detects suspicious strings in Potao_Dropperswdecoy_D755E52BA5658A639C778C22D1A906A3"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "createprocess" nocase
        $s5 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Dropperswdecoy_EEBBCB1ED_eebbcb1e
{
    meta:
        description = "Detects suspicious strings in Potao_Dropperswdecoy_EEBBCB1ED5F5606AEC296168DEE39166"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Dropperswdecoy_FC4B28508_fc4b2850
{
    meta:
        description = "Detects suspicious strings in Potao_Dropperswdecoy_FC4B285088413127B6D827656B9D0481"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_02D438DF77_02d438df
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_02D438DF779AFFDDAF02CA995C60CECB"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_043F99A875_043f99a8
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_043F99A875424CA0023A21739DBA51EF"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_11B4E7EA6B_11b4e7ea
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_11B4E7EA6BAE19A29343AE3FF3FB00CA"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_1AB8D45656_1ab8d456
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_1AB8D45656E245ACA4E59AA0519F6BA0"
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


rule SuspiciousStrings_Potao_OtherDroppers_27D74523B1_27d74523
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_27D74523B182AE630C4E5236897E11F3"
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


rule SuspiciousStrings_Potao_OtherDroppers_360DF4C2F2_360df4c2
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_360DF4C2F2B99052C07E08EDBE15AB2C"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_38E708FEA8_38e708fe
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_38E708FEA8016520CB25D3CB933F2244"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_6BA88E8E74_6ba88e8e
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_6BA88E8E74B12C914483C026AE92EB42"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_89A3EA3967_89a3ea39
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_89A3EA3967745E04199EBF222494452E"
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


rule SuspiciousStrings_Potao_USBSpreaders_057028E46EA_057028e4
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_057028E46EA797834DA401E4DB7C860A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "AppData" nocase
        $s5 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_1234BF4F0F5_1234bf4f
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_1234BF4F0F5DEBC800D85C1BD2255671"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "AppData" nocase
        $s5 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_2BD0D2B5EE4_2bd0d2b5
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_2BD0D2B5EE4E93717EA71445B102E38E"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_35724E234F6_35724e23
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_35724E234F6258E601257FB219DB9079"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "advapi32.dll" nocase
        $s3 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_3813B848162_3813b848
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_3813B848162261CC5982DD64C741B450"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "AppData" nocase
        $s6 = "createprocess" nocase
        $s7 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_514423670DE_51442367
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_514423670DE210F13092D6CB8916748E"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_542B00F903F_542b00f9
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_542B00F903F945AD3A9291CB0AF73446"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_76DDA7CA153_76dda7ca
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_76DDA7CA15323FD658054E0550149B7B"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_A2BB01B7644_a2bb01b7
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_A2BB01B764491DD61FA3A7BA5AFC709C"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "AppData" nocase
        $s6 = "createprocess" nocase
        $s7 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_A427FF7ABB1_a427ff7a
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_A427FF7ABB17AF6CF5FB70C49E9BF4E1"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_A59053CC3F6_a59053cc
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_A59053CC3F66E72540634EB7895824AC"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_ABB9F4FAB64_abb9f4fa
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_ABB9F4FAB64DD7A03574ABDD1076B5EA"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_AE552FC43F1_ae552fc4
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_AE552FC43F1BA8684655D8BF8C6AF869"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "createprocess" nocase
        $s6 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_CA1A3618088_ca1a3618
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_CA1A3618088F91B8FB2A30C9A9AA4ACA"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "AppData" nocase
        $s5 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_CDC60EB93B5_cdc60eb9
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_CDC60EB93B594FB5E7E5895E2B441240"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "AppData" nocase
        $s6 = "createprocess" nocase
        $s7 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_E685EA8B37F_e685ea8b
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_E685EA8B37F707F3706D7281B8F6816A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Q300972I_EXE_f1a8d75b
{
    meta:
        description = "Detects suspicious strings in Q300972I.EXE"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "Temp\\" nocase
        $s5 = "createprocess" nocase
        $s6 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Q30097_1_EXE_b4474bb5
{
    meta:
        description = "Detects suspicious strings in Q30097~1.EXE"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "Temp\\" nocase
        $s5 = "createprocess" nocase
        $s6 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_RBShell_rbx_0_131_dylib_5d3743ad
{
    meta:
        description = "Detects suspicious strings in RBShell.rbx_0.131.dylib"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_SCHDPL32_exe_4ae9a4a8
{
    meta:
        description = "Detects suspicious strings in SCHDPL32.exe"
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


rule SuspiciousStrings_Torpig_miniloader_011C1CA6030E_011c1ca6
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_011C1CA6030EE091CE7C20CD3AAECFA0"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Torpig_miniloader_0F82964CF390_0f82964c
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_0F82964CF39056402EE2DE9193635B34"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Torpig_miniloader_2DACC4556FAD_2dacc455
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_2DACC4556FAD30027A384875C8D9D900"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Torpig_miniloader_4A3543E6771B_4a3543e6
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_4A3543E6771BC78D32AE46820AED1391"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Torpig_miniloader_809910F29AA6_809910f2
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_809910F29AA63913EFA76D00FA8C7C0B"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Torpig_miniloader_83419EEA7121_83419eea
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_83419EEA712182C1054615E4EC7B8CBE"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Torpig_miniloader_87851480DEB1_87851480
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_87851480DEB151D3A0AA9A425FD74E61"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Torpig_miniloader_C3366B6006AC_c3366b60
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_C3366B6006ACC1F8DF875EAA114796F0"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_TripleFantasy_9180D5AFFE1E5DF0_9180d5af
{
    meta:
        description = "Detects suspicious strings in TripleFantasy_9180D5AFFE1E5DF0717D7385E7F54386"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "advapi32.dll" nocase
        $s3 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_UpdateCheck_exe_610be271
{
    meta:
        description = "Detects suspicious strings in UpdateCheck.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_W32_Swen_MM_exe_9d4f6244
{
    meta:
        description = "Detects suspicious strings in W32_Swen@MM.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".exe" nocase
        $s2 = ".dll" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "virus" nocase
        $s7 = "trojan" nocase
        $s8 = "createprocess" nocase
        $s9 = "regopenkey" nocase
        $s10 = "shell" nocase
        $s11 = "hacker" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_WORM_VOBFUS_SMA3_7b19b2b8
{
    meta:
        description = "Detects suspicious strings in WORM_VOBFUS.SMA3"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "C:\\Windows\\" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_WORM_VOBFUS_SMIS_634aa845
{
    meta:
        description = "Detects suspicious strings in WORM_VOBFUS.SMIS"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "C:\\Windows\\" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_WORM_VOBFUS_SMM2_4e15d812
{
    meta:
        description = "Detects suspicious strings in WORM_VOBFUS.SMM2"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "C:\\Windows\\" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Win32_GravityRAT_exe_ec629f64
{
    meta:
        description = "Detects suspicious strings in Win32.GravityRAT.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "encrypt" nocase
        $s1 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Win32_MyLobot_bin_c5307c17
{
    meta:
        description = "Detects suspicious strings in Win32.MyLobot.bin"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Win32_Sofacy_A_ed7f6260
{
    meta:
        description = "Detects suspicious strings in Win32.Sofacy.A"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Win32_Triton_1904cad4
{
    meta:
        description = "Detects suspicious strings in Win32.Triton"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "createprocess" nocase
        $s5 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Win32_Unknown_SpectreMeltdown_b6b9c196
{
    meta:
        description = "Detects suspicious strings in Win32.Unknown_SpectreMeltdown"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "urlmoniker" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Win32_Unnamed_SpecMelt_8f188da2
{
    meta:
        description = "Detects suspicious strings in Win32.Unnamed_SpecMelt"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Win32_WannaPeace_exe_eefa6f98
{
    meta:
        description = "Detects suspicious strings in Win32.WannaPeace.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "shell" nocase
        $s3 = "encrypt" nocase
        $s4 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Win32_Wannacry_exe_30fe2f9a
{
    meta:
        description = "Detects suspicious strings in Win32.Wannacry.exe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Win32_XAgent_bin_2f6d1bed
{
    meta:
        description = "Detects suspicious strings in Win32.XAgent.bin"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a0d82c3730bc41e267711480c80098_b29ca4f2
{
    meta:
        description = "Detects suspicious strings in a0d82c3730bc41e267711480c8009883d1412b68977ab175421eabc34e4ef355"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a38df3ec8b9fe52a32860cf5756d2f_a5bd39bf
{
    meta:
        description = "Detects suspicious strings in a38df3ec8b9fe52a32860cf5756d2fe345badafd7e74466cd349eb32ba5cc339"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "C:\\Windows\\" nocase
        $s4 = "AppData" nocase
        $s5 = "Temp\\" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a6ff8dfe654da70390cd71626cdca8_0df40b22
{
    meta:
        description = "Detects suspicious strings in a6ff8dfe654da70390cd71626cdca8a6f6a0d7980cd7d82269373737b04fd206"
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


rule SuspiciousStrings_a7493fac96345a989b1a0377244407_b269894f
{
    meta:
        description = "Detects suspicious strings in a7493fac96345a989b1a03772444075754a2ef11daa22a7600466adc1f69a669"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a7c387b4929f51e38706d8b0f8641e_67ef79ee
{
    meta:
        description = "Detects suspicious strings in a7c387b4929f51e38706d8b0f8641e032253b07bc2869a450dfa3df5663d7392"
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


rule SuspiciousStrings_a7e3ad8ea7edf1ca10b0e5b0d97667_18704459
{
    meta:
        description = "Detects suspicious strings in a7e3ad8ea7edf1ca10b0e5b0d976675c3016e5933219f97e94900dea0d470abe"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ad8965e531424cb34120bf0c1b4b98_2d540860
{
    meta:
        description = "Detects suspicious strings in ad8965e531424cb34120bf0c1b4b98d4ab769bed534d9a36583364e9572332fa"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "downloadfile" nocase
        $s5 = "regopenkey" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ae66e009e16f0fad3b70ad20801f48_03b76a51
{
    meta:
        description = "Detects suspicious strings in ae66e009e16f0fad3b70ad20801f48f2edb904fa5341a89e126a26fd3fc80f75"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "cmd.exe" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "trojan" nocase
        $s7 = "downloadfile" nocase
        $s8 = "shell" nocase
        $s9 = "encrypt" nocase
        $s10 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_afa8d185de2f357082ed4042fc057a_ec9ae4c3
{
    meta:
        description = "Detects suspicious strings in afa8d185de2f357082ed4042fc057a6d7300f603d3bfdbe7e6c351868e45e477"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b000a0095a8fda38227103f253b6d7_674216ba
{
    meta:
        description = "Detects suspicious strings in b000a0095a8fda38227103f253b6d79134b862a83df50315d7d9c5b537fd994b"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b06ab1f3abf8262f32c3deab9d344d_a4d3b789
{
    meta:
        description = "Detects suspicious strings in b06ab1f3abf8262f32c3deab9d344d241e4203235043fe996cb499ed2fdf17c4"
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


rule SuspiciousStrings_b12c7d57507286bbbe36d7acf9b34c_ffb0b9b5
{
    meta:
        description = "Detects suspicious strings in b12c7d57507286bbbe36d7acf9b34c22c96606ffd904e3c23008399a4a50c047"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b153e10c95bb8bfa6dbf5835067c5b_c7af7185
{
    meta:
        description = "Detects suspicious strings in b153e10c95bb8bfa6dbf5835067c5b45840f057a38ef9b8871b6dc40edcf601f"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b154ac015c0d1d6250032f63c749f9_b154ac01
{
    meta:
        description = "Detects suspicious strings in b154ac015c0d1d6250032f63c749f9cf"
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


rule SuspiciousStrings_b275c8978d18832bd3da9975d0f43c_c19e91a9
{
    meta:
        description = "Detects suspicious strings in b275c8978d18832bd3da9975d0f43cbc90e09a99718f4efaf1be7b43db46cf95"
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


rule SuspiciousStrings_b2ca4093b2e0271cb7a3230118843f_344d431a
{
    meta:
        description = "Detects suspicious strings in b2ca4093b2e0271cb7a3230118843fccc094e0160a0968994ed9f10c8702d867"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "downloadfile" nocase
        $s5 = "regopenkey" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b81b10bdf4f29347979ea8a1715cbf_ad44a7c5
{
    meta:
        description = "Detects suspicious strings in b81b10bdf4f29347979ea8a1715cbfc560e3452ba9fffcc33cd19a3dc47083a4"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "user32.dll" nocase
        $s3 = "kernel32.dll" nocase
        $s4 = "advapi32.dll" nocase
        $s5 = "virus" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b96bd6bbf0e3f4f98b606a2ab5db4a_b96bd6bb
{
    meta:
        description = "Detects suspicious strings in b96bd6bbf0e3f4f98b606a2ab5db4a69"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bac8489de573f614d988097e9eae53_cab76ac0
{
    meta:
        description = "Detects suspicious strings in bac8489de573f614d988097e9eae53ffc2eb4e7dcb0e68c349f549a26d2130a8"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        $s2 = "createprocess" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bb8e52face5b076cc890bbfaaf4bb7_bb8e52fa
{
    meta:
        description = "Detects suspicious strings in bb8e52face5b076cc890bbfaaf4bb73e"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bc4ae56434b45818f57724f4cd1935_92e72429
{
    meta:
        description = "Detects suspicious strings in bc4ae56434b45818f57724f4cd19354a13e5964fd097d1933a30e2e31c9bdfa5.bin"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".exe" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bc6c2fda18f8ee36930b469f6500e2_e57f8364
{
    meta:
        description = "Detects suspicious strings in bc6c2fda18f8ee36930b469f6500e28096eb6795e5fd17c44273c67bc9fa6a6d"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bea95bebec95e0893a845f62e832d7_bea95beb
{
    meta:
        description = "Detects suspicious strings in bea95bebec95e0893a845f62e832d7cf.exe.ViR"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".exe" nocase
        $s2 = ".dll" nocase
        $s3 = "user32.dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "advapi32.dll" nocase
        $s6 = "createprocess" nocase
        $s7 = "regopenkey" nocase
        $s8 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bed0bec3d123e7611dc3d722813eeb_740c47c6
{
    meta:
        description = "Detects suspicious strings in bed0bec3d123e7611dc3d722813eeb197a2b8048396cef4414f29f24af3a29c4"
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


rule SuspiciousStrings_bfc63b30624332f4fc2e510f95b69d_981234d9
{
    meta:
        description = "Detects suspicious strings in bfc63b30624332f4fc2e510f95b69d18dd0241eb0d2fcd33ed2e81b7275ab488"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c0cf8e008fbfa0cb2c61d968057b4a_1c024e59
{
    meta:
        description = "Detects suspicious strings in c0cf8e008fbfa0cb2c61d968057b4a077d62f64d7320769982d28107db370513"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c14f6ac5bcd8645eb80a612a6bf6d5_14322a51
{
    meta:
        description = "Detects suspicious strings in c14f6ac5bcd8645eb80a612a6bf6d58c31b0e28e50be871f278c341ed1fa8c7c"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = "cmd.exe" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c16410c49dc40a371be22773f420b7_10e16e36
{
    meta:
        description = "Detects suspicious strings in c16410c49dc40a371be22773f420b7dd3cfd4d8205cf39909ad9a6f26f55718e"
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


rule SuspiciousStrings_c2bb47ac533d1413c829a1453b2b85_4076f4bf
{
    meta:
        description = "Detects suspicious strings in c2bb47ac533d1413c829a1453b2b854b95aabebf1b26b446bd1ad0838f1e09de"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c34e5d36bd3a9a6fca92e900ab015a_e815078b
{
    meta:
        description = "Detects suspicious strings in c34e5d36bd3a9a6fca92e900ab015aa50bb20d2cd6c0b6e03d070efe09ee689a"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c460fc0d4fdaf5c68623e18de106f1_d6d95626
{
    meta:
        description = "Detects suspicious strings in c460fc0d4fdaf5c68623e18de106f1c3601d7bd6ba80ddad86c10fd6ea123850"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "https://" nocase
        $s1 = ".exe" nocase
        $s2 = ".dll" nocase
        $s3 = "cmd.exe" nocase
        $s4 = "user32.dll" nocase
        $s5 = "kernel32.dll" nocase
        $s6 = "advapi32.dll" nocase
        $s7 = "ProgramData" nocase
        $s8 = "AppData" nocase
        $s9 = "downloadfile" nocase
        $s10 = "shell" nocase
        $s11 = "encrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c999bf5da5ea3960408d3cba154f96_35c29de9
{
    meta:
        description = "Detects suspicious strings in c999bf5da5ea3960408d3cba154f965d3436b497ac9d4959b412bfcd956c8491"
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


rule SuspiciousStrings_c9d5dc956841e000bfd8762e2f0b48_f01a9a2d
{
    meta:
        description = "Detects suspicious strings in c9d5dc956841e000bfd8762e2f0b48b66c79b79500e894b4efa7fb9ba17e4e9e"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ca467e332368cbae652245faa4978a_ca467e33
{
    meta:
        description = "Detects suspicious strings in ca467e332368cbae652245faa4978aa4"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "AppData" nocase
        $s5 = "regopenkey" nocase
        $s6 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ccd4a648cc2c4a5bbcd148f9c182f4_2a3ec4ae
{
    meta:
        description = "Detects suspicious strings in ccd4a648cc2c4a5bbcd148f9c182f4c9595440a41dd3ea289a11609063c86a6d"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        $s1 = "user32.dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "advapi32.dll" nocase
        $s4 = "regopenkey" nocase
        $s5 = "shell" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_cf4bf26b2d6f1c6055534bbe9decb5_675593b6
{
    meta:
        description = "Detects suspicious strings in cf4bf26b2d6f1c6055534bbe9decb579ef0180e0f8c467c1a26e2ead7567058a"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = ".exe" nocase
        $s2 = ".dll" nocase
        $s3 = "cmd.exe" nocase
        $s4 = "user32.dll" nocase
        $s5 = "kernel32.dll" nocase
        $s6 = "C:\\Windows\\" nocase
        $s7 = "backdoor" nocase
        $s8 = "downloadfile" nocase
        $s9 = "createprocess" nocase
        $s10 = "shell" nocase
        $s11 = "inject" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_cf65cc6e4b2b0c3f602b16398c8c30_a8e3b108
{
    meta:
        description = "Detects suspicious strings in cf65cc6e4b2b0c3f602b16398c8c30c277b8cfaed689fe7cb61b92560d4e5b1b"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = "http://" nocase
        $s1 = "https://" nocase
        $s2 = ".exe" nocase
        $s3 = ".dll" nocase
        $s4 = "kernel32.dll" nocase
        $s5 = "backdoor" nocase
        $s6 = "shell" nocase
        $s7 = "inject" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_cfca38c408c95e45cdf797723dc5cd_934b91c6
{
    meta:
        description = "Detects suspicious strings in cfca38c408c95e45cdf797723dc5cdb0d6dadb1b8338a5fda6808ce9a04e6486"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "encrypt" nocase
        $s3 = "decrypt" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_cff49c25b053f775db8980a431a958_bb49e068
{
    meta:
        description = "Detects suspicious strings in cff49c25b053f775db8980a431a958020bdf969ea08872de4cef5a5f344f534c"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".exe" nocase
        $s1 = ".dll" nocase
        $s2 = "kernel32.dll" nocase
        $s3 = "C:\\Windows\\" nocase
        $s4 = "AppData" nocase
        $s5 = "Temp\\" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ch_dll_1cb8fa64
{
    meta:
        description = "Detects suspicious strings in ch.dll"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
                $s0 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_cryptowall_bin_47363b94
{
    meta:
        description = "Detects suspicious strings in cryptowall.bin"
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

