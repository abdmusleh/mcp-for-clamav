
rule Generic_Suspicious_Strings_fancybear_germanparliament_1f7c586bcd
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "FancyBear.GermanParliament"
        original_filepath = "FancyBear.GermanParliament"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_bdef2ddcd8d4d66a42c9cbafd5cf7d86c4c0e3ed8c45cc734742c5da2fb573f7_a0eb0c4abc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "bdef2ddcd8d4d66a42c9cbafd5cf7d86c4c0e3ed8c45cc734742c5da2fb573f7"
        original_filepath = "bdef2ddcd8d4d66a42c9cbafd5cf7d86c4c0e3ed8c45cc734742c5da2fb573f7"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_efd470cfa90b918e5d558e5c8c3821343af06eedfd484dfeb20c4605f9bdc30e_bin_6f4abc3cab
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "efd470cfa90b918e5d558e5c8c3821343af06eedfd484dfeb20c4605f9bdc30e.bin"
        original_filepath = "efd470cfa90b918e5d558e5c8c3821343af06eedfd484dfeb20c4605f9bdc30e.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_cerber_exe_50929857b6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "cerber.exe"
        original_filepath = "cerber.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_29d6161522c7f7f21b35401907c702bddb05ed47_bin_ba944fe4f2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "29D6161522C7F7F21B35401907C702BDDB05ED47.bin"
        original_filepath = "29D6161522C7F7F21B35401907C702BDDB05ED47.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_sample_exe_4d3d390f8c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "sample.exe"
        original_filepath = "sample.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_75b30164a31d305f47f2c3c2121432e6d7b316cfb3deb6b39f78180168bc9472_bb7681179a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, ftp://, .exe"
        filename = "75b30164a31d305f47f2c3c2121432e6d7b316cfb3deb6b39f78180168bc9472"
        original_filepath = "75b30164a31d305f47f2c3c2121432e6d7b316cfb3deb6b39f78180168bc9472"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "ftp://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_f60b29cfb7eab3aeb391f46e94d4d8efadde5498583a2f5c71bd8212d8ae92da_cd2a320b5a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://"
        filename = "f60b29cfb7eab3aeb391f46e94d4d8efadde5498583a2f5c71bd8212d8ae92da"
        original_filepath = "f60b29cfb7eab3aeb391f46e94d4d8efadde5498583a2f5c71bd8212d8ae92da"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_67e4f5301851646b10a95f65a0b3bacb_04c9d000a4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "67E4F5301851646B10A95F65A0B3BACB"
        original_filepath = "67E4F5301851646B10A95F65A0B3BACB"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_2094d105ec70aa98866a83b38a22614cff906b2cf0a08970ed59887383ee7b70_5b8a8b7c10
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "2094d105ec70aa98866a83b38a22614cff906b2cf0a08970ed59887383ee7b70"
        original_filepath = "2094d105ec70aa98866a83b38a22614cff906b2cf0a08970ed59887383ee7b70"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_e784e95fb5b0188f0c7c82add9a3c89c5bc379eaf356a4d3876d9493a986e343_a2d3d81b21
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, ftp://, .exe"
        filename = "e784e95fb5b0188f0c7c82add9a3c89c5bc379eaf356a4d3876d9493a986e343"
        original_filepath = "e784e95fb5b0188f0c7c82add9a3c89c5bc379eaf356a4d3876d9493a986e343"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "ftp://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_worm_vobfus_smis_72f17cd417
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "WORM_VOBFUS.SMIS"
        original_filepath = "WORM_VOBFUS.SMIS"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_d2642d3731508b52efa34adf57701f18e2f8b70addf31e33e445e75b9a909822_dfe95a41d9
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "d2642d3731508b52efa34adf57701f18e2f8b70addf31e33e445e75b9a909822"
        original_filepath = "d2642d3731508b52efa34adf57701f18e2f8b70addf31e33e445e75b9a909822"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_2a1f5a04025b7837d187ed8e9aaab7b5fff607327866e9bc9e5da83a84b56dda_bin_ffb626dc2f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "2a1f5a04025b7837d187ed8e9aaab7b5fff607327866e9bc9e5da83a84b56dda.bin"
        original_filepath = "2a1f5a04025b7837d187ed8e9aaab7b5fff607327866e9bc9e5da83a84b56dda.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_d86af736644e20e62807f03c49f4d0ad7de9cbd0723049f34ec79f8c7308fdd5_6d70229c8f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "d86af736644e20e62807f03c49f4d0ad7de9cbd0723049f34ec79f8c7308fdd5"
        original_filepath = "d86af736644e20e62807f03c49f4d0ad7de9cbd0723049f34ec79f8c7308fdd5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_c3b48db40cf810cb63bf36262b7c5b19_8be7a5120b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "C3B48DB40CF810CB63BF36262B7C5B19"
        original_filepath = "C3B48DB40CF810CB63BF36262B7C5B19"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_d048f7ae2d244a264e58af67b1a20db0_15eb5fc171
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "D048F7AE2D244A264E58AF67B1A20DB0"
        original_filepath = "D048F7AE2D244A264E58AF67B1A20DB0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_cf4bf26b2d6f1c6055534bbe9decb579ef0180e0f8c467c1a26e2ead7567058a_b0a07469b5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like cmd.exe, explorer.exe, http://"
        filename = "cf4bf26b2d6f1c6055534bbe9decb579ef0180e0f8c467c1a26e2ead7567058a"
        original_filepath = "cf4bf26b2d6f1c6055534bbe9decb579ef0180e0f8c467c1a26e2ead7567058a"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "cmd.exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_b7f36159aec7f3512e00bfa8aa189cbb97f9cc4752a635bc272c7a5ac1710e0b_9f9354fdea
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, ftp://, .exe"
        filename = "b7f36159aec7f3512e00bfa8aa189cbb97f9cc4752a635bc272c7a5ac1710e0b"
        original_filepath = "b7f36159aec7f3512e00bfa8aa189cbb97f9cc4752a635bc272c7a5ac1710e0b"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "ftp://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_f65fa71e8ffe11bb6e7c6c84c3d365f4fe729e1e9c38cb4f073d2b65058465fa_615817ac41
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "f65fa71e8ffe11bb6e7c6c84c3d365f4fe729e1e9c38cb4f073d2b65058465fa"
        original_filepath = "f65fa71e8ffe11bb6e7c6c84c3d365f4fe729e1e9c38cb4f073d2b65058465fa"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_52cb02da0462fdd08d537b2c949e2e252f7a7a88354d596e9f5c9f1498d1c68f_b113b70659
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "52cb02da0462fdd08d537b2c949e2e252f7a7a88354d596e9f5c9f1498d1c68f"
        original_filepath = "52cb02da0462fdd08d537b2c949e2e252f7a7a88354d596e9f5c9f1498d1c68f"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_c34e5d36bd3a9a6fca92e900ab015aa50bb20d2cd6c0b6e03d070efe09ee689a_a7aadd5847
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "c34e5d36bd3a9a6fca92e900ab015aa50bb20d2cd6c0b6e03d070efe09ee689a"
        original_filepath = "c34e5d36bd3a9a6fca92e900ab015aa50bb20d2cd6c0b6e03d070efe09ee689a"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_unpacked_mem_004f384f7c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, .dll"
        filename = "unpacked.mem"
        original_filepath = "unpacked.mem"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_798_abroad_exe_d1c4e61a12
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "798_abroad.exe"
        original_filepath = "798_abroad.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_flash829_exe_7e9fa622de
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "FLASH829.EXE"
        original_filepath = "FLASH829.EXE"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_b2ca4093b2e0271cb7a3230118843fccc094e0160a0968994ed9f10c8702d867_d9c10b74a7
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "b2ca4093b2e0271cb7a3230118843fccc094e0160a0968994ed9f10c8702d867"
        original_filepath = "b2ca4093b2e0271cb7a3230118843fccc094e0160a0968994ed9f10c8702d867"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_testde_1_cpl_196c9a697d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "TESTDE~1.CPL"
        original_filepath = "TESTDE~1.CPL"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_q30097_1_exe_87e423815f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "Q30097~1.EXE"
        original_filepath = "Q30097~1.EXE"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_q300972i_exe_1c6b65eba8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "Q300972I.EXE"
        original_filepath = "Q300972I.EXE"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_win32_wannapeace_exe_3635cc1110
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "Win32.WannaPeace.exe"
        original_filepath = "Win32.WannaPeace.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_a1b468e9550f9960c5e60f7c52ca3c058de19d42eafa760b9d5282eb24b7c55f_fa311a3116
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "a1b468e9550f9960c5e60f7c52ca3c058de19d42eafa760b9d5282eb24b7c55f"
        original_filepath = "a1b468e9550f9960c5e60f7c52ca3c058de19d42eafa760b9d5282eb24b7c55f"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_773635768e738bec776dfd7504164b3596e5eee344757dd1ac9a1ad19b452c86_4a18aa0c8c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "773635768e738bec776dfd7504164b3596e5eee344757dd1ac9a1ad19b452c86"
        original_filepath = "773635768e738bec776dfd7504164b3596e5eee344757dd1ac9a1ad19b452c86"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_5d491ea5705e90c817cf0f5211c9edbcd5291fe8bd4cc69cdb58e8d0e6b6d1fe_fdc0b05cc9
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "5d491ea5705e90c817cf0f5211c9edbcd5291fe8bd4cc69cdb58e8d0e6b6d1fe"
        original_filepath = "5d491ea5705e90c817cf0f5211c9edbcd5291fe8bd4cc69cdb58e8d0e6b6d1fe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_a7493fac96345a989b1a03772444075754a2ef11daa22a7600466adc1f69a669_790a150041
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "a7493fac96345a989b1a03772444075754a2ef11daa22a7600466adc1f69a669"
        original_filepath = "a7493fac96345a989b1a03772444075754a2ef11daa22a7600466adc1f69a669"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_wtepzsfwgb_a650033619
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "WTEpZSFwgb"
        original_filepath = "WTEpZSFwgb"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_the_zeus_binary_chapros_beffc5ba25
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "the_zeus_binary_chapros"
        original_filepath = "the_zeus_binary_chapros"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_7zipsetup_exe_626ad065e3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "7ZipSetup.exe"
        original_filepath = "7ZipSetup.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_e1d852f2ea8436ac33bc8fe200aca4af4fb15f33ecda6441741589daa44115c5_b6b6f1d709
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "e1d852f2ea8436ac33bc8fe200aca4af4fb15f33ecda6441741589daa44115c5"
        original_filepath = "e1d852f2ea8436ac33bc8fe200aca4af4fb15f33ecda6441741589daa44115c5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_0dc2ab0ccf783fb39028326a7e8b0ba4eaa148020ec05fc26313ef2bf70f700f_42df1d263b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "0dc2ab0ccf783fb39028326a7e8b0ba4eaa148020ec05fc26313ef2bf70f700f"
        original_filepath = "0dc2ab0ccf783fb39028326a7e8b0ba4eaa148020ec05fc26313ef2bf70f700f"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_4bfe2216ee63657312af1b2507c8f2bf362fdf1d63c88faba397e880c2e39430_632f769a44
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "4bfe2216ee63657312af1b2507c8f2bf362fdf1d63c88faba397e880c2e39430"
        original_filepath = "4bfe2216ee63657312af1b2507c8f2bf362fdf1d63c88faba397e880c2e39430"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_schdpl32_exe_78133028cc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "SCHDPL32.exe"
        original_filepath = "SCHDPL32.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_2_tmp_83fb708bd3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "2.tmp"
        original_filepath = "2.tmp"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_7824eb5f173c43574593bd3afab41a60e0e2ffae80201a9b884721b451e6d935_cf6a119dd1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, ftp://, .exe"
        filename = "7824eb5f173c43574593bd3afab41a60e0e2ffae80201a9b884721b451e6d935"
        original_filepath = "7824eb5f173c43574593bd3afab41a60e0e2ffae80201a9b884721b451e6d935"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "ftp://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_scanslam_exe_4584edcce6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "scanslam.exe"
        original_filepath = "scanslam.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_4c1dc737915d76b7ce579abddaba74ead6fdb5b519a1ea45308b8c49b950655c_bin_0f9efd3213
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, explorer.exe, http://"
        filename = "4c1dc737915d76b7ce579abddaba74ead6fdb5b519a1ea45308b8c49b950655c.bin"
        original_filepath = "4c1dc737915d76b7ce579abddaba74ead6fdb5b519a1ea45308b8c49b950655c.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_build_exe_3c8dd96fc2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "Build.exe"
        original_filepath = "Build.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_botbinary_exe_171ec09594
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "BOTBINARY.EXE"
        original_filepath = "BOTBINARY.EXE"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fef436e4196ae779ec1d6dd6dcfeec045bc1f848efed5b24e287354a18c6dd85_18f602c800
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "fef436e4196ae779ec1d6dd6dcfeec045bc1f848efed5b24e287354a18c6dd85"
        original_filepath = "fef436e4196ae779ec1d6dd6dcfeec045bc1f848efed5b24e287354a18c6dd85"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_e93d6f4ce34d4f594d7aed76cfde0fad_17d568ba88
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "e93d6f4ce34d4f594d7aed76cfde0fad"
        original_filepath = "e93d6f4ce34d4f594d7aed76cfde0fad"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_dw20_dll_0983198523
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "DW20.dll"
        original_filepath = "DW20.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_bc12d7052e6cfce8f16625ca8b88803cd4e58356eb32fe62667336d4dee708a3_a677de3542
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "bc12d7052e6cfce8f16625ca8b88803cd4e58356eb32fe62667336d4dee708a3"
        original_filepath = "bc12d7052e6cfce8f16625ca8b88803cd4e58356eb32fe62667336d4dee708a3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_afa8d185de2f357082ed4042fc057a6d7300f603d3bfdbe7e6c351868e45e477_03be3cf61c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "afa8d185de2f357082ed4042fc057a6d7300f603d3bfdbe7e6c351868e45e477"
        original_filepath = "afa8d185de2f357082ed4042fc057a6d7300f603d3bfdbe7e6c351868e45e477"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_avatar_rootkit_netbotnet_32d6644c5ea66e390070d3dc3401e54b_unpacked_e288e6fd6a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Avatar_Rootkit_NETbotnet_32d6644c5ea66e390070d3dc3401e54b_unpacked"
        original_filepath = "Avatar_Rootkit_NETbotnet_32d6644c5ea66e390070d3dc3401e54b_unpacked"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_d12cd9490fd75e192ea053a05e869ed2f3f9748bf1563e6e496e7153fb4e6c98_96b1abc2ad
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "d12cd9490fd75e192ea053a05e869ed2f3f9748bf1563e6e496e7153fb4e6c98"
        original_filepath = "d12cd9490fd75e192ea053a05e869ed2f3f9748bf1563e6e496e7153fb4e6c98"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_d8a849654ab97debaf28ae5b749c3b1ff1812ea49978713853333db48c3972c3_57f4b1894b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "d8a849654ab97debaf28ae5b749c3b1ff1812ea49978713853333db48c3972c3"
        original_filepath = "d8a849654ab97debaf28ae5b749c3b1ff1812ea49978713853333db48c3972c3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_2c9c3ddd4d93e687eb095444cef7668b21636b364bff55de953bdd1df40071da_09d3945def
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "2c9c3ddd4d93e687eb095444cef7668b21636b364bff55de953bdd1df40071da"
        original_filepath = "2c9c3ddd4d93e687eb095444cef7668b21636b364bff55de953bdd1df40071da"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_6de1bb58ae3c37876c6372208366f5548fcc647ffd19ad1d31cebd9069b8a559_8982750ae1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "6de1bb58ae3c37876c6372208366f5548fcc647ffd19ad1d31cebd9069b8a559"
        original_filepath = "6de1bb58ae3c37876c6372208366f5548fcc647ffd19ad1d31cebd9069b8a559"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_2ecb26021d21fcef3d8bba63de0c888499110a2b78e4caa6fa07a2b27d87f71b_825ab45637
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "2ecb26021d21fcef3d8bba63de0c888499110a2b78e4caa6fa07a2b27d87f71b"
        original_filepath = "2ecb26021d21fcef3d8bba63de0c888499110a2b78e4caa6fa07a2b27d87f71b"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_6c803aac51038ce308ee085f2cd82a055aaa9ba24d08a19efb2c0fcfde936c34_20bed9ca51
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "6c803aac51038ce308ee085f2cd82a055aaa9ba24d08a19efb2c0fcfde936c34"
        original_filepath = "6c803aac51038ce308ee085f2cd82a055aaa9ba24d08a19efb2c0fcfde936c34"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_d5c57788cf12b020c4083eb228911260b744a2a67c88662c9bab8faebca98fa2_197ac0d935
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "d5c57788cf12b020c4083eb228911260b744a2a67c88662c9bab8faebca98fa2"
        original_filepath = "d5c57788cf12b020c4083eb228911260b744a2a67c88662c9bab8faebca98fa2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_c16410c49dc40a371be22773f420b7dd3cfd4d8205cf39909ad9a6f26f55718e_a591000609
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "c16410c49dc40a371be22773f420b7dd3cfd4d8205cf39909ad9a6f26f55718e"
        original_filepath = "c16410c49dc40a371be22773f420b7dd3cfd4d8205cf39909ad9a6f26f55718e"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_6217cebf11a76c888cc6ae94f54597a877462ed70da49a88589a9197173cc072_d8b3a56b47
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "6217cebf11a76c888cc6ae94f54597a877462ed70da49a88589a9197173cc072"
        original_filepath = "6217cebf11a76c888cc6ae94f54597a877462ed70da49a88589a9197173cc072"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_9900c91f6d754f15f73729ce5a4333a718463e24aa7e6192c7527ec5c80dac42_dd9d076fec
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "9900c91f6d754f15f73729ce5a4333a718463e24aa7e6192c7527ec5c80dac42"
        original_filepath = "9900c91f6d754f15f73729ce5a4333a718463e24aa7e6192c7527ec5c80dac42"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_5ba187106567e8d036edd5ddb6763f89774c158d2a571e15d76572d8604c22a0_f937d0cc12
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "5ba187106567e8d036edd5ddb6763f89774c158d2a571e15d76572d8604c22a0"
        original_filepath = "5ba187106567e8d036edd5ddb6763f89774c158d2a571e15d76572d8604c22a0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_8e97c371633d285cd8fc842f4582705052a9409149ee67d97de545030787a192_9efea5bef2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "8e97c371633d285cd8fc842f4582705052a9409149ee67d97de545030787a192"
        original_filepath = "8e97c371633d285cd8fc842f4582705052a9409149ee67d97de545030787a192"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_e83c6c36dbd143ee0fd36aff30fb43529a34129817dc2530f251121527cbf4b4_81208bee40
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "e83c6c36dbd143ee0fd36aff30fb43529a34129817dc2530f251121527cbf4b4"
        original_filepath = "e83c6c36dbd143ee0fd36aff30fb43529a34129817dc2530f251121527cbf4b4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_6e09e1a4f56ea736ff21ad5e188845615b57e1a5168f4bdaebe7ddc634912de9_8166ecaa74
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "6e09e1a4f56ea736ff21ad5e188845615b57e1a5168f4bdaebe7ddc634912de9"
        original_filepath = "6e09e1a4f56ea736ff21ad5e188845615b57e1a5168f4bdaebe7ddc634912de9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_6b146e3a59025d7085127b552494e8aaf76450a19c249bfed0b4c09f328e564f_b43a301b87
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "6b146e3a59025d7085127b552494e8aaf76450a19c249bfed0b4c09f328e564f"
        original_filepath = "6b146e3a59025d7085127b552494e8aaf76450a19c249bfed0b4c09f328e564f"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_5559fcc93eef38a1c22db66a3e0f9e9f026c99e741cc8b1a4980d166f2696188_7b6e44e8a1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "5559fcc93eef38a1c22db66a3e0f9e9f026c99e741cc8b1a4980d166f2696188"
        original_filepath = "5559fcc93eef38a1c22db66a3e0f9e9f026c99e741cc8b1a4980d166f2696188"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_2796a119171328e91648a73d95eb297edc220e8768f4bbba5fb7237122a988fc_2207827ac3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "2796a119171328e91648a73d95eb297edc220e8768f4bbba5fb7237122a988fc"
        original_filepath = "2796a119171328e91648a73d95eb297edc220e8768f4bbba5fb7237122a988fc"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_3536df7379660d931256b3cf49be810c0d931c3957c464d75e4cba78ba3b92e3_e18c6d6184
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "3536df7379660d931256b3cf49be810c0d931c3957c464d75e4cba78ba3b92e3"
        original_filepath = "3536df7379660d931256b3cf49be810c0d931c3957c464d75e4cba78ba3b92e3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_2a9a5afc342cde12c6eb9a91ad29f7afdfd8f0fb17b983dcfddceccfbc17af69_a7d0093dc7
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "2a9a5afc342cde12c6eb9a91ad29f7afdfd8f0fb17b983dcfddceccfbc17af69"
        original_filepath = "2a9a5afc342cde12c6eb9a91ad29f7afdfd8f0fb17b983dcfddceccfbc17af69"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_ae66e009e16f0fad3b70ad20801f48f2edb904fa5341a89e126a26fd3fc80f75_4751f7830a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, .exe, .dll"
        filename = "ae66e009e16f0fad3b70ad20801f48f2edb904fa5341a89e126a26fd3fc80f75"
        original_filepath = "ae66e009e16f0fad3b70ad20801f48f2edb904fa5341a89e126a26fd3fc80f75"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = ".exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_plugx_3c74a85c2cf883bd9d4b9f8b9746030f_dw20_dll_d3253a7978
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "PlugX_3C74A85C2CF883BD9D4B9F8B9746030F_DW20.dll_"
        original_filepath = "PlugX_3C74A85C2CF883BD9D4B9F8B9746030F_DW20.dll_"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_9a776b895e93926e2a758c09e341accb9333edc1243d216a5e53f47c6043c852_a7d6717d51
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, ftp://, .exe"
        filename = "9a776b895e93926e2a758c09e341accb9333edc1243d216a5e53f47c6043c852"
        original_filepath = "9a776b895e93926e2a758c09e341accb9333edc1243d216a5e53f47c6043c852"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "ftp://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_c4762489488f797b4b33382c8b1b71c94a42c846f1f28e0e118c83fe032848f0_84a24748ec
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "c4762489488f797b4b33382c8b1b71c94a42c846f1f28e0e118c83fe032848f0"
        original_filepath = "c4762489488f797b4b33382c8b1b71c94a42c846f1f28e0e118c83fe032848f0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_psih_safe_9d35db9524
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "psih.safe"
        original_filepath = "psih.safe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_5a310669920099cd51f82bc9eb5459e9889b6357a21f7ce95ac961e053c79acb_43e8cdb505
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "5a310669920099cd51f82bc9eb5459e9889b6357a21f7ce95ac961e053c79acb"
        original_filepath = "5a310669920099cd51f82bc9eb5459e9889b6357a21f7ce95ac961e053c79acb"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_2_dll_ed726c985b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "2.dll"
        original_filepath = "2.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_17_68bb4e8769
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "17"
        original_filepath = "17"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_ca467e332368cbae652245faa4978aa4_17b1a9f75e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "ca467e332368cbae652245faa4978aa4"
        original_filepath = "ca467e332368cbae652245faa4978aa4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_dd207384b31d118745ebc83203a4b04a_bin_94d55e4b75
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "dd207384b31d118745ebc83203a4b04a.bin"
        original_filepath = "dd207384b31d118745ebc83203a4b04a.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_b44634d90a9ff2ed8a9d0304c11bf612_bin_69c06ac5ef
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "b44634d90a9ff2ed8a9d0304c11bf612.bin"
        original_filepath = "b44634d90a9ff2ed8a9d0304c11bf612.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_document_772976_829712_scr_74f5653aec
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Document-772976_829712.scr"
        original_filepath = "Document-772976_829712.scr"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_999bc5e16312db6abff5f6c9e54c546f_bin_11925db983
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "999bc5e16312db6abff5f6c9e54c546f.bin"
        original_filepath = "999bc5e16312db6abff5f6c9e54c546f.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_payload_f8eccfebda8a1e0caabbe23a8b94d7ced980353a9b3673a4173e24958a3bdbb9_b2499322a0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, explorer.exe"
        filename = "payload_f8eccfebda8a1e0caabbe23a8b94d7ced980353a9b3673a4173e24958a3bdbb9"
        original_filepath = "payload_f8eccfebda8a1e0caabbe23a8b94d7ced980353a9b3673a4173e24958a3bdbb9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_loader_9b313e9c79921b22b488a11344b280d4cec9dd09c2201f9e5aaf08a115650b25_b641868877
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "loader_9b313e9c79921b22b488a11344b280d4cec9dd09c2201f9e5aaf08a115650b25"
        original_filepath = "loader_9b313e9c79921b22b488a11344b280d4cec9dd09c2201f9e5aaf08a115650b25"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_fax_390392029_072514_exe_94297f95fc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "fax_390392029_072514.exe"
        original_filepath = "fax_390392029_072514.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_chqpl_file_b324392ca2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "chqpl.file"
        original_filepath = "chqpl.file"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_midgets_scr_0b89a98f30
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "midgets.scr"
        original_filepath = "midgets.scr"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_equationdrug_4556ce5eb007af1de5bd3b457f0b216d_fc2a603602
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "EquationDrug_4556CE5EB007AF1DE5BD3B457F0B216D"
        original_filepath = "EquationDrug_4556CE5EB007AF1DE5BD3B457F0B216D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_e1d852f2ea8436ac33bc8fe200aca4af4fb15f33ecda6441741589daa44115c5_cf3e1d8ed7
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "e1d852f2ea8436ac33bc8fe200aca4af4fb15f33ecda6441741589daa44115c5"
        original_filepath = "e1d852f2ea8436ac33bc8fe200aca4af4fb15f33ecda6441741589daa44115c5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_0dc2ab0ccf783fb39028326a7e8b0ba4eaa148020ec05fc26313ef2bf70f700f_eebe93f0d6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "0dc2ab0ccf783fb39028326a7e8b0ba4eaa148020ec05fc26313ef2bf70f700f"
        original_filepath = "0dc2ab0ccf783fb39028326a7e8b0ba4eaa148020ec05fc26313ef2bf70f700f"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_wmighost_dll_1b88b47e91
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "wmighost.dll"
        original_filepath = "wmighost.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_afa8d185de2f357082ed4042fc057a6d7300f603d3bfdbe7e6c351868e45e477_370bc9ccff
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "afa8d185de2f357082ed4042fc057a6d7300f603d3bfdbe7e6c351868e45e477"
        original_filepath = "afa8d185de2f357082ed4042fc057a6d7300f603d3bfdbe7e6c351868e45e477"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_6072a303039b032f1b3b0e596a3eb9a35568cef830a18404c18bb4fffef86fba_ee20fb6d82
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "6072a303039b032f1b3b0e596a3eb9a35568cef830a18404c18bb4fffef86fba"
        original_filepath = "6072a303039b032f1b3b0e596a3eb9a35568cef830a18404c18bb4fffef86fba"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_a38df3ec8b9fe52a32860cf5756d2fe345badafd7e74466cd349eb32ba5cc339_5e77a69613
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "a38df3ec8b9fe52a32860cf5756d2fe345badafd7e74466cd349eb32ba5cc339"
        original_filepath = "a38df3ec8b9fe52a32860cf5756d2fe345badafd7e74466cd349eb32ba5cc339"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_86bb737bd9a508be2ff9dc0dee7e7c40abea215088c61788a368948f9250fa4c_a2d66844b6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "86bb737bd9a508be2ff9dc0dee7e7c40abea215088c61788a368948f9250fa4c"
        original_filepath = "86bb737bd9a508be2ff9dc0dee7e7c40abea215088c61788a368948f9250fa4c"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_6b91fdb0992ca029c913092db7b4fd94c917c1473953d1ec77c74d030776fe9a_7bcbf22d6e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "6b91fdb0992ca029c913092db7b4fd94c917c1473953d1ec77c74d030776fe9a"
        original_filepath = "6b91fdb0992ca029c913092db7b4fd94c917c1473953d1ec77c74d030776fe9a"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_01259a104a0199b794b0c61fcfc657eb766b2caeae68d5c6b164a53a97874257_e3d15f8d6f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "01259a104a0199b794b0c61fcfc657eb766b2caeae68d5c6b164a53a97874257"
        original_filepath = "01259a104a0199b794b0c61fcfc657eb766b2caeae68d5c6b164a53a97874257"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_05455efecab4a7931fa53a3c2008d04fc6b539c5e8f451f19b617bd9b3ebcd83_bd460eed9b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "05455efecab4a7931fa53a3c2008d04fc6b539c5e8f451f19b617bd9b3ebcd83"
        original_filepath = "05455efecab4a7931fa53a3c2008d04fc6b539c5e8f451f19b617bd9b3ebcd83"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_9c17f267f79597ee01515f5ef925375d8a19844830cc46917a3d1b5bcb0ba4c3_51f4f5c3ba
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "9c17f267f79597ee01515f5ef925375d8a19844830cc46917a3d1b5bcb0ba4c3"
        original_filepath = "9c17f267f79597ee01515f5ef925375d8a19844830cc46917a3d1b5bcb0ba4c3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_7249b1a5082c9d9654d9fac3bb5e965ea23e395554d3351b77dd4f29677426fe_22141bb486
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "7249b1a5082c9d9654d9fac3bb5e965ea23e395554d3351b77dd4f29677426fe"
        original_filepath = "7249b1a5082c9d9654d9fac3bb5e965ea23e395554d3351b77dd4f29677426fe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_084a220ba90622cc223b93f32130e9f2d072679f66d1816775bf14832d492b8a_75e36a78e3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "084a220ba90622cc223b93f32130e9f2d072679f66d1816775bf14832d492b8a"
        original_filepath = "084a220ba90622cc223b93f32130e9f2d072679f66d1816775bf14832d492b8a"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_0cfc34fa76228b1afc7ce63e284a23ce1cd2927e6159b9dea9702ad9cb2a6300_cc6462dd48
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "0cfc34fa76228b1afc7ce63e284a23ce1cd2927e6159b9dea9702ad9cb2a6300"
        original_filepath = "0cfc34fa76228b1afc7ce63e284a23ce1cd2927e6159b9dea9702ad9cb2a6300"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_cff49c25b053f775db8980a431a958020bdf969ea08872de4cef5a5f344f534c_bfc5cf32f1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "cff49c25b053f775db8980a431a958020bdf969ea08872de4cef5a5f344f534c"
        original_filepath = "cff49c25b053f775db8980a431a958020bdf969ea08872de4cef5a5f344f534c"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_a3667153a6322fb8d4cf8869c094a05e995e2954fda833fe14304837ed4fd0bd_2c7f566a3d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "a3667153a6322fb8d4cf8869c094a05e995e2954fda833fe14304837ed4fd0bd"
        original_filepath = "a3667153a6322fb8d4cf8869c094a05e995e2954fda833fe14304837ed4fd0bd"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_0eb038e7e5edd6ac1b4eee8dd1c51b6d94da24d02ba705e7e7f10b41edf701c2_a295ab64fc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "0eb038e7e5edd6ac1b4eee8dd1c51b6d94da24d02ba705e7e7f10b41edf701c2"
        original_filepath = "0eb038e7e5edd6ac1b4eee8dd1c51b6d94da24d02ba705e7e7f10b41edf701c2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_c7128e2772b4f8c59943028e205d1b23c07f36206c1c61a05645c7bf143b24ee_d2285520ba
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "c7128e2772b4f8c59943028e205d1b23c07f36206c1c61a05645c7bf143b24ee"
        original_filepath = "c7128e2772b4f8c59943028e205d1b23c07f36206c1c61a05645c7bf143b24ee"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_a6ff8dfe654da70390cd71626cdca8a6f6a0d7980cd7d82269373737b04fd206_074c83cc7f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "a6ff8dfe654da70390cd71626cdca8a6f6a0d7980cd7d82269373737b04fd206"
        original_filepath = "a6ff8dfe654da70390cd71626cdca8a6f6a0d7980cd7d82269373737b04fd206"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_6072a303039b032f1b3b0e596a3eb9a35568cef830a18404c18bb4fffef86fba_c344fd74fb
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "6072a303039b032f1b3b0e596a3eb9a35568cef830a18404c18bb4fffef86fba"
        original_filepath = "6072a303039b032f1b3b0e596a3eb9a35568cef830a18404c18bb4fffef86fba"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_c1e5dae72a51a7b7219346c4a360d867_067ef09a07
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "C1E5DAE72A51A7B7219346C4A360D867"
        original_filepath = "C1E5DAE72A51A7B7219346C4A360D867"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_cf8533849ee5e82023ad7adbdbd6543cb6db596c53048b1a0c00b3643a72db30_d2e66ea1c9
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "cf8533849ee5e82023ad7adbdbd6543cb6db596c53048b1a0c00b3643a72db30"
        original_filepath = "cf8533849ee5e82023ad7adbdbd6543cb6db596c53048b1a0c00b3643a72db30"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_a7e3ad8ea7edf1ca10b0e5b0d976675c3016e5933219f97e94900dea0d470abe_f602b35c40
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "a7e3ad8ea7edf1ca10b0e5b0d976675c3016e5933219f97e94900dea0d470abe"
        original_filepath = "a7e3ad8ea7edf1ca10b0e5b0d976675c3016e5933219f97e94900dea0d470abe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_9b3c6fd39b2809e388255c5651953251920c5c7d5e77da1070ab3c127e8bdc11_d4b67f9b93
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "9b3c6fd39b2809e388255c5651953251920c5c7d5e77da1070ab3c127e8bdc11"
        original_filepath = "9b3c6fd39b2809e388255c5651953251920c5c7d5e77da1070ab3c127e8bdc11"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_129b8825eaf61dcc2321aad7b84632233fa4bbc7e24bdf123b507157353930f0_37b88a4cdd
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "129b8825eaf61dcc2321aad7b84632233fa4bbc7e24bdf123b507157353930f0"
        original_filepath = "129b8825eaf61dcc2321aad7b84632233fa4bbc7e24bdf123b507157353930f0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_18884936d002839833a537921eb7ebdb073fa8a153bfeba587457b07b74fb3b2_8294cd0cde
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "18884936d002839833a537921eb7ebdb073fa8a153bfeba587457b07b74fb3b2"
        original_filepath = "18884936d002839833a537921eb7ebdb073fa8a153bfeba587457b07b74fb3b2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_21_exe_d9d6278b6b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "21.exe"
        original_filepath = "21.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_zerolocker_d4c62215df74753371db33a19a69fccdc4b375c893a4b7f8b30172710fbd4cfa_c6e197916b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "zerolocker_d4c62215df74753371db33a19a69fccdc4b375c893a4b7f8b30172710fbd4cfa"
        original_filepath = "zerolocker_d4c62215df74753371db33a19a69fccdc4b375c893a4b7f8b30172710fbd4cfa"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_1215584b4fa69130799f6cf5efe467f380dc68b14ed2c76f63ca6b461ad57246_d216b6d4f0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "1215584b4fa69130799f6cf5efe467f380dc68b14ed2c76f63ca6b461ad57246"
        original_filepath = "1215584b4fa69130799f6cf5efe467f380dc68b14ed2c76f63ca6b461ad57246"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_a98099541168c7f36b107e24e9c80c9125fefb787ae720799b03bb4425aba1a9_1989bc838c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "a98099541168c7f36b107e24e9c80c9125fefb787ae720799b03bb4425aba1a9"
        original_filepath = "a98099541168c7f36b107e24e9c80c9125fefb787ae720799b03bb4425aba1a9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_output_1301364_old_282ab761ee
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "output.1301364.old"
        original_filepath = "output.1301364.old"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_8218c23361e9f1b25ee1a93796ef471ca8ca5ac672b7db69ad05f42eb90b0b8d_3fb7ea67e1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "8218c23361e9f1b25ee1a93796ef471ca8ca5ac672b7db69ad05f42eb90b0b8d"
        original_filepath = "8218c23361e9f1b25ee1a93796ef471ca8ca5ac672b7db69ad05f42eb90b0b8d"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_c14f6ac5bcd8645eb80a612a6bf6d58c31b0e28e50be871f278c341ed1fa8c7c_82ba32b413
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "c14f6ac5bcd8645eb80a612a6bf6d58c31b0e28e50be871f278c341ed1fa8c7c"
        original_filepath = "c14f6ac5bcd8645eb80a612a6bf6d58c31b0e28e50be871f278c341ed1fa8c7c"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_05b63707ca3cad54085e521aee84c7472ff7b3fe05e22fd65c8e2ee6f36c6243_750472cde2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .dll"
        filename = "05b63707ca3cad54085e521aee84c7472ff7b3fe05e22fd65c8e2ee6f36c6243"
        original_filepath = "05b63707ca3cad54085e521aee84c7472ff7b3fe05e22fd65c8e2ee6f36c6243"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_7e5b05d29c3aa2aa178c3cc0338ba52b39dc89dafadeec7301f187db0b060372_1f877dc949
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "7e5b05d29c3aa2aa178c3cc0338ba52b39dc89dafadeec7301f187db0b060372"
        original_filepath = "7e5b05d29c3aa2aa178c3cc0338ba52b39dc89dafadeec7301f187db0b060372"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_57f64f170dfeaa1150493ed3f63ea6f1df3ca71ad1722e12ac0f77744fb1a829_e69e7d931d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like cmd.exe, explorer.exe, http://"
        filename = "57f64f170dfeaa1150493ed3f63ea6f1df3ca71ad1722e12ac0f77744fb1a829"
        original_filepath = "57f64f170dfeaa1150493ed3f63ea6f1df3ca71ad1722e12ac0f77744fb1a829"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "cmd.exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_d31d135bc450eafa698e6b7fb5d11b4926948163af09122ca1c568284d8b33b3_2a9fdcf945
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "d31d135bc450eafa698e6b7fb5d11b4926948163af09122ca1c568284d8b33b3"
        original_filepath = "d31d135bc450eafa698e6b7fb5d11b4926948163af09122ca1c568284d8b33b3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_b1102ed4bca6dae6f2f498ade2f73f76af527fa803f0e0b46e100d4cf5150682_111327f274
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "b1102ed4bca6dae6f2f498ade2f73f76af527fa803f0e0b46e100d4cf5150682"
        original_filepath = "b1102ed4bca6dae6f2f498ade2f73f76af527fa803f0e0b46e100d4cf5150682"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_2e3645c8441f2be4182869db5ae320da00c513e0cb643142c70a833f529f28aa_05edd25980
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "2e3645c8441f2be4182869db5ae320da00c513e0cb643142c70a833f529f28aa"
        original_filepath = "2e3645c8441f2be4182869db5ae320da00c513e0cb643142c70a833f529f28aa"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_d17fe5bc3042baf219e81cbbf991749dfcd8b6d73cf6506a8228e19910da3578_02abddccd8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "d17fe5bc3042baf219e81cbbf991749dfcd8b6d73cf6506a8228e19910da3578"
        original_filepath = "d17fe5bc3042baf219e81cbbf991749dfcd8b6d73cf6506a8228e19910da3578"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_dd469fbf68f6bf71e495b3e497e31d17aa1d0af918a943f8637dd3304f840740_ed962b0a33
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, .dll"
        filename = "dd469fbf68f6bf71e495b3e497e31d17aa1d0af918a943f8637dd3304f840740"
        original_filepath = "dd469fbf68f6bf71e495b3e497e31d17aa1d0af918a943f8637dd3304f840740"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_e0f109836a025d4531ea895cebecc9bdefb84a0cc747861986c4bc231e1d4213_c5cbf840d8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "e0f109836a025d4531ea895cebecc9bdefb84a0cc747861986c4bc231e1d4213"
        original_filepath = "e0f109836a025d4531ea895cebecc9bdefb84a0cc747861986c4bc231e1d4213"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_241737842eb17676b3603e2f076336b7bc6304accef3057401264affb963bef8_1b4946b23a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "241737842eb17676b3603e2f076336b7bc6304accef3057401264affb963bef8"
        original_filepath = "241737842eb17676b3603e2f076336b7bc6304accef3057401264affb963bef8"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_82f7bcda95fcc0e690159a2fbd7b3e38ef3ff9105496498f86d1fa9ff4312846_1ecd24c3dc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, cmd.exe, http://"
        filename = "82f7bcda95fcc0e690159a2fbd7b3e38ef3ff9105496498f86d1fa9ff4312846"
        original_filepath = "82f7bcda95fcc0e690159a2fbd7b3e38ef3ff9105496498f86d1fa9ff4312846"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "cmd.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_ccd4a648cc2c4a5bbcd148f9c182f4c9595440a41dd3ea289a11609063c86a6d_2c5b494c31
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .vbs, http://"
        filename = "ccd4a648cc2c4a5bbcd148f9c182f4c9595440a41dd3ea289a11609063c86a6d"
        original_filepath = "ccd4a648cc2c4a5bbcd148f9c182f4c9595440a41dd3ea289a11609063c86a6d"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".vbs" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_d2cc1135c314f526f88fbe19f25d94899d52de7e3422f334437f32388d040d71_b094a61540
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "d2cc1135c314f526f88fbe19f25d94899d52de7e3422f334437f32388d040d71"
        original_filepath = "d2cc1135c314f526f88fbe19f25d94899d52de7e3422f334437f32388d040d71"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_f4ea99dc41cb7922d01955eef9303ec3a24b88c3318138855346de1e830ed09e_3b8e0a12a3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "f4ea99dc41cb7922d01955eef9303ec3a24b88c3318138855346de1e830ed09e"
        original_filepath = "f4ea99dc41cb7922d01955eef9303ec3a24b88c3318138855346de1e830ed09e"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_d176951b9ff3239b659ad57b729edb0845785e418852ecfeef1669f4c6fed61b_0f7cf09254
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "d176951b9ff3239b659ad57b729edb0845785e418852ecfeef1669f4c6fed61b"
        original_filepath = "d176951b9ff3239b659ad57b729edb0845785e418852ecfeef1669f4c6fed61b"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_9ada058a558b7cadb238fc2c259f204369cd604e927f9712fd51262ca6987cb1_0cc054cb20
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, explorer.exe, http://"
        filename = "9ada058a558b7cadb238fc2c259f204369cd604e927f9712fd51262ca6987cb1"
        original_filepath = "9ada058a558b7cadb238fc2c259f204369cd604e927f9712fd51262ca6987cb1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".vbs" nocase ascii wide
        $g5 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4,$g5)
}


rule Generic_Suspicious_Strings_b19a46f99b649dc731ed5c8410bda7e0385d15e1b9aab1e467b05dccd7753865_6c44157e7c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "b19a46f99b649dc731ed5c8410bda7e0385d15e1b9aab1e467b05dccd7753865"
        original_filepath = "b19a46f99b649dc731ed5c8410bda7e0385d15e1b9aab1e467b05dccd7753865"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_fe4fad660bb44e108ab07d812f8b1bbf16852c1b881a5e721a9f811cae317f39_2e2602b829
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like explorer.exe, http://, .exe"
        filename = "fe4fad660bb44e108ab07d812f8b1bbf16852c1b881a5e721a9f811cae317f39"
        original_filepath = "fe4fad660bb44e108ab07d812f8b1bbf16852c1b881a5e721a9f811cae317f39"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "explorer.exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".vbs" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_0ff80e4db32d1d45a0c2afdfd7a1be961c0fbd9d43613a22a989f9024cc1b1e9_87605b724d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "0ff80e4db32d1d45a0c2afdfd7a1be961c0fbd9d43613a22a989f9024cc1b1e9"
        original_filepath = "0ff80e4db32d1d45a0c2afdfd7a1be961c0fbd9d43613a22a989f9024cc1b1e9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_5a32bf21904387d469d4f8cdaff46048e99666fc9b4d74872af9379df7979bfe_872d8b0196
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, cmd.exe, http://"
        filename = "5a32bf21904387d469d4f8cdaff46048e99666fc9b4d74872af9379df7979bfe"
        original_filepath = "5a32bf21904387d469d4f8cdaff46048e99666fc9b4d74872af9379df7979bfe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "cmd.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_5a6a0e01949799dc72c030b4ad8149446624dcd9645ba3eefda981c3fda26472_c71c330ae5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "5a6a0e01949799dc72c030b4ad8149446624dcd9645ba3eefda981c3fda26472"
        original_filepath = "5a6a0e01949799dc72c030b4ad8149446624dcd9645ba3eefda981c3fda26472"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_35f16e469047cf4ef78f87a616d26ec09e3d6a3d7a51415ea34805549a41dcfa_42a587c6a6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "35f16e469047cf4ef78f87a616d26ec09e3d6a3d7a51415ea34805549a41dcfa"
        original_filepath = "35f16e469047cf4ef78f87a616d26ec09e3d6a3d7a51415ea34805549a41dcfa"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_5e1839fed3562d559166f7f9d3e388cdd21da83b67ccb70fa4121825b91469d6_2d20391f30
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "5e1839fed3562d559166f7f9d3e388cdd21da83b67ccb70fa4121825b91469d6"
        original_filepath = "5e1839fed3562d559166f7f9d3e388cdd21da83b67ccb70fa4121825b91469d6"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_ef4a2cfe4d9d3495d4957a65299f608f7b823fab0699fded728fd3900c0b2bb4_6dec813a73
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, .dll"
        filename = "ef4a2cfe4d9d3495d4957a65299f608f7b823fab0699fded728fd3900c0b2bb4"
        original_filepath = "ef4a2cfe4d9d3495d4957a65299f608f7b823fab0699fded728fd3900c0b2bb4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_3f0aa01ed70bc2ab29557521a65476ec2ff2c867315067cc8a5937d63bcbe815_1788d1c98d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "3f0aa01ed70bc2ab29557521a65476ec2ff2c867315067cc8a5937d63bcbe815"
        original_filepath = "3f0aa01ed70bc2ab29557521a65476ec2ff2c867315067cc8a5937d63bcbe815"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_6a4e32229e5ca41e8eca99cefe5beef3e3621c2199f8844b4d218c14b5481534_802d95d560
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "6a4e32229e5ca41e8eca99cefe5beef3e3621c2199f8844b4d218c14b5481534"
        original_filepath = "6a4e32229e5ca41e8eca99cefe5beef3e3621c2199f8844b4d218c14b5481534"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_7af402f4bd2b1a2d2d8b74fb7599860f3a90b7b6f66a519f2b4d31aeea2500aa_f0c0d9b7eb
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "7af402f4bd2b1a2d2d8b74fb7599860f3a90b7b6f66a519f2b4d31aeea2500aa"
        original_filepath = "7af402f4bd2b1a2d2d8b74fb7599860f3a90b7b6f66a519f2b4d31aeea2500aa"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_a99bf162a8588b2f318c9460aef78851bd64e4826c2cb124984d2ab357a6beea_eecffc0b29
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "a99bf162a8588b2f318c9460aef78851bd64e4826c2cb124984d2ab357a6beea"
        original_filepath = "a99bf162a8588b2f318c9460aef78851bd64e4826c2cb124984d2ab357a6beea"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_f5b6c0d73c513c3c8efbcc967d7f6865559e90d59fb78b2b15394f22fd7315cb_c782766198
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "f5b6c0d73c513c3c8efbcc967d7f6865559e90d59fb78b2b15394f22fd7315cb"
        original_filepath = "f5b6c0d73c513c3c8efbcc967d7f6865559e90d59fb78b2b15394f22fd7315cb"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_484578b6e7e427a151c309bdc00c90b1c0faf25a8581cace55e2c25ec34056e0_16a3b7bc82
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "484578b6e7e427a151c309bdc00c90b1c0faf25a8581cace55e2c25ec34056e0"
        original_filepath = "484578b6e7e427a151c309bdc00c90b1c0faf25a8581cace55e2c25ec34056e0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_bc422a4e1b6a351ac6fe73d496015cfa6a9dbd5e38566c6f44a59faff83ee95a_f6a4f78ecc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "bc422a4e1b6a351ac6fe73d496015cfa6a9dbd5e38566c6f44a59faff83ee95a"
        original_filepath = "bc422a4e1b6a351ac6fe73d496015cfa6a9dbd5e38566c6f44a59faff83ee95a"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_67ad30c3359b377d1964a5add97d2dc96b855940685131b302d5ba2c907ef355_63f996b787
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, cmd.exe, http://"
        filename = "67ad30c3359b377d1964a5add97d2dc96b855940685131b302d5ba2c907ef355"
        original_filepath = "67ad30c3359b377d1964a5add97d2dc96b855940685131b302d5ba2c907ef355"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "cmd.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_1d3d460b22f70cc26252673e12dfd85da988f69046d6b94602576270df590b2c_145e1157f4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "1d3d460b22f70cc26252673e12dfd85da988f69046d6b94602576270df590b2c"
        original_filepath = "1d3d460b22f70cc26252673e12dfd85da988f69046d6b94602576270df590b2c"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_50cdd2397836d33a8dc285ed421d9b7cc69e38ba0421638235206fd466299dab_03a721d8f7
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "50cdd2397836d33a8dc285ed421d9b7cc69e38ba0421638235206fd466299dab"
        original_filepath = "50cdd2397836d33a8dc285ed421d9b7cc69e38ba0421638235206fd466299dab"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_5b17bc2a89727700f94570b0dddc12b315db34dbbd79186177167abbb173cee5_33fea3b9f9
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "5b17bc2a89727700f94570b0dddc12b315db34dbbd79186177167abbb173cee5"
        original_filepath = "5b17bc2a89727700f94570b0dddc12b315db34dbbd79186177167abbb173cee5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_01b09cb97a58ea0f9bf2b98b38b83f0cfc9f97f39f7bfd73a990c9b00bcdb66c_e4a622578f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "01b09cb97a58ea0f9bf2b98b38b83f0cfc9f97f39f7bfd73a990c9b00bcdb66c"
        original_filepath = "01b09cb97a58ea0f9bf2b98b38b83f0cfc9f97f39f7bfd73a990c9b00bcdb66c"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_d096c3a67634599bc47151f0e01a7423a3eb873377371b2b928c0d4f57635a1f_b4c83fa95c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "d096c3a67634599bc47151f0e01a7423a3eb873377371b2b928c0d4f57635a1f"
        original_filepath = "d096c3a67634599bc47151f0e01a7423a3eb873377371b2b928c0d4f57635a1f"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_b8f2da1eefa09077d86a443ad688080b98672f171918c06e2b3652df783be03a_f0a20bc989
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "b8f2da1eefa09077d86a443ad688080b98672f171918c06e2b3652df783be03a"
        original_filepath = "b8f2da1eefa09077d86a443ad688080b98672f171918c06e2b3652df783be03a"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_804387e43fdd1bd45b35e65d52d86882d64956b0a286e8721da402062f95a9e3_3a09c5fe71
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "804387e43fdd1bd45b35e65d52d86882d64956b0a286e8721da402062f95a9e3"
        original_filepath = "804387e43fdd1bd45b35e65d52d86882d64956b0a286e8721da402062f95a9e3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_c9d5dc956841e000bfd8762e2f0b48b66c79b79500e894b4efa7fb9ba17e4e9e_a7ec15ba9e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "c9d5dc956841e000bfd8762e2f0b48b66c79b79500e894b4efa7fb9ba17e4e9e"
        original_filepath = "c9d5dc956841e000bfd8762e2f0b48b66c79b79500e894b4efa7fb9ba17e4e9e"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_6fd7697efc137faf2d3ad5d63ffe4743db70f905a71dbed76207beeeb04732f2_dc9ec5036a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "6fd7697efc137faf2d3ad5d63ffe4743db70f905a71dbed76207beeeb04732f2"
        original_filepath = "6fd7697efc137faf2d3ad5d63ffe4743db70f905a71dbed76207beeeb04732f2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_f66a6b49a23cf3cc842a84d955c0292e7d1c0718ec4e78d4513e18b6c53a94ac_e9245a8691
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "f66a6b49a23cf3cc842a84d955c0292e7d1c0718ec4e78d4513e18b6c53a94ac"
        original_filepath = "f66a6b49a23cf3cc842a84d955c0292e7d1c0718ec4e78d4513e18b6c53a94ac"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_4cb020a66fdbc99b0bce2ae24d5684685e2b1e9219fbdfda56b3aace4e8d5f66_a42acfc7f1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, cmd.exe, http://"
        filename = "4cb020a66fdbc99b0bce2ae24d5684685e2b1e9219fbdfda56b3aace4e8d5f66"
        original_filepath = "4cb020a66fdbc99b0bce2ae24d5684685e2b1e9219fbdfda56b3aace4e8d5f66"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "cmd.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_898a7527c065454ba9fad0e36469e12b214f5a3bd40a5ec7fcaf9b75afc34dce_edd26f0088
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "898a7527c065454ba9fad0e36469e12b214f5a3bd40a5ec7fcaf9b75afc34dce"
        original_filepath = "898a7527c065454ba9fad0e36469e12b214f5a3bd40a5ec7fcaf9b75afc34dce"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_1e278cfe8098f3badedd5e497f36753d46d96d81edd1c5bee4fc7bc6380c26b3_68d7fdb716
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, cmd.exe, http://"
        filename = "1e278cfe8098f3badedd5e497f36753d46d96d81edd1c5bee4fc7bc6380c26b3"
        original_filepath = "1e278cfe8098f3badedd5e497f36753d46d96d81edd1c5bee4fc7bc6380c26b3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "cmd.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_7102d6b76a4170203daa939072bba548960db436f85113cd1fca0bb554d95b3c_f53cb4328c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "7102d6b76a4170203daa939072bba548960db436f85113cd1fca0bb554d95b3c"
        original_filepath = "7102d6b76a4170203daa939072bba548960db436f85113cd1fca0bb554d95b3c"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_9d4e18ae979bdf6b57e685896b350b23c428d911eee14af133c3ee7d208f8a82_18791f89da
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, explorer.exe, http://"
        filename = "9d4e18ae979bdf6b57e685896b350b23c428d911eee14af133c3ee7d208f8a82"
        original_filepath = "9d4e18ae979bdf6b57e685896b350b23c428d911eee14af133c3ee7d208f8a82"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".vbs" nocase ascii wide
        $g5 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4,$g5)
}


rule Generic_Suspicious_Strings_a4f59d4d42e42b882068cacf8b70f314add963e2cbbf7a52e70df130bfe23dff_17afe13a2b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, cmd.exe, http://"
        filename = "a4f59d4d42e42b882068cacf8b70f314add963e2cbbf7a52e70df130bfe23dff"
        original_filepath = "a4f59d4d42e42b882068cacf8b70f314add963e2cbbf7a52e70df130bfe23dff"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "cmd.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_6c006620062b40b22d00e7e73a93e6a7fa66ce720093b44b4a0f3ef809fa2716_5e0ef68fe5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, cmd.exe, http://"
        filename = "6c006620062b40b22d00e7e73a93e6a7fa66ce720093b44b4a0f3ef809fa2716"
        original_filepath = "6c006620062b40b22d00e7e73a93e6a7fa66ce720093b44b4a0f3ef809fa2716"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "cmd.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_f34bd1d485de437fe18360d1e850c3fd64415e49d691e610711d8d232071a0b1_6b9a51c0c2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "f34bd1d485de437fe18360d1e850c3fd64415e49d691e610711d8d232071a0b1"
        original_filepath = "f34bd1d485de437fe18360d1e850c3fd64415e49d691e610711d8d232071a0b1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_c377b79732e93f981998817e6f0e8664578b474445ba11b402c70b4b0357caab_187902d183
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "c377b79732e93f981998817e6f0e8664578b474445ba11b402c70b4b0357caab"
        original_filepath = "c377b79732e93f981998817e6f0e8664578b474445ba11b402c70b4b0357caab"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_2e850cb2a1d06d2665601cefd88802ff99905de8bc4ea348ea051d4886e780ee_f5887877e5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "2e850cb2a1d06d2665601cefd88802ff99905de8bc4ea348ea051d4886e780ee"
        original_filepath = "2e850cb2a1d06d2665601cefd88802ff99905de8bc4ea348ea051d4886e780ee"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_bb4e7b0c969895fc9836640b80e2bdc6572d214ba2ee55b77588f8a4eedea5a4_b15e224ec7
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "bb4e7b0c969895fc9836640b80e2bdc6572d214ba2ee55b77588f8a4eedea5a4"
        original_filepath = "bb4e7b0c969895fc9836640b80e2bdc6572d214ba2ee55b77588f8a4eedea5a4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_521b3add2ab6cee5a5cfd53b78e08ef2214946393d2a156c674606528b05763a_b3d047e617
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, explorer.exe, http://"
        filename = "521b3add2ab6cee5a5cfd53b78e08ef2214946393d2a156c674606528b05763a"
        original_filepath = "521b3add2ab6cee5a5cfd53b78e08ef2214946393d2a156c674606528b05763a"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".vbs" nocase ascii wide
        $g5 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4,$g5)
}


rule Generic_Suspicious_Strings_4529f3751102e7c0a6ec05c6a987d0cc5edc08f75f287dd6ac189abbd1282014_558eb6331b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "4529f3751102e7c0a6ec05c6a987d0cc5edc08f75f287dd6ac189abbd1282014"
        original_filepath = "4529f3751102e7c0a6ec05c6a987d0cc5edc08f75f287dd6ac189abbd1282014"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_10b2a7c9329b232e4eef81bac6ba26323e3683ac1f8a99d3a9f8965da5036b6f_2e898546ac
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "10b2a7c9329b232e4eef81bac6ba26323e3683ac1f8a99d3a9f8965da5036b6f"
        original_filepath = "10b2a7c9329b232e4eef81bac6ba26323e3683ac1f8a99d3a9f8965da5036b6f"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_ee41eb21f439b1168ae815ca067ee91d84d6947397d71e214edc6868dbf4f272_fc5c9871d8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "ee41eb21f439b1168ae815ca067ee91d84d6947397d71e214edc6868dbf4f272"
        original_filepath = "ee41eb21f439b1168ae815ca067ee91d84d6947397d71e214edc6868dbf4f272"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_18f4f14857e9b7e3aa1f6f21f21396abd5f421342b7f4d00402a4aff5a538fa1_d362afd1c1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "18f4f14857e9b7e3aa1f6f21f21396abd5f421342b7f4d00402a4aff5a538fa1"
        original_filepath = "18f4f14857e9b7e3aa1f6f21f21396abd5f421342b7f4d00402a4aff5a538fa1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_b4c470be7e434dac0b61919a6b0c5b10cf7a01a22c5403c4540afdb5f2c79fab_ea112138d8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .dll"
        filename = "b4c470be7e434dac0b61919a6b0c5b10cf7a01a22c5403c4540afdb5f2c79fab"
        original_filepath = "b4c470be7e434dac0b61919a6b0c5b10cf7a01a22c5403c4540afdb5f2c79fab"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_blanca_de_nieve_scr_c1c25fe6c4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "blanca de nieve.scr"
        original_filepath = "blanca de nieve.scr"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_bea95bebec95e0893a845f62e832d7cf_exe_vir_aea8e78214
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "bea95bebec95e0893a845f62e832d7cf.exe.ViR"
        original_filepath = "bea95bebec95e0893a845f62e832d7cf.exe.ViR"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_a0d82c3730bc41e267711480c8009883d1412b68977ab175421eabc34e4ef355_4332de8088
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "a0d82c3730bc41e267711480c8009883d1412b68977ab175421eabc34e4ef355"
        original_filepath = "a0d82c3730bc41e267711480c8009883d1412b68977ab175421eabc34e4ef355"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_3564ceb9251eccd82d0c060c0dca83c9812f72c5fb72b5c25443dfd8a780c734_b9f79dd45d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "3564ceb9251eccd82d0c060c0dca83c9812f72c5fb72b5c25443dfd8a780c734"
        original_filepath = "3564ceb9251eccd82d0c060c0dca83c9812f72c5fb72b5c25443dfd8a780c734"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_a7c387b4929f51e38706d8b0f8641e032253b07bc2869a450dfa3df5663d7392_8157807e03
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "a7c387b4929f51e38706d8b0f8641e032253b07bc2869a450dfa3df5663d7392"
        original_filepath = "a7c387b4929f51e38706d8b0f8641e032253b07bc2869a450dfa3df5663d7392"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_bfc63b30624332f4fc2e510f95b69d18dd0241eb0d2fcd33ed2e81b7275ab488_c01e30c3c5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "bfc63b30624332f4fc2e510f95b69d18dd0241eb0d2fcd33ed2e81b7275ab488"
        original_filepath = "bfc63b30624332f4fc2e510f95b69d18dd0241eb0d2fcd33ed2e81b7275ab488"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_8c213b3707b0b042d769fdf543c6e8bd7c127cea6a9bc989eaf241a1505d1ed9_e2cdd93b6e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "8c213b3707b0b042d769fdf543c6e8bd7c127cea6a9bc989eaf241a1505d1ed9"
        original_filepath = "8c213b3707b0b042d769fdf543c6e8bd7c127cea6a9bc989eaf241a1505d1ed9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_e1ba03a10a40aab909b2ba58dcdfd378b4d264f1f4a554b669797bbb8c8ac902_3b4fb4e6f4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "e1ba03a10a40aab909b2ba58dcdfd378b4d264f1f4a554b669797bbb8c8ac902"
        original_filepath = "e1ba03a10a40aab909b2ba58dcdfd378b4d264f1f4a554b669797bbb8c8ac902"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa_exe_17205db91f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .ps1, cmd.exe, .exe"
        filename = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.exe"
        original_filepath = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".ps1" nocase ascii wide
        $g1 = "cmd.exe" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".vbs" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_b275c8978d18832bd3da9975d0f43cbc90e09a99718f4efaf1be7b43db46cf95_418b6f07fb
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "b275c8978d18832bd3da9975d0f43cbc90e09a99718f4efaf1be7b43db46cf95"
        original_filepath = "b275c8978d18832bd3da9975d0f43cbc90e09a99718f4efaf1be7b43db46cf95"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_51b4ef5dc9d26b7a26e214cee90598631e2eaa67_162f3394aa
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "51B4EF5DC9D26B7A26E214CEE90598631E2EAA67"
        original_filepath = "51B4EF5DC9D26B7A26E214CEE90598631E2EAA67"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_file_4571518150a8181b403df4ae7ad54ce8b16ded0c_exe_596cf838cd
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "file_4571518150a8181b403df4ae7ad54ce8b16ded0c.exe"
        original_filepath = "file_4571518150a8181b403df4ae7ad54ce8b16ded0c.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_fake_intel__1__exe_9ec32b35b0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Fake Intel (1).exe"
        original_filepath = "Fake Intel (1).exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_589af04a85dc66ec6b94123142a17cf194decd61f5d79e76183db026010e0d31_bd97580fc5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "589af04a85dc66ec6b94123142a17cf194decd61f5d79e76183db026010e0d31"
        original_filepath = "589af04a85dc66ec6b94123142a17cf194decd61f5d79e76183db026010e0d31"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_9ea5aa00e0a738b74066c61b1d35331170a9e0a84df1cc6cef58fd46a8ec5a2e_56cc5d82a1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "9ea5aa00e0a738b74066c61b1d35331170a9e0a84df1cc6cef58fd46a8ec5a2e"
        original_filepath = "9ea5aa00e0a738b74066c61b1d35331170a9e0a84df1cc6cef58fd46a8ec5a2e"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_a38df3ec8b9fe52a32860cf5756d2fe345badafd7e74466cd349eb32ba5cc339_45ea72f876
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "a38df3ec8b9fe52a32860cf5756d2fe345badafd7e74466cd349eb32ba5cc339"
        original_filepath = "a38df3ec8b9fe52a32860cf5756d2fe345badafd7e74466cd349eb32ba5cc339"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_86bb737bd9a508be2ff9dc0dee7e7c40abea215088c61788a368948f9250fa4c_15d84da14c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "86bb737bd9a508be2ff9dc0dee7e7c40abea215088c61788a368948f9250fa4c"
        original_filepath = "86bb737bd9a508be2ff9dc0dee7e7c40abea215088c61788a368948f9250fa4c"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_rootkit_ex1_e8c5159e9e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "rootkit.ex1"
        original_filepath = "rootkit.ex1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_invoice_2318362983713_823931342io_pdf_exe_3bf9780701
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "invoice_2318362983713_823931342io.pdf.exe"
        original_filepath = "invoice_2318362983713_823931342io.pdf.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_6b91fdb0992ca029c913092db7b4fd94c917c1473953d1ec77c74d030776fe9a_3ab1bceba0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "6b91fdb0992ca029c913092db7b4fd94c917c1473953d1ec77c74d030776fe9a"
        original_filepath = "6b91fdb0992ca029c913092db7b4fd94c917c1473953d1ec77c74d030776fe9a"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_pdfxcview_exe_7ba6de8c94
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "PDFXCview.exe"
        original_filepath = "PDFXCview.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_f897a65b_exe_45df2e2a8a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "F897A65B.exe"
        original_filepath = "F897A65B.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_cfca38c408c95e45cdf797723dc5cdb0d6dadb1b8338a5fda6808ce9a04e6486_fdb9554dfc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "cfca38c408c95e45cdf797723dc5cdb0d6dadb1b8338a5fda6808ce9a04e6486"
        original_filepath = "cfca38c408c95e45cdf797723dc5cdb0d6dadb1b8338a5fda6808ce9a04e6486"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_eqig_unpacked_ex_99fac62760
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "eqig unpacked.ex_"
        original_filepath = "eqig unpacked.ex_"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_zeroaccess_xxx_porn_movie_avi_exe_f33b9e5865
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "ZeroAccess_xxx-porn-movie.avi.exe_"
        original_filepath = "ZeroAccess_xxx-porn-movie.avi.exe_"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_0468127a19daf4c7bc41015c5640fe1f_372a9d44f8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .dll"
        filename = "0468127a19daf4c7bc41015c5640fe1f"
        original_filepath = "0468127a19daf4c7bc41015c5640fe1f"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_cryptowall_bin_1543979c0a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "cryptowall.bin"
        original_filepath = "cryptowall.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_30196c83a1f857d36fde160d55bd4e5b5d50fbb082bd846db295cbe0f9d35cfb_5469569a3a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "30196c83a1f857d36fde160d55bd4e5b5d50fbb082bd846db295cbe0f9d35cfb"
        original_filepath = "30196c83a1f857d36fde160d55bd4e5b5d50fbb082bd846db295cbe0f9d35cfb"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_bc4ae56434b45818f57724f4cd19354a13e5964fd097d1933a30e2e31c9bdfa5_bin_5590462b1d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "bc4ae56434b45818f57724f4cd19354a13e5964fd097d1933a30e2e31c9bdfa5.bin"
        original_filepath = "bc4ae56434b45818f57724f4cd19354a13e5964fd097d1933a30e2e31c9bdfa5.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96_bin_890f6871c3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96.bin"
        original_filepath = "683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_cf65cc6e4b2b0c3f602b16398c8c30c277b8cfaed689fe7cb61b92560d4e5b1b_3138551d7e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "cf65cc6e4b2b0c3f602b16398c8c30c277b8cfaed689fe7cb61b92560d4e5b1b"
        original_filepath = "cf65cc6e4b2b0c3f602b16398c8c30c277b8cfaed689fe7cb61b92560d4e5b1b"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fc085d9be18f3d8d7ca68fbe1d9e29abbe53e7582453f61a9cd65da06961f751_94abb36a9e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "fc085d9be18f3d8d7ca68fbe1d9e29abbe53e7582453f61a9cd65da06961f751"
        original_filepath = "fc085d9be18f3d8d7ca68fbe1d9e29abbe53e7582453f61a9cd65da06961f751"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fd042b14ae659e420a15c3b7db25649d3b21d92c586fe8594f88c21ae6770956_4f87a9c3ca
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "fd042b14ae659e420a15c3b7db25649d3b21d92c586fe8594f88c21ae6770956"
        original_filepath = "fd042b14ae659e420a15c3b7db25649d3b21d92c586fe8594f88c21ae6770956"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_faketruecryptsetup_babd17701cbe876149dc07e68ec7ca4f_977f780c80
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "Potao_FakeTrueCryptSetup_BABD17701CBE876149DC07E68EC7CA4F"
        original_filepath = "Potao_FakeTrueCryptSetup_BABD17701CBE876149DC07E68EC7CA4F"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_potao_faketruecryptsetup_f34b77f7b2233ee6f727d59fb28f438a_f73f4b5f78
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "Potao_FakeTrueCryptSetup_F34B77F7B2233EE6F727D59FB28F438A"
        original_filepath = "Potao_FakeTrueCryptSetup_F34B77F7B2233EE6F727D59FB28F438A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_potao_faketruecryptsetup_83f3ec97a95595ebe40a75e94c98a7bd_630f7fa77c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "Potao_FakeTrueCryptSetup_83F3EC97A95595EBE40A75E94C98A7BD"
        original_filepath = "Potao_FakeTrueCryptSetup_83F3EC97A95595EBE40A75E94C98A7BD"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_potao_faketruecryptsetup_cfc8901fe6a9a8299087bfc73ae8909e_f6b7fcc40d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "Potao_FakeTrueCryptSetup_CFC8901FE6A9A8299087BFC73AE8909E"
        original_filepath = "Potao_FakeTrueCryptSetup_CFC8901FE6A9A8299087BFC73AE8909E"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_potao_faketruecryptextracted_exe_f64704ed25f4c728af996eee3ee85411_807cde008f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, .ps1, cmd.exe"
        filename = "Potao_FakeTrueCryptextracted exe_F64704ED25F4C728AF996EEE3EE85411"
        original_filepath = "Potao_FakeTrueCryptextracted exe_F64704ED25F4C728AF996EEE3EE85411"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = ".ps1" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide
        $g3 = "http://" nocase ascii wide
        $g4 = ".exe" nocase ascii wide
        $g5 = ".vbs" nocase ascii wide
        $g6 = "ftp://" nocase ascii wide
        $g7 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4,$g5,$g6,$g7)
}


rule Generic_Suspicious_Strings_potao_faketruecryptextracted_exe_c1f715ff0afc78af81d215d485cc235c_52f7ddf433
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, .ps1, cmd.exe"
        filename = "Potao_FakeTrueCryptextracted exe_C1F715FF0AFC78AF81D215D485CC235C"
        original_filepath = "Potao_FakeTrueCryptextracted exe_C1F715FF0AFC78AF81D215D485CC235C"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = ".ps1" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide
        $g3 = "http://" nocase ascii wide
        $g4 = ".exe" nocase ascii wide
        $g5 = ".vbs" nocase ascii wide
        $g6 = "ftp://" nocase ascii wide
        $g7 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4,$g5,$g6,$g7)
}


rule Generic_Suspicious_Strings_potao_faketruecryptextracted_exe_7ca6101c2ae4838fbbd7ceb0b2354e43_51ec5f3539
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, .ps1, cmd.exe"
        filename = "Potao_FakeTrueCryptextracted exe_7CA6101C2AE4838FBBD7CEB0B2354E43"
        original_filepath = "Potao_FakeTrueCryptextracted exe_7CA6101C2AE4838FBBD7CEB0B2354E43"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = ".ps1" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide
        $g3 = "http://" nocase ascii wide
        $g4 = ".exe" nocase ascii wide
        $g5 = ".vbs" nocase ascii wide
        $g6 = "ftp://" nocase ascii wide
        $g7 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4,$g5,$g6,$g7)
}


rule Generic_Suspicious_Strings_potao_faketruecryptextracted_exe_b64dbe5817b24d17a0404e9b2606ad96_9427cf1b52
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, .ps1, cmd.exe"
        filename = "Potao_FakeTrueCryptextracted exe_B64DBE5817B24D17A0404E9B2606AD96"
        original_filepath = "Potao_FakeTrueCryptextracted exe_B64DBE5817B24D17A0404E9B2606AD96"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = ".ps1" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide
        $g3 = "http://" nocase ascii wide
        $g4 = ".exe" nocase ascii wide
        $g5 = ".vbs" nocase ascii wide
        $g6 = "ftp://" nocase ascii wide
        $g7 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4,$g5,$g6,$g7)
}


rule Generic_Suspicious_Strings_potao_1stversion_a35e48909a49334a7ebb5448a78dcff9_9dfee919d3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Potao_1stVersion_A35E48909A49334A7EBB5448A78DCFF9"
        original_filepath = "Potao_1stVersion_A35E48909A49334A7EBB5448A78DCFF9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_potao_1stversion_a446ced5db1de877cf78f77741e2a804_737047b4e5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "Potao_1stVersion_A446CED5DB1DE877CF78F77741E2A804"
        original_filepath = "Potao_1stVersion_A446CED5DB1DE877CF78F77741E2A804"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_potao_1stversion_85b0e3264820008a30f17ca19332fa19_6f02630a70
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Potao_1stVersion_85B0E3264820008A30F17CA19332FA19"
        original_filepath = "Potao_1stVersion_85B0E3264820008A30F17CA19332FA19"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_potao_1stversion_3b7d88a069631111d5585b1b10cccc86_33349b31df
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_1stVersion_3B7D88A069631111D5585B1B10CCCC86"
        original_filepath = "Potao_1stVersion_3B7D88A069631111D5585B1B10CCCC86"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_1stversion_0c7183d761f15772b7e9c788be601d29_b589abbedb
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Potao_1stVersion_0C7183D761F15772B7E9C788BE601D29"
        original_filepath = "Potao_1stVersion_0C7183D761F15772B7E9C788BE601D29"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_potao_1stversion_502f35002b1a95f1ae135baff6cff836_e04894627d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_1stVersion_502F35002B1A95F1AE135BAFF6CFF836"
        original_filepath = "Potao_1stVersion_502F35002B1A95F1AE135BAFF6CFF836"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_1stversion_d1658b792dd1569abc27966083f59d44_71e14adaf1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Potao_1stVersion_D1658B792DD1569ABC27966083F59D44"
        original_filepath = "Potao_1stVersion_D1658B792DD1569ABC27966083F59D44"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_potao_1stversion_ac854a3c91d52bfc09605506e76975ae_333f4a4cbc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_1stVersion_AC854A3C91D52BFC09605506E76975AE"
        original_filepath = "Potao_1stVersion_AC854A3C91D52BFC09605506E76975AE"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_1stversion_14634d446471b9e2f55158d9ac09d0b2_0574c1a45d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Potao_1stVersion_14634D446471B9E2F55158D9AC09D0B2"
        original_filepath = "Potao_1stVersion_14634D446471B9E2F55158D9AC09D0B2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_potao_1stversion_d939a05e1e3c9d7b6127d503c025dbc4_c23254c08d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Potao_1stVersion_D939A05E1E3C9D7B6127D503C025DBC4"
        original_filepath = "Potao_1stVersion_D939A05E1E3C9D7B6127D503C025DBC4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_potao_debugversion_bdc9255df5385f534fea83b497c371c8_1ee97490e2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_DebugVersion_BDC9255DF5385F534FEA83B497C371C8"
        original_filepath = "Potao_DebugVersion_BDC9255DF5385F534FEA83B497C371C8"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_debugversion_7263a328f0d47c76b4e103546b648484_4feeb9c856
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_DebugVersion_7263A328F0D47C76B4E103546B648484"
        original_filepath = "Potao_DebugVersion_7263A328F0D47C76B4E103546B648484"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_debugversion_5199fcd031987834ed3121fb316f4970_6ee8318341
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_DebugVersion_5199FCD031987834ED3121FB316F4970"
        original_filepath = "Potao_DebugVersion_5199FCD031987834ED3121FB316F4970"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_dropperswdecoy_5a24a7370f35dbdbb81adf52e769a442_9e0e3fe4ae
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_Dropperswdecoy_5A24A7370F35DBDBB81ADF52E769A442"
        original_filepath = "Potao_Dropperswdecoy_5A24A7370F35DBDBB81ADF52E769A442"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_dropperswdecoy_73e7ee83133a175b815059f1af79ab1b_3844f8f2b8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_Dropperswdecoy_73E7EE83133A175B815059F1AF79AB1B"
        original_filepath = "Potao_Dropperswdecoy_73E7EE83133A175B815059F1AF79AB1B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_dropperswdecoy_b4d909077aa25f31386722e716a5305c_b5dfe3d52d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_Dropperswdecoy_B4D909077AA25F31386722E716A5305C"
        original_filepath = "Potao_Dropperswdecoy_B4D909077AA25F31386722E716A5305C"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_dropperswdecoy_eebbcb1ed5f5606aec296168dee39166_0cd9b5a786
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_Dropperswdecoy_EEBBCB1ED5F5606AEC296168DEE39166"
        original_filepath = "Potao_Dropperswdecoy_EEBBCB1ED5F5606AEC296168DEE39166"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_dropperswdecoy_fc4b285088413127b6d827656b9d0481_d7e33ba831
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_Dropperswdecoy_FC4B285088413127B6D827656B9D0481"
        original_filepath = "Potao_Dropperswdecoy_FC4B285088413127B6D827656B9D0481"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_dropperswdecoy_d755e52ba5658a639c778c22d1a906a3_457b8f3072
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_Dropperswdecoy_D755E52BA5658A639C778C22D1A906A3"
        original_filepath = "Potao_Dropperswdecoy_D755E52BA5658A639C778C22D1A906A3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_droppersfrompostalsites_07e99b2f572b84af5c4504c23f1653bb_3d4f00f82a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_Droppersfrompostalsites_07E99B2F572B84AF5C4504C23F1653BB"
        original_filepath = "Potao_Droppersfrompostalsites_07E99B2F572B84AF5C4504C23F1653BB"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_droppersfrompostalsites_579ad4a596602a10b7cf4659b6b6909d_15a8d40de3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_Droppersfrompostalsites_579AD4A596602A10B7CF4659B6B6909D"
        original_filepath = "Potao_Droppersfrompostalsites_579AD4A596602A10B7CF4659B6B6909D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_droppersfrompostalsites_e64eb8b571f655b744c9154d8032caef_7e8d28d5b4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_Droppersfrompostalsites_E64EB8B571F655B744C9154D8032CAEF"
        original_filepath = "Potao_Droppersfrompostalsites_E64EB8B571F655B744C9154D8032CAEF"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_droppersfrompostalsites_a4b0615cb639607e6905437dd900c059_81e4a8f7c4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_Droppersfrompostalsites_A4B0615CB639607E6905437DD900C059"
        original_filepath = "Potao_Droppersfrompostalsites_A4B0615CB639607E6905437DD900C059"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_droppersfrompostalsites_1927a80cd45f0d27b1ae034c11ddedb0_128cf11a23
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_Droppersfrompostalsites_1927A80CD45F0D27B1AE034C11DDEDB0"
        original_filepath = "Potao_Droppersfrompostalsites_1927A80CD45F0D27B1AE034C11DDEDB0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_droppersfrompostalsites_65f494580c95e10541d1f377c0a7bd49_a8cfe5a2b7
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_Droppersfrompostalsites_65F494580C95E10541D1F377C0A7BD49"
        original_filepath = "Potao_Droppersfrompostalsites_65F494580C95E10541D1F377C0A7BD49"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_usbspreaders_39b67cc6dae5214328022c44f28ced8b_685f893817
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Potao_USBSpreaders_39B67CC6DAE5214328022C44F28CED8B"
        original_filepath = "Potao_USBSpreaders_39B67CC6DAE5214328022C44F28CED8B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_potao_usbspreaders_a427ff7abb17af6cf5fb70c49e9bf4e1_ff7b54d5e9
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_USBSpreaders_A427FF7ABB17AF6CF5FB70C49E9BF4E1"
        original_filepath = "Potao_USBSpreaders_A427FF7ABB17AF6CF5FB70C49E9BF4E1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_usbspreaders_542b00f903f945ad3a9291cb0af73446_b9b3e9872d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_USBSpreaders_542B00F903F945AD3A9291CB0AF73446"
        original_filepath = "Potao_USBSpreaders_542B00F903F945AD3A9291CB0AF73446"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_usbspreaders_76dda7ca15323fd658054e0550149b7b_28218aa06d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_USBSpreaders_76DDA7CA15323FD658054E0550149B7B"
        original_filepath = "Potao_USBSpreaders_76DDA7CA15323FD658054E0550149B7B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_usbspreaders_9179f4683ece450c1ac7a819b32bdb6d_45ab4a67f9
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Potao_USBSpreaders_9179F4683ECE450C1AC7A819B32BDB6D"
        original_filepath = "Potao_USBSpreaders_9179F4683ECE450C1AC7A819B32BDB6D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_potao_usbspreaders_a59053cc3f66e72540634eb7895824ac_736de3d43b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Potao_USBSpreaders_A59053CC3F66E72540634EB7895824AC"
        original_filepath = "Potao_USBSpreaders_A59053CC3F66E72540634EB7895824AC"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_potao_usbspreaders_ae552fc43f1ba8684655d8bf8c6af869_fdd0f93d8e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Potao_USBSpreaders_AE552FC43F1BA8684655D8BF8C6AF869"
        original_filepath = "Potao_USBSpreaders_AE552FC43F1BA8684655D8BF8C6AF869"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_potao_usbspreaders_35724e234f6258e601257fb219db9079_40e4a592de
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_USBSpreaders_35724E234F6258E601257FB219DB9079"
        original_filepath = "Potao_USBSpreaders_35724E234F6258E601257FB219DB9079"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_usbspreaders_2646f7159e1723f089d63e08c8bfaffb_db267e4625
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Potao_USBSpreaders_2646F7159E1723F089D63E08C8BFAFFB"
        original_filepath = "Potao_USBSpreaders_2646F7159E1723F089D63E08C8BFAFFB"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_potao_usbspreaders_609abb2a86c324bbb9ba1e253595e573_37bd9409ef
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Potao_USBSpreaders_609ABB2A86C324BBB9BA1E253595E573"
        original_filepath = "Potao_USBSpreaders_609ABB2A86C324BBB9BA1E253595E573"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_potao_usbspreaders_abb9f4fab64dd7a03574abdd1076b5ea_6c75cffa7f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Potao_USBSpreaders_ABB9F4FAB64DD7A03574ABDD1076B5EA"
        original_filepath = "Potao_USBSpreaders_ABB9F4FAB64DD7A03574ABDD1076B5EA"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_potao_otherdroppers_043f99a875424ca0023a21739dba51ef_25f79b7e86
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_OtherDroppers_043F99A875424CA0023A21739DBA51EF"
        original_filepath = "Potao_OtherDroppers_043F99A875424CA0023A21739DBA51EF"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_otherdroppers_02d438df779affddaf02ca995c60cecb_4cf874486e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_OtherDroppers_02D438DF779AFFDDAF02CA995C60CECB"
        original_filepath = "Potao_OtherDroppers_02D438DF779AFFDDAF02CA995C60CECB"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_otherdroppers_27d74523b182ae630c4e5236897e11f3_18589b40e1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_OtherDroppers_27D74523B182AE630C4E5236897E11F3"
        original_filepath = "Potao_OtherDroppers_27D74523B182AE630C4E5236897E11F3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_otherdroppers_89a3ea3967745e04199ebf222494452e_e887fc5b8f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_OtherDroppers_89A3EA3967745E04199EBF222494452E"
        original_filepath = "Potao_OtherDroppers_89A3EA3967745E04199EBF222494452E"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_otherdroppers_6ba88e8e74b12c914483c026ae92eb42_e28635cdae
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_OtherDroppers_6BA88E8E74B12C914483C026AE92EB42"
        original_filepath = "Potao_OtherDroppers_6BA88E8E74B12C914483C026AE92EB42"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_otherdroppers_1ab8d45656e245aca4e59aa0519f6ba0_83c1397cf8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_OtherDroppers_1AB8D45656E245ACA4E59AA0519F6BA0"
        original_filepath = "Potao_OtherDroppers_1AB8D45656E245ACA4E59AA0519F6BA0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_otherdroppers_38e708fea8016520cb25d3cb933f2244_eb2272297c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_OtherDroppers_38E708FEA8016520CB25D3CB933F2244"
        original_filepath = "Potao_OtherDroppers_38E708FEA8016520CB25D3CB933F2244"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_otherdroppers_360df4c2f2b99052c07e08edbe15ab2c_76b1b656af
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_OtherDroppers_360DF4C2F2B99052C07E08EDBE15AB2C"
        original_filepath = "Potao_OtherDroppers_360DF4C2F2B99052C07E08EDBE15AB2C"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_potao_otherdroppers_11b4e7ea6bae19a29343ae3ff3fb00ca_933c3d7434
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Potao_OtherDroppers_11B4E7EA6BAE19A29343AE3FF3FB00CA"
        original_filepath = "Potao_OtherDroppers_11B4E7EA6BAE19A29343AE3FF3FB00CA"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_44472436a5b46d19cb34fa0e74924e4efc80dfa2ed491773a2852b03853221a2_d7f8c4c433
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, cmd.exe, http://"
        filename = "44472436a5b46d19cb34fa0e74924e4efc80dfa2ed491773a2852b03853221a2"
        original_filepath = "44472436a5b46d19cb34fa0e74924e4efc80dfa2ed491773a2852b03853221a2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "cmd.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_torpig_miniloader_0f82964cf39056402ee2de9193635b34_0eee639fc3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Torpig miniloader_0F82964CF39056402EE2DE9193635B34"
        original_filepath = "Torpig miniloader_0F82964CF39056402EE2DE9193635B34"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_torpig_miniloader_2dacc4556fad30027a384875c8d9d900_f4e859f3ad
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Torpig miniloader_2DACC4556FAD30027A384875C8D9D900"
        original_filepath = "Torpig miniloader_2DACC4556FAD30027A384875C8D9D900"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_torpig_miniloader_c3366b6006acc1f8df875eaa114796f0_f4bb86826f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Torpig miniloader_C3366B6006ACC1F8DF875EAA114796F0"
        original_filepath = "Torpig miniloader_C3366B6006ACC1F8DF875EAA114796F0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_torpig_miniloader_4a3543e6771bc78d32ae46820aed1391_47d87fbbb3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Torpig miniloader_4A3543E6771BC78D32AE46820AED1391"
        original_filepath = "Torpig miniloader_4A3543E6771BC78D32AE46820AED1391"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_torpig_miniloader_011c1ca6030ee091ce7c20cd3aaecfa0_89f2e3df3f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Torpig miniloader_011C1CA6030EE091CE7C20CD3AAECFA0"
        original_filepath = "Torpig miniloader_011C1CA6030EE091CE7C20CD3AAECFA0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_torpig_miniloader_83419eea712182c1054615e4ec7b8cbe_b66f003213
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Torpig miniloader_83419EEA712182C1054615E4EC7B8CBE"
        original_filepath = "Torpig miniloader_83419EEA712182C1054615E4EC7B8CBE"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_torpig_miniloader_809910f29aa63913efa76d00fa8c7c0b_70188c4e6c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Torpig miniloader_809910F29AA63913EFA76D00FA8C7C0B"
        original_filepath = "Torpig miniloader_809910F29AA63913EFA76D00FA8C7C0B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_torpig_miniloader_87851480deb151d3a0aa9a425fd74e61_9b0d226b1d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Torpig miniloader_87851480DEB151D3A0AA9A425FD74E61"
        original_filepath = "Torpig miniloader_87851480DEB151D3A0AA9A425FD74E61"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_dumped_dll_1b5c4f63b5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "dumped.dll"
        original_filepath = "dumped.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_08fd696873ed9df967a991fb397fe11e54a4367c81c6660575e1413b440c3af2_6cec18c696
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "08fd696873ed9df967a991fb397fe11e54a4367c81c6660575e1413b440c3af2"
        original_filepath = "08fd696873ed9df967a991fb397fe11e54a4367c81c6660575e1413b440c3af2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_file_4571518150a8181b403df4ae7ad54ce8b16ded0c_exe_488ac5c69a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "file_4571518150a8181b403df4ae7ad54ce8b16ded0c.exe"
        original_filepath = "file_4571518150a8181b403df4ae7ad54ce8b16ded0c.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_aed230b6b772aeb5c25e9336086e9dd4d6081d3efc205f9f9214b51f2f8c3655_311504e595
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "aed230b6b772aeb5c25e9336086e9dd4d6081d3efc205f9f9214b51f2f8c3655"
        original_filepath = "aed230b6b772aeb5c25e9336086e9dd4d6081d3efc205f9f9214b51f2f8c3655"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_payload_dll_7e76d32558
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "payload.dll"
        original_filepath = "payload.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_win32_klez_exe_41414130b0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "Win32_klez.exe"
        original_filepath = "Win32_klez.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_78201fd42dfc65e94774d8a9b87293c19044ad93edf59d3ff6846766ed4c3e2e_d42a4a4b4f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "78201fd42dfc65e94774d8a9b87293c19044ad93edf59d3ff6846766ed4c3e2e"
        original_filepath = "78201fd42dfc65e94774d8a9b87293c19044ad93edf59d3ff6846766ed4c3e2e"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_64442cceb7d618e70c62d461cfaafdb8e653b8d98ac4765a6b3d8fd1ea3bce15_537d6f9541
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "64442cceb7d618e70c62d461cfaafdb8e653b8d98ac4765a6b3d8fd1ea3bce15"
        original_filepath = "64442cceb7d618e70c62d461cfaafdb8e653b8d98ac4765a6b3d8fd1ea3bce15"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_01259a104a0199b794b0c61fcfc657eb766b2caeae68d5c6b164a53a97874257_5529c6c0dc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "01259a104a0199b794b0c61fcfc657eb766b2caeae68d5c6b164a53a97874257"
        original_filepath = "01259a104a0199b794b0c61fcfc657eb766b2caeae68d5c6b164a53a97874257"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_3bedb4bdb17718fda1edd1a8fa4289dc61fdda598474b5648414e4565e88ecd5_d77a41d759
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "3bedb4bdb17718fda1edd1a8fa4289dc61fdda598474b5648414e4565e88ecd5"
        original_filepath = "3bedb4bdb17718fda1edd1a8fa4289dc61fdda598474b5648414e4565e88ecd5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_d30f306d4d866a07372b94f7657a7a2b0500137fe7ef51678d0ef4249895c2c5_e02c15de55
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "d30f306d4d866a07372b94f7657a7a2b0500137fe7ef51678d0ef4249895c2c5"
        original_filepath = "d30f306d4d866a07372b94f7657a7a2b0500137fe7ef51678d0ef4249895c2c5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_323canon_exe_worm_vobfus_sm01_5698284edd
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "323CANON.EXE_WORM_VOBFUS.SM01"
        original_filepath = "323CANON.EXE_WORM_VOBFUS.SM01"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_decrypted_rkctl_win32_dll_ee39763155
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "decrypted_rkctl_Win32.dll"
        original_filepath = "decrypted_rkctl_Win32.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_stabuniq_f31b797831b36a4877aa0fd173a7a4a2_628050dfda
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "stabuniq_F31B797831B36A4877AA0FD173A7A4A2"
        original_filepath = "stabuniq_F31B797831B36A4877AA0FD173A7A4A2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_brutal_gift_5_0b7_db32d2d73f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "Brutal Gift 5.0b7"
        original_filepath = "Brutal Gift 5.0b7"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_rbssl_rbx_0_132_dylib_f48a4b00e5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "RBSSL.rbx_0.132.dylib"
        original_filepath = "RBSSL.rbx_0.132.dylib"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_w32_elkern_4926_exe_fdc73fa261
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "W32.Elkern.4926.exe"
        original_filepath = "W32.Elkern.4926.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_b14299fd4d1cbfb4cc7486d978398214_e0dc9c4987
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "B14299FD4D1CBFB4CC7486D978398214"
        original_filepath = "B14299FD4D1CBFB4CC7486D978398214"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_eefa052da01c3faa1d1f516ddfefa8ceb8a5185bb9b5368142ffdf839aea4506_85876385f5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "eefa052da01c3faa1d1f516ddfefa8ceb8a5185bb9b5368142ffdf839aea4506"
        original_filepath = "eefa052da01c3faa1d1f516ddfefa8ceb8a5185bb9b5368142ffdf839aea4506"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_decrypted_inj_services_x64_dll_11829da0e9
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "decrypted_inj_services_x64.dll"
        original_filepath = "decrypted_inj_services_x64.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_1b893ca3b782679b1e5d1afecb75be7bcc145b5da21a30f6c18dbddc9c6de4e7_96b078ad62
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "1b893ca3b782679b1e5d1afecb75be7bcc145b5da21a30f6c18dbddc9c6de4e7"
        original_filepath = "1b893ca3b782679b1e5d1afecb75be7bcc145b5da21a30f6c18dbddc9c6de4e7"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_win32_darktequila_exe_f360925ca2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Win32.DarkTequila.exe"
        original_filepath = "Win32.DarkTequila.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_eqig_ex_0f483f3318
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "eqig.ex_"
        original_filepath = "eqig.ex_"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_ydrhrp_one_dll_56b80a9604
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "ydrHrp_One.dll"
        original_filepath = "ydrHrp_One.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_8dfaa1f579de14bca8bb27c54a57dd87646a835969766ca9ddb81ecd9329f4e4_41e866c4b1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "8dfaa1f579de14bca8bb27c54a57dd87646a835969766ca9ddb81ecd9329f4e4"
        original_filepath = "8dfaa1f579de14bca8bb27c54a57dd87646a835969766ca9ddb81ecd9329f4e4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_50414f60d7e24d25f9ebb68f99d67a46e8b12458474ac503b6e0d0562075a985_50eaca1ec1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "50414f60d7e24d25f9ebb68f99d67a46e8b12458474ac503b6e0d0562075a985"
        original_filepath = "50414f60d7e24d25f9ebb68f99d67a46e8b12458474ac503b6e0d0562075a985"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_shmgr_dll_ad6590e0df575228911852b1e401d46e_064b2f725b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "shmgr.dll_AD6590E0DF575228911852B1E401D46E"
        original_filepath = "shmgr.dll_AD6590E0DF575228911852B1E401D46E"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_d43c10a2c983049d4a32487ab1e8fe7727646052228554e0112f6651f4833d2c_d5a90bc4b6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "d43c10a2c983049d4a32487ab1e8fe7727646052228554e0112f6651f4833d2c"
        original_filepath = "d43c10a2c983049d4a32487ab1e8fe7727646052228554e0112f6651f4833d2c"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_4a8b7cfb2e33aa079ba51166591c7a210ad8b3c7c7f242fccf8cb2e71e8e40d5_13f7cc77af
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "4a8b7cfb2e33aa079ba51166591c7a210ad8b3c7c7f242fccf8cb2e71e8e40d5"
        original_filepath = "4a8b7cfb2e33aa079ba51166591c7a210ad8b3c7c7f242fccf8cb2e71e8e40d5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_1874b20e3e802406c594341699c5863a2c07c4c79cf762888ee28142af83547f_0fb761018a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "1874b20e3e802406c594341699c5863a2c07c4c79cf762888ee28142af83547f"
        original_filepath = "1874b20e3e802406c594341699c5863a2c07c4c79cf762888ee28142af83547f"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_64ab1c1b19682026900d060b969ab3c3ab860988733b7e7bf3ba78a4ea0340b9_e88d32e669
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "64ab1c1b19682026900d060b969ab3c3ab860988733b7e7bf3ba78a4ea0340b9"
        original_filepath = "64ab1c1b19682026900d060b969ab3c3ab860988733b7e7bf3ba78a4ea0340b9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_011fe9974f07cb12ba30e69e7a84e5cb489ce14a81bced59a11031fc0c3681b7_05a62f2eaf
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "011fe9974f07cb12ba30e69e7a84e5cb489ce14a81bced59a11031fc0c3681b7"
        original_filepath = "011fe9974f07cb12ba30e69e7a84e5cb489ce14a81bced59a11031fc0c3681b7"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc_70a3e38842
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, cmd.exe, explorer.exe"
        filename = "31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc"
        original_filepath = "31eb1de7e840a342fd468e558e5ab627bcb4c542a8fe01aec4d5ba01d539a0fc"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "cmd.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = "http://" nocase ascii wide
        $g4 = ".exe" nocase ascii wide
        $g5 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4,$g5)
}


rule Generic_Suspicious_Strings_12534f7014b3338d8f9f86ff1bbeacf8c80ad03f1d0d19077ff0e406c58b5133_0222cfd6bb
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "12534f7014b3338d8f9f86ff1bbeacf8c80ad03f1d0d19077ff0e406c58b5133"
        original_filepath = "12534f7014b3338d8f9f86ff1bbeacf8c80ad03f1d0d19077ff0e406c58b5133"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_86140e6770fbd0cc6988f025d52bb4f59c0d78213c75451b42c9f812fe1a9354_335c01a8e8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "86140e6770fbd0cc6988f025d52bb4f59c0d78213c75451b42c9f812fe1a9354"
        original_filepath = "86140e6770fbd0cc6988f025d52bb4f59c0d78213c75451b42c9f812fe1a9354"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_66b7983831cbb952ceeb1ffff608880f1805f1df0b062cef4c17b258b7f478ce_6f00bff489
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "66b7983831cbb952ceeb1ffff608880f1805f1df0b062cef4c17b258b7f478ce"
        original_filepath = "66b7983831cbb952ceeb1ffff608880f1805f1df0b062cef4c17b258b7f478ce"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_8445aa54adf4d666e65084909a7b989a190ec6eca2844546c2e99a8cfb832fad_15678383e0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "8445aa54adf4d666e65084909a7b989a190ec6eca2844546c2e99a8cfb832fad"
        original_filepath = "8445aa54adf4d666e65084909a7b989a190ec6eca2844546c2e99a8cfb832fad"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71_b6ac6ee9ac
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71"
        original_filepath = "3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_8129bd45466c2676b248c08bb0efcd9ccc8b684abf3435e290fcf4739c0a439f_053fc2ee7a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, .exe, .dll"
        filename = "8129bd45466c2676b248c08bb0efcd9ccc8b684abf3435e290fcf4739c0a439f"
        original_filepath = "8129bd45466c2676b248c08bb0efcd9ccc8b684abf3435e290fcf4739c0a439f"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = ".exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_b000a0095a8fda38227103f253b6d79134b862a83df50315d7d9c5b537fd994b_7e81050a18
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "b000a0095a8fda38227103f253b6d79134b862a83df50315d7d9c5b537fd994b"
        original_filepath = "b000a0095a8fda38227103f253b6d79134b862a83df50315d7d9c5b537fd994b"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_a08e0d1839b86d0d56a52d07123719211a3c3d43a6aa05aa34531a72ed1207dc_df79356ef0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "a08e0d1839b86d0d56a52d07123719211a3c3d43a6aa05aa34531a72ed1207dc"
        original_filepath = "a08e0d1839b86d0d56a52d07123719211a3c3d43a6aa05aa34531a72ed1207dc"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_shylock_skype_8fbeb78b06985c3188562e2f1b82d57d_8a292c6994
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Shylock-skype_8FBEB78B06985C3188562E2F1B82D57D"
        original_filepath = "Shylock-skype_8FBEB78B06985C3188562E2F1B82D57D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_df5a394ad60512767d375647dbb82994_7b6e867253
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "DF5A394AD60512767D375647DBB82994"
        original_filepath = "DF5A394AD60512767D375647DBB82994"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_9bd32162e0a50f8661fd19e3b26ff65868ab5ea636916bd54c244b0148bd9c1b_03c3e9b148
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "9bd32162e0a50f8661fd19e3b26ff65868ab5ea636916bd54c244b0148bd9c1b"
        original_filepath = "9bd32162e0a50f8661fd19e3b26ff65868ab5ea636916bd54c244b0148bd9c1b"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_eac776c3c83c9db1a770ffaf6df9e94611c8293cbd41cb9257148603b8f2be0b_4184a2f59e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "eac776c3c83c9db1a770ffaf6df9e94611c8293cbd41cb9257148603b8f2be0b"
        original_filepath = "eac776c3c83c9db1a770ffaf6df9e94611c8293cbd41cb9257148603b8f2be0b"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_2a3b92f6180367306d750e59c9b6446b_461d985fe1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "2a3b92f6180367306d750e59c9b6446b"
        original_filepath = "2a3b92f6180367306d750e59c9b6446b"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = "rundll32.exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_decrypted_inj_snake_win32_dll_3af587665f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "decrypted_inj_snake_Win32.dll"
        original_filepath = "decrypted_inj_snake_Win32.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_3f2781d44c71a2c0509173118dd97e5196db510a65c9f659dc2366fa315fe5e5_5cebe75159
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "3f2781d44c71a2c0509173118dd97e5196db510a65c9f659dc2366fa315fe5e5"
        original_filepath = "3f2781d44c71a2c0509173118dd97e5196db510a65c9f659dc2366fa315fe5e5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_05455efecab4a7931fa53a3c2008d04fc6b539c5e8f451f19b617bd9b3ebcd83_a5d9d141a4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "05455efecab4a7931fa53a3c2008d04fc6b539c5e8f451f19b617bd9b3ebcd83"
        original_filepath = "05455efecab4a7931fa53a3c2008d04fc6b539c5e8f451f19b617bd9b3ebcd83"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_grayfish_9b1ca66aab784dc5f1dfe635d8f8a904_6702247dba
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "GrayFish_9B1CA66AAB784DC5F1DFE635D8F8A904"
        original_filepath = "GrayFish_9B1CA66AAB784DC5F1DFE635D8F8A904"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_aaa__xe_303e6ed4ff
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "AAA._xe"
        original_filepath = "AAA._xe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_119_executable_493d1cea50
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "119.executable"
        original_filepath = "119.executable"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_11fb52c96853e12f011b7b7894e9884e56eb5522_f0ecb68c33
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "11fb52c96853e12f011b7b7894e9884e56eb5522"
        original_filepath = "11fb52c96853e12f011b7b7894e9884e56eb5522"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_grok_24a6ec8ebf9c0867ed1c097f4a653b8d_31ee5a7ff8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe"
        filename = "GROK_24A6EC8EBF9C0867ED1C097F4A653B8D"
        original_filepath = "GROK_24A6EC8EBF9C0867ED1C097F4A653B8D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_ef47aaf4e964e1e1b7787c480e60a744550de847618510d2bf54bbc5bda57470_dc3702e72c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "ef47aaf4e964e1e1b7787c480e60a744550de847618510d2bf54bbc5bda57470"
        original_filepath = "ef47aaf4e964e1e1b7787c480e60a744550de847618510d2bf54bbc5bda57470"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_1d34d800aa3320dc17a5786f8eec16ee_3adecf1138
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "1D34D800AA3320DC17A5786F8EEC16EE"
        original_filepath = "1D34D800AA3320DC17A5786F8EEC16EE"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_8390e210162d9b14d5b0b1ef9746c16853aa2d29d1dfc4eab6a051885e0333ed_f78fe70561
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "8390e210162d9b14d5b0b1ef9746c16853aa2d29d1dfc4eab6a051885e0333ed"
        original_filepath = "8390e210162d9b14d5b0b1ef9746c16853aa2d29d1dfc4eab6a051885e0333ed"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_5663b2d4a4aec55d5d6fb507e3fdcb92ffc978d411de68b084c37f86af6d2e19_3eb1466e53
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "5663b2d4a4aec55d5d6fb507e3fdcb92ffc978d411de68b084c37f86af6d2e19"
        original_filepath = "5663b2d4a4aec55d5d6fb507e3fdcb92ffc978d411de68b084c37f86af6d2e19"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_triplefantasy_9180d5affe1e5df0717d7385e7f54386_1c72a185aa
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "TripleFantasy_9180D5AFFE1E5DF0717D7385E7F54386"
        original_filepath = "TripleFantasy_9180D5AFFE1E5DF0717D7385E7F54386"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_5d40615701c48a122e44f831e7c8643d07765629a83b15d090587f469c77693d_1da745207f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, .exe, .dll"
        filename = "5d40615701c48a122e44f831e7c8643d07765629a83b15d090587f469c77693d"
        original_filepath = "5d40615701c48a122e44f831e7c8643d07765629a83b15d090587f469c77693d"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = ".exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_c460fc0d4fdaf5c68623e18de106f1c3601d7bd6ba80ddad86c10fd6ea123850_e5133df448
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, .exe, .dll"
        filename = "c460fc0d4fdaf5c68623e18de106f1c3601d7bd6ba80ddad86c10fd6ea123850"
        original_filepath = "c460fc0d4fdaf5c68623e18de106f1c3601d7bd6ba80ddad86c10fd6ea123850"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = ".exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_8b758ccdfbfa5ff3a0b67b2063c2397531cf0f7b3d278298da76528f443779e9_dd6cd7bf6f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "8b758ccdfbfa5ff3a0b67b2063c2397531cf0f7b3d278298da76528f443779e9"
        original_filepath = "8b758ccdfbfa5ff3a0b67b2063c2397531cf0f7b3d278298da76528f443779e9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_b81b10bdf4f29347979ea8a1715cbfc560e3452ba9fffcc33cd19a3dc47083a4_44d3be08f3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "b81b10bdf4f29347979ea8a1715cbfc560e3452ba9fffcc33cd19a3dc47083a4"
        original_filepath = "b81b10bdf4f29347979ea8a1715cbfc560e3452ba9fffcc33cd19a3dc47083a4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_f5ca1277b7fde07880a691f7f3794a11980a408c510442fde486793ee56ad291_d5f03fc429
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "f5ca1277b7fde07880a691f7f3794a11980a408c510442fde486793ee56ad291"
        original_filepath = "f5ca1277b7fde07880a691f7f3794a11980a408c510442fde486793ee56ad291"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_win32_sofacy_a_9cfb9c6a22
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Win32.Sofacy.A"
        original_filepath = "Win32.Sofacy.A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_8d7be9ed64811ea7986d788a75cbc4ca166702c6ff68c33873270d7c6597f5db_d38ee52b67
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "8d7be9ed64811ea7986d788a75cbc4ca166702c6ff68c33873270d7c6597f5db"
        original_filepath = "8d7be9ed64811ea7986d788a75cbc4ca166702c6ff68c33873270d7c6597f5db"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_e77306d2e3d656fa04856f658885803243aef204760889ca2c09fbe9ba36581d_868df2989a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "e77306d2e3d656fa04856f658885803243aef204760889ca2c09fbe9ba36581d"
        original_filepath = "e77306d2e3d656fa04856f658885803243aef204760889ca2c09fbe9ba36581d"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_c0cf8e008fbfa0cb2c61d968057b4a077d62f64d7320769982d28107db370513_a07f2bbad0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "c0cf8e008fbfa0cb2c61d968057b4a077d62f64d7320769982d28107db370513"
        original_filepath = "c0cf8e008fbfa0cb2c61d968057b4a077d62f64d7320769982d28107db370513"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_f77db63cbed98391027f2525c14e161f_6cd0dd8657
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "F77DB63CBED98391027F2525C14E161F"
        original_filepath = "F77DB63CBED98391027F2525C14E161F"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_9c17f267f79597ee01515f5ef925375d8a19844830cc46917a3d1b5bcb0ba4c3_bc821c2aff
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "9c17f267f79597ee01515f5ef925375d8a19844830cc46917a3d1b5bcb0ba4c3"
        original_filepath = "9c17f267f79597ee01515f5ef925375d8a19844830cc46917a3d1b5bcb0ba4c3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_23eeb35780faf868a7b17b8e8da364d71bae0e46c1ababddddddecbdbd2c2c64_be85087e0c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "23eeb35780faf868a7b17b8e8da364d71bae0e46c1ababddddddecbdbd2c2c64"
        original_filepath = "23eeb35780faf868a7b17b8e8da364d71bae0e46c1ababddddddecbdbd2c2c64"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_6674ffe375f8ab54cfa2a276e4a39b414cf327e0b00733c215749e8a94385c63_8c3c5f765b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, .dll"
        filename = "6674ffe375f8ab54cfa2a276e4a39b414cf327e0b00733c215749e8a94385c63"
        original_filepath = "6674ffe375f8ab54cfa2a276e4a39b414cf327e0b00733c215749e8a94385c63"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_b12c7d57507286bbbe36d7acf9b34c22c96606ffd904e3c23008399a4a50c047_234abe3822
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "b12c7d57507286bbbe36d7acf9b34c22c96606ffd904e3c23008399a4a50c047"
        original_filepath = "b12c7d57507286bbbe36d7acf9b34c22c96606ffd904e3c23008399a4a50c047"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_signed_exe_bbacc3d6af
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "signed.exe"
        original_filepath = "signed.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_malware_exe_a38d2348a1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe"
        filename = "malware.exe"
        original_filepath = "malware.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_0581a38d1dc61e0da50722cb6c4253d603cc7965c87e1e42db548460d4abdcae_bin_2781940cf0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "0581a38d1dc61e0da50722cb6c4253d603cc7965c87e1e42db548460d4abdcae.bin"
        original_filepath = "0581a38d1dc61e0da50722cb6c4253d603cc7965c87e1e42db548460d4abdcae.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_malware_exe_336ca54b90
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "malware.exe"
        original_filepath = "malware.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_decrypted_rkctl_x64_dll_64ad8dae08
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "decrypted_rkctl_x64.dll"
        original_filepath = "decrypted_rkctl_x64.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_7249b1a5082c9d9654d9fac3bb5e965ea23e395554d3351b77dd4f29677426fe_4c568a1228
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "7249b1a5082c9d9654d9fac3bb5e965ea23e395554d3351b77dd4f29677426fe"
        original_filepath = "7249b1a5082c9d9654d9fac3bb5e965ea23e395554d3351b77dd4f29677426fe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_d8fdcdaad652c19f4f4676cd2f89ae834dbc19e2759a206044b18601875f2726_77041642d8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "d8fdcdaad652c19f4f4676cd2f89ae834dbc19e2759a206044b18601875f2726"
        original_filepath = "d8fdcdaad652c19f4f4676cd2f89ae834dbc19e2759a206044b18601875f2726"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fixklez_com_93e6169bb6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "FixKlez.com"
        original_filepath = "FixKlez.com"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_1002_exe_4af127a42c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "1002.exe"
        original_filepath = "1002.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_f1e546fe9d51dc96eb766ec61269edfb_7f35b2bd2e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "F1E546FE9D51DC96EB766EC61269EDFB"
        original_filepath = "F1E546FE9D51DC96EB766EC61269EDFB"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_f1d903251db466d35533c28e3c032b7212aa43c8d64ddf8c5521b43031e69e1e_2ac17fbc1d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "f1d903251db466d35533c28e3c032b7212aa43c8d64ddf8c5521b43031e69e1e"
        original_filepath = "f1d903251db466d35533c28e3c032b7212aa43c8d64ddf8c5521b43031e69e1e"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_81cdbe905392155a1ba8b687a02e65d611b60aac938e470a76ef518e8cffd74d_1190df341e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, explorer.exe, http://"
        filename = "81cdbe905392155a1ba8b687a02e65d611b60aac938e470a76ef518e8cffd74d"
        original_filepath = "81cdbe905392155a1ba8b687a02e65d611b60aac938e470a76ef518e8cffd74d"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = "ftp://" nocase ascii wide
        $g5 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4,$g5)
}


rule Generic_Suspicious_Strings_52fe506928b0262f10de31e783af8540b6a0b232b15749d647847488acd0e17a_e126477ea3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, explorer.exe, http://"
        filename = "52fe506928b0262f10de31e783af8540b6a0b232b15749d647847488acd0e17a"
        original_filepath = "52fe506928b0262f10de31e783af8540b6a0b232b15749d647847488acd0e17a"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = "ftp://" nocase ascii wide
        $g5 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4,$g5)
}


rule Generic_Suspicious_Strings_e049d8f69ddee0c2d360c27b98fa9e61b7202bb0d3884dd3ca63f8aa288422dc_e203cbf952
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "e049d8f69ddee0c2d360c27b98fa9e61b7202bb0d3884dd3ca63f8aa288422dc"
        original_filepath = "e049d8f69ddee0c2d360c27b98fa9e61b7202bb0d3884dd3ca63f8aa288422dc"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_5001793790939009355ba841610412e0f8d60ef5461f2ea272ccf4fd4c83b823_7c21537341
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "5001793790939009355ba841610412e0f8d60ef5461f2ea272ccf4fd4c83b823"
        original_filepath = "5001793790939009355ba841610412e0f8d60ef5461f2ea272ccf4fd4c83b823"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_counter_exe_fd1632d7af
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "counter.exe"
        original_filepath = "counter.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_win32_unknown_spectremeltdown_858525ce45
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Win32.Unknown_SpectreMeltdown"
        original_filepath = "Win32.Unknown_SpectreMeltdown"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_fix_nimda_exe_bc5127e9e3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, explorer.exe"
        filename = "FIX_NIMDA.exe"
        original_filepath = "FIX_NIMDA.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_hv46va_dll_76f2abe6f2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "hV46VA.dll"
        original_filepath = "hV46VA.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_lwxtbjqm_cpp_b636c352f3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "lwxtbjqm.cpp"
        original_filepath = "lwxtbjqm.cpp"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_ad8965e531424cb34120bf0c1b4b98d4ab769bed534d9a36583364e9572332fa_d2784b0a76
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "ad8965e531424cb34120bf0c1b4b98d4ab769bed534d9a36583364e9572332fa"
        original_filepath = "ad8965e531424cb34120bf0c1b4b98d4ab769bed534d9a36583364e9572332fa"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_yfoye_dump_exe_b1fa86bb96
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "yfoye_dump.exe"
        original_filepath = "yfoye_dump.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_03641e5632673615f23b2a8325d7355c4499a40f47b6ae094606a73c56e24ad0_dcb882a807
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "03641e5632673615f23b2a8325d7355c4499a40f47b6ae094606a73c56e24ad0"
        original_filepath = "03641e5632673615f23b2a8325d7355c4499a40f47b6ae094606a73c56e24ad0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_ransomware_unnamed_0_exe_677a0644f1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Ransomware.Unnamed_0.exe"
        original_filepath = "Ransomware.Unnamed_0.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_bb8e52face5b076cc890bbfaaf4bb73e_0208452748
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "bb8e52face5b076cc890bbfaaf4bb73e"
        original_filepath = "bb8e52face5b076cc890bbfaaf4bb73e"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_hui_ex1_079c131d92
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "hui.ex1"
        original_filepath = "hui.ex1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_027cc450ef5f8c5f653329641ec1fed9_exe_9cf43e0371
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like cmd.exe, http://, .exe"
        filename = "027cc450ef5f8c5f653329641ec1fed9.exe"
        original_filepath = "027cc450ef5f8c5f653329641ec1fed9.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "cmd.exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".vbs" nocase ascii wide
        $g4 = "rundll32.exe" nocase ascii wide
        $g5 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4,$g5)
}


rule Generic_Suspicious_Strings_b96bd6bbf0e3f4f98b606a2ab5db4a69_adb0737dce
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "b96bd6bbf0e3f4f98b606a2ab5db4a69"
        original_filepath = "b96bd6bbf0e3f4f98b606a2ab5db4a69"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_60c01a897dd8d60d3fea002ed3a4b764_49a6fcbe5c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "60C01A897DD8D60D3FEA002ED3A4B764"
        original_filepath = "60C01A897DD8D60D3FEA002ED3A4B764"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_win32_wannacry_exe_f6d810d8d4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, .ps1, cmd.exe"
        filename = "Win32.Wannacry.exe"
        original_filepath = "Win32.Wannacry.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = ".ps1" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide
        $g3 = "http://" nocase ascii wide
        $g4 = ".exe" nocase ascii wide
        $g5 = ".vbs" nocase ascii wide
        $g6 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4,$g5,$g6)
}


rule Generic_Suspicious_Strings_win32_exe_363ed87924
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "win32.exe"
        original_filepath = "win32.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_54c6107c09f591a11e5e347acad5b47c70ff5d5641a01647854643e007177dab_df92aee02c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://"
        filename = "54c6107c09f591a11e5e347acad5b47c70ff5d5641a01647854643e007177dab"
        original_filepath = "54c6107c09f591a11e5e347acad5b47c70ff5d5641a01647854643e007177dab"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_hostr_exe_d8514e708b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "hostr.exe"
        original_filepath = "hostr.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_9a0e765eecc5433af3dc726206ecc56e_9c2a96d4d8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "9A0E765EECC5433AF3DC726206ECC56E"
        original_filepath = "9A0E765EECC5433AF3DC726206ECC56E"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_installbc201401_exe_b66b228705
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "InstallBC201401.exe"
        original_filepath = "InstallBC201401.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_0d7d4dc173c88c4f72c8f9f419ae8473d044f4b3e8f32e4a0f34fe4bbc698776_35bfcd0364
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, cmd.exe, explorer.exe"
        filename = "0d7d4dc173c88c4f72c8f9f419ae8473d044f4b3e8f32e4a0f34fe4bbc698776"
        original_filepath = "0d7d4dc173c88c4f72c8f9f419ae8473d044f4b3e8f32e4a0f34fe4bbc698776"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "cmd.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = "http://" nocase ascii wide
        $g4 = ".exe" nocase ascii wide
        $g5 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4,$g5)
}


rule Generic_Suspicious_Strings_084a220ba90622cc223b93f32130e9f2d072679f66d1816775bf14832d492b8a_80d8973549
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "084a220ba90622cc223b93f32130e9f2d072679f66d1816775bf14832d492b8a"
        original_filepath = "084a220ba90622cc223b93f32130e9f2d072679f66d1816775bf14832d492b8a"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_260ebbf392498d00d767a5c5ba695e1a124057c1c01fff2ae76db7853fe4255b_c3195d88fc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "260ebbf392498d00d767a5c5ba695e1a124057c1c01fff2ae76db7853fe4255b"
        original_filepath = "260ebbf392498d00d767a5c5ba695e1a124057c1c01fff2ae76db7853fe4255b"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = "ftp://" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_9cd5127ef31da0e8a4e36292f2af5a9ec1de3b294da367d7c05786fe2d5de44f_bf48d757bc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "9cd5127ef31da0e8a4e36292f2af5a9ec1de3b294da367d7c05786fe2d5de44f"
        original_filepath = "9cd5127ef31da0e8a4e36292f2af5a9ec1de3b294da367d7c05786fe2d5de44f"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_ee21378abf78e31d79f9170e76d01ffb74aa65ce885937fb5bc1e71dff68627d_0321b79301
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "ee21378abf78e31d79f9170e76d01ffb74aa65ce885937fb5bc1e71dff68627d"
        original_filepath = "ee21378abf78e31d79f9170e76d01ffb74aa65ce885937fb5bc1e71dff68627d"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_222d68c03d96d230bc3829e86be8821f32960375b70388028a705a4986b8d9c6_fae70adfc4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "222d68c03d96d230bc3829e86be8821f32960375b70388028a705a4986b8d9c6"
        original_filepath = "222d68c03d96d230bc3829e86be8821f32960375b70388028a705a4986b8d9c6"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_30964541572f322a20b541e2e5eedaa5f20f118995d4b9d4c5d5dda98f09f3d2_7e4697d438
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like explorer.exe, http://, .exe"
        filename = "30964541572f322a20b541e2e5eedaa5f20f118995d4b9d4c5d5dda98f09f3d2"
        original_filepath = "30964541572f322a20b541e2e5eedaa5f20f118995d4b9d4c5d5dda98f09f3d2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "explorer.exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = "rundll32.exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_388f5bc2f088769b361dfe8a45f0d5237c4580b287612422a03babe6994339ff_456c794ba6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "388f5bc2f088769b361dfe8a45f0d5237c4580b287612422a03babe6994339ff"
        original_filepath = "388f5bc2f088769b361dfe8a45f0d5237c4580b287612422a03babe6994339ff"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_a880d7c77491fcc6f9c88bae064f075a339e6753ef9fa9410b928565887c13b7_d1fa67b103
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "a880d7c77491fcc6f9c88bae064f075a339e6753ef9fa9410b928565887c13b7"
        original_filepath = "a880d7c77491fcc6f9c88bae064f075a339e6753ef9fa9410b928565887c13b7"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_implantbigbang_bin_6b7dbeb316
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .vbs, .dll"
        filename = "ImplantBigBang.bin"
        original_filepath = "ImplantBigBang.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".vbs" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_1003_exe_f2bf611b18
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "1003.exe"
        original_filepath = "1003.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_301210d5557d9ba34f401d3ef7a7276f_c85964e3ee
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "301210D5557D9BA34F401D3EF7A7276F"
        original_filepath = "301210D5557D9BA34F401D3EF7A7276F"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_win32_duqu_0cd27466d4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "win32.duqu"
        original_filepath = "win32.duqu"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_c116cd083284cc599c024c3479ca9b70_2_tmp_b11511202d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "C116CD083284CC599C024C3479CA9B70_2.tmp_"
        original_filepath = "C116CD083284CC599C024C3479CA9B70_2.tmp_"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_androrat_binder_patched_exe_5f6308107a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, cmd.exe, http://"
        filename = "AndroRat Binder_Patched.exe"
        original_filepath = "AndroRat Binder_Patched.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "cmd.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_aapt_exe_358514e9e2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "aapt.exe"
        original_filepath = "aapt.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_decrypted_inj_snake_x64_dll_77df225f3f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "decrypted_inj_snake_x64.dll"
        original_filepath = "decrypted_inj_snake_x64.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_23f12c28515e7b9d8b2dd60ef660290ae32434bb50d56a8c8259df4881800971_2fd6b42cf0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "23f12c28515e7b9d8b2dd60ef660290ae32434bb50d56a8c8259df4881800971"
        original_filepath = "23f12c28515e7b9d8b2dd60ef660290ae32434bb50d56a8c8259df4881800971"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_win64_trojan_greenbug_3beb04ee4b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "Win64.Trojan.GreenBug"
        original_filepath = "Win64.Trojan.GreenBug"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_740992d40b84b10aa9640214a4a490e989ea7b869cea27dbbdef544bb33b1048_b3fb36d000
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "740992d40b84b10aa9640214a4a490e989ea7b869cea27dbbdef544bb33b1048"
        original_filepath = "740992d40b84b10aa9640214a4a490e989ea7b869cea27dbbdef544bb33b1048"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_svchost_exe_54c0324a88
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "svchost.exe"
        original_filepath = "svchost.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_e89614e3b0430d706bef2d1f13b30b43e5c53db9a477e2ff60ef5464e1e9add4_exe_44f128c849
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "e89614e3b0430d706bef2d1f13b30b43e5c53db9a477e2ff60ef5464e1e9add4.exe"
        original_filepath = "e89614e3b0430d706bef2d1f13b30b43e5c53db9a477e2ff60ef5464e1e9add4.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_1635ec04f069ccc8331d01fdf31132a4bc8f6fd3830ac94739df95ee093c555c_1842597a67
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "1635ec04f069ccc8331d01fdf31132a4bc8f6fd3830ac94739df95ee093c555c"
        original_filepath = "1635ec04f069ccc8331d01fdf31132a4bc8f6fd3830ac94739df95ee093c555c"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198_0faa76f1a2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198"
        original_filepath = "0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_70f8789b03e38d07584f57581363afa848dd5c3a197f2483c6dfa4f3e7f78b9b_181fc85a2a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, cmd.exe, http://"
        filename = "70f8789b03e38d07584f57581363afa848dd5c3a197f2483c6dfa4f3e7f78b9b"
        original_filepath = "70f8789b03e38d07584f57581363afa848dd5c3a197f2483c6dfa4f3e7f78b9b"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "cmd.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_63e6b8136058d7a06dfff4034b4ab17a261cdf398e63868a601f77ddd1b32802_ef8860ff27
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "63e6b8136058d7a06dfff4034b4ab17a261cdf398e63868a601f77ddd1b32802"
        original_filepath = "63e6b8136058d7a06dfff4034b4ab17a261cdf398e63868a601f77ddd1b32802"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_0cfc34fa76228b1afc7ce63e284a23ce1cd2927e6159b9dea9702ad9cb2a6300_c78c27a551
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "0cfc34fa76228b1afc7ce63e284a23ce1cd2927e6159b9dea9702ad9cb2a6300"
        original_filepath = "0cfc34fa76228b1afc7ce63e284a23ce1cd2927e6159b9dea9702ad9cb2a6300"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_win32_unnamed_specmelt_0118e63baa
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Win32.Unnamed_SpecMelt"
        original_filepath = "Win32.Unnamed_SpecMelt"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_fanny_0a209ac0de4ac033f31d6ba9191a8f7a_01aecda191
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "Fanny_0A209AC0DE4AC033F31D6BA9191A8F7A"
        original_filepath = "Fanny_0A209AC0DE4AC033F31D6BA9191A8F7A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_9ccb4ed133be5c9c554027347ad8b722f0b4c3f14bfd947edfe75a015bf085e5_ad0347c1c4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "9ccb4ed133be5c9c554027347ad8b722f0b4c3f14bfd947edfe75a015bf085e5"
        original_filepath = "9ccb4ed133be5c9c554027347ad8b722f0b4c3f14bfd947edfe75a015bf085e5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = "ftp://" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_6b97b3cd2fcfb4b74985143230441463_gadget_exe_944e38390e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .dll"
        filename = "6B97B3CD2FCFB4B74985143230441463_Gadget.exe_"
        original_filepath = "6B97B3CD2FCFB4B74985143230441463_Gadget.exe_"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_updatecheck_exe_d1ee7dcac0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "UpdateCheck.exe"
        original_filepath = "UpdateCheck.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_miniconfigbuilder_exe_436815b532
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "MiniConfigBuilder.exe"
        original_filepath = "MiniConfigBuilder.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_build_4_17_2014_id29303_bin_13f0f663db
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "build_4_17_2014_id29303.bin"
        original_filepath = "build_4_17_2014_id29303.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_php_3cf9c27197
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, ftp://"
        filename = "php"
        original_filepath = "php"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "ftp://" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_ioncube_loader_lin_5_3_ts_so_19c606f134
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "ioncube_loader_lin_5.3_ts.so"
        original_filepath = "ioncube_loader_lin_5.3_ts.so"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_ioncube_loader_lin_5_2_ts_so_c13799e694
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "ioncube_loader_lin_5.2_ts.so"
        original_filepath = "ioncube_loader_lin_5.2_ts.so"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_ioncube_loader_lin_5_2_so_bdf8ed1fab
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "ioncube_loader_lin_5.2.so"
        original_filepath = "ioncube_loader_lin_5.2.so"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_ioncube_loader_lin_5_4_ts_so_4430061af8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "ioncube_loader_lin_5.4_ts.so"
        original_filepath = "ioncube_loader_lin_5.4_ts.so"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_ioncube_loader_lin_5_4_so_e5cd32e7a8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "ioncube_loader_lin_5.4.so"
        original_filepath = "ioncube_loader_lin_5.4.so"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_ioncube_loader_lin_5_3_so_a5a5bd24ec
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "ioncube_loader_lin_5.3.so"
        original_filepath = "ioncube_loader_lin_5.3.so"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_agent_exe_f466ccc8d3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "agent.exe"
        original_filepath = "agent.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_7b8674c8f0f7c0963f2c04c35ae880e87d4c8ed836fc651e8c976197468bd98a_b8f660d273
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "7b8674c8f0f7c0963f2c04c35ae880e87d4c8ed836fc651e8c976197468bd98a"
        original_filepath = "7b8674c8f0f7c0963f2c04c35ae880e87d4c8ed836fc651e8c976197468bd98a"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_decrypted_inj_services_win32_dll_1055608a68
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "decrypted_inj_services_Win32.dll"
        original_filepath = "decrypted_inj_services_Win32.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_dustman_exe_f1f3d1dc77
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "Dustman.exe"
        original_filepath = "Dustman.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fc75410aa8f76154f5ae8fe035b9a13c76f6e132077346101a0d673ed9f3a0dd_913edd0b47
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "fc75410aa8f76154f5ae8fe035b9a13c76f6e132077346101a0d673ed9f3a0dd"
        original_filepath = "fc75410aa8f76154f5ae8fe035b9a13c76f6e132077346101a0d673ed9f3a0dd"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_clientupdate_exe__x86__bin_7c91c06dac
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "ClientUpdate.exe (x86).bin"
        original_filepath = "ClientUpdate.exe (x86).bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_conficker_62b0412419
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "conficker"
        original_filepath = "conficker"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_doublefantasy_2a12630ff976ba0994143ca93fecd17f_8ea3bf1aef
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "DoubleFantasy_2A12630FF976BA0994143CA93FECD17F"
        original_filepath = "DoubleFantasy_2A12630FF976BA0994143CA93FECD17F"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_bac8489de573f614d988097e9eae53ffc2eb4e7dcb0e68c349f549a26d2130a8_f25c0b68c8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "bac8489de573f614d988097e9eae53ffc2eb4e7dcb0e68c349f549a26d2130a8"
        original_filepath = "bac8489de573f614d988097e9eae53ffc2eb4e7dcb0e68c349f549a26d2130a8"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_d883dc7acc192019f220409ee2cadd64_8173781f84
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "D883DC7ACC192019F220409EE2CADD64"
        original_filepath = "D883DC7ACC192019F220409EE2CADD64"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_win32_triton_8310fe451f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Win32.Triton"
        original_filepath = "Win32.Triton"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_40c46bcab9acc0d6d235491c01a66d4c6f35d884c19c6f410901af6d1e33513b_da6293e54f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "40c46bcab9acc0d6d235491c01a66d4c6f35d884c19c6f410901af6d1e33513b"
        original_filepath = "40c46bcab9acc0d6d235491c01a66d4c6f35d884c19c6f410901af6d1e33513b"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_win32_sofacycarberp_bin_323adb8d58
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Win32.SofacyCarberp.bin"
        original_filepath = "Win32.SofacyCarberp.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_d214c717a357fe3a455610b197c390aa_3d370d179a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "D214C717A357FE3A455610B197C390AA"
        original_filepath = "D214C717A357FE3A455610B197C390AA"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_mono_cecil_dll_c8e170a00e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Mono.Cecil.dll"
        original_filepath = "Mono.Cecil.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_sc2_dll_c31dd0dcb0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "sc2.dll"
        original_filepath = "sc2.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_fm_dll_c750597b1e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "fm.dll"
        original_filepath = "fm.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_cam_dll_7b1df46b20
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "cam.dll"
        original_filepath = "cam.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_ch_dll_4a42819fa2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "ch.dll"
        original_filepath = "ch.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_mic_dll_39e4ddae34
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Mic.dll"
        original_filepath = "Mic.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_pw_dll_90d625bacf
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, ftp://"
        filename = "pw.dll"
        original_filepath = "pw.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "ftp://" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_naudio_dll_037dacb2a6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "NAudio.dll"
        original_filepath = "NAudio.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_malware_exe_175cb4b4ea
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "malware.exe"
        original_filepath = "malware.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_a77c61e86bc69fdc909560bb7a0fa1dd61ee6c86afceb9ea17462a97e7114ab0_40b92c3786
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "a77c61e86bc69fdc909560bb7a0fa1dd61ee6c86afceb9ea17462a97e7114ab0"
        original_filepath = "a77c61e86bc69fdc909560bb7a0fa1dd61ee6c86afceb9ea17462a97e7114ab0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_4cef5835072bb0290a05f9c5281d4a614733f480ba7f1904ae91325a10a15a04_bf7a73c060
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "4cef5835072bb0290a05f9c5281d4a614733f480ba7f1904ae91325a10a15a04"
        original_filepath = "4cef5835072bb0290a05f9c5281d4a614733f480ba7f1904ae91325a10a15a04"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_strip_girl_2_0bdcom_patches_exe_52f8141646
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "strip-girl-2.0bdcom_patches.exe"
        original_filepath = "strip-girl-2.0bdcom_patches.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_vcffipzmnipbxzdl_exe_649a54f860
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Vcffipzmnipbxzdl.exe"
        original_filepath = "Vcffipzmnipbxzdl.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_73ebf8c9571f00c9923c87e7442f3d9132627163c5a64e40ad4eb1a1f2266de9_d08ba915b4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "73ebf8c9571f00c9923c87e7442f3d9132627163c5a64e40ad4eb1a1f2266de9"
        original_filepath = "73ebf8c9571f00c9923c87e7442f3d9132627163c5a64e40ad4eb1a1f2266de9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_7d38eb24cf5644e090e45d5efa923aff0e69a600fb0ab627e8929bb485243926_33d16b5fd7
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "7d38eb24cf5644e090e45d5efa923aff0e69a600fb0ab627e8929bb485243926"
        original_filepath = "7d38eb24cf5644e090e45d5efa923aff0e69a600fb0ab627e8929bb485243926"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_abba___happy_new_year_zaycev_net_exe_99e8a3f487
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "abba_-_happy_new_year_zaycev_net.exe"
        original_filepath = "abba_-_happy_new_year_zaycev_net.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_thebigbang_bin_3d7bb7c47e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "TheBigBang.bin"
        original_filepath = "TheBigBang.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_ardamaxkeylogger_e33af9e602cbb7ac3634c2608150dd18_d9e649567f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "ArdamaxKeylogger_E33AF9E602CBB7AC3634C2608150DD18"
        original_filepath = "ArdamaxKeylogger_E33AF9E602CBB7AC3634C2608150DD18"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_2779937398506e8ad207f5b291ae53d8af82b9f2739b0508ae3e0cfc40ced092_8c172efeb5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "2779937398506e8ad207f5b291ae53d8af82b9f2739b0508ae3e0cfc40ced092"
        original_filepath = "2779937398506e8ad207f5b291ae53d8af82b9f2739b0508ae3e0cfc40ced092"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_70a1c4ed3a09a44a41d54c4fd4b409a5fc3159f6_xagent_osx_40cfc47a72
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, ftp://"
        filename = "70A1C4ED3A09A44A41D54C4FD4B409A5FC3159F6_XAgent_OSX"
        original_filepath = "70A1C4ED3A09A44A41D54C4FD4B409A5FC3159F6_XAgent_OSX"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = "ftp://" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_a917c1cc198cf36c0f2f6c24652e5c2e94e28d963b128d54f00144d216b2d118_6a5b989caf
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, ftp://, .exe"
        filename = "a917c1cc198cf36c0f2f6c24652e5c2e94e28d963b128d54f00144d216b2d118"
        original_filepath = "a917c1cc198cf36c0f2f6c24652e5c2e94e28d963b128d54f00144d216b2d118"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "ftp://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_cff49c25b053f775db8980a431a958020bdf969ea08872de4cef5a5f344f534c_fedfb95095
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "cff49c25b053f775db8980a431a958020bdf969ea08872de4cef5a5f344f534c"
        original_filepath = "cff49c25b053f775db8980a431a958020bdf969ea08872de4cef5a5f344f534c"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_hupigon_ex_b4ba79e45e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "Hupigon.ex_"
        original_filepath = "Hupigon.ex_"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_1952fa94b582e9af9dca596b5e51c585a78b8b1610639e3b878bbfa365e8e908_81981e5f2e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "1952fa94b582e9af9dca596b5e51c585a78b8b1610639e3b878bbfa365e8e908"
        original_filepath = "1952fa94b582e9af9dca596b5e51c585a78b8b1610639e3b878bbfa365e8e908"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_win32_gravityrat_exe_6748bcc770
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "Win32.GravityRAT.exe"
        original_filepath = "Win32.GravityRAT.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_win32_xagent_bin_9193b2b74c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Win32.XAgent.bin"
        original_filepath = "Win32.XAgent.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_raffle_exe_349fc6a37d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "raffle.exe"
        original_filepath = "raffle.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_6bc73659a9f251eef5c4e4e4aa7c05ff95b3df58cde829686ceee8bd845f3442_903cdfc666
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, cmd.exe, http://"
        filename = "6bc73659a9f251eef5c4e4e4aa7c05ff95b3df58cde829686ceee8bd845f3442"
        original_filepath = "6bc73659a9f251eef5c4e4e4aa7c05ff95b3df58cde829686ceee8bd845f3442"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "cmd.exe" nocase ascii wide
        $g2 = "http://" nocase ascii wide
        $g3 = ".exe" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_1ee894c0b91f3b2f836288c22ebeab44798f222f17c255f557af2260b8c6a32d_1c2a3be334
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "1ee894c0b91f3b2f836288c22ebeab44798f222f17c255f557af2260b8c6a32d"
        original_filepath = "1ee894c0b91f3b2f836288c22ebeab44798f222f17c255f557af2260b8c6a32d"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_40accff9b9d71053d4d6f95e6efd7eca1bb1ef5af77c319fe5a4b429eb373990_afe75cec7b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "40accff9b9d71053d4d6f95e6efd7eca1bb1ef5af77c319fe5a4b429eb373990"
        original_filepath = "40accff9b9d71053d4d6f95e6efd7eca1bb1ef5af77c319fe5a4b429eb373990"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_bc6c2fda18f8ee36930b469f6500e28096eb6795e5fd17c44273c67bc9fa6a6d_96fb744c26
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "bc6c2fda18f8ee36930b469f6500e28096eb6795e5fd17c44273c67bc9fa6a6d"
        original_filepath = "bc6c2fda18f8ee36930b469f6500e28096eb6795e5fd17c44273c67bc9fa6a6d"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_b06ab1f3abf8262f32c3deab9d344d241e4203235043fe996cb499ed2fdf17c4_9b64809a88
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "b06ab1f3abf8262f32c3deab9d344d241e4203235043fe996cb499ed2fdf17c4"
        original_filepath = "b06ab1f3abf8262f32c3deab9d344d241e4203235043fe996cb499ed2fdf17c4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_9d4b4c39106f8e2fd036e798fc67bbd7b98284121724c0f845bca0a6d2ae3999_dbc108bd18
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "9d4b4c39106f8e2fd036e798fc67bbd7b98284121724c0f845bca0a6d2ae3999"
        original_filepath = "9d4b4c39106f8e2fd036e798fc67bbd7b98284121724c0f845bca0a6d2ae3999"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = "ftp://" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_db36ad77875bbf622d96ae8086f44924c37034dd95e9eb6d6369cc6accd2a40d_0a68084495
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, ftp://, .exe"
        filename = "db36ad77875bbf622d96ae8086f44924c37034dd95e9eb6d6369cc6accd2a40d"
        original_filepath = "db36ad77875bbf622d96ae8086f44924c37034dd95e9eb6d6369cc6accd2a40d"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "ftp://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_03254e6240c35f7d787ca5175ffc36818185e62bdfc4d88d5b342451a747156d_32fd485f97
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://"
        filename = "03254e6240c35f7d787ca5175ffc36818185e62bdfc4d88d5b342451a747156d"
        original_filepath = "03254e6240c35f7d787ca5175ffc36818185e62bdfc4d88d5b342451a747156d"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_e2e6ed82703de21eb4c5885730ba3db42f3ddda8b94beb2ee0c3af61bc435747_0b592ccb43
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "e2e6ed82703de21eb4c5885730ba3db42f3ddda8b94beb2ee0c3af61bc435747"
        original_filepath = "e2e6ed82703de21eb4c5885730ba3db42f3ddda8b94beb2ee0c3af61bc435747"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_0283c0f02307adc4ee46c0382df4b5d7b4eb80114fbaf5cb7fe5412f027d165e_802705042c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "0283c0f02307adc4ee46c0382df4b5d7b4eb80114fbaf5cb7fe5412f027d165e"
        original_filepath = "0283c0f02307adc4ee46c0382df4b5d7b4eb80114fbaf5cb7fe5412f027d165e"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_macsecurity_19c16e7cbd
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://"
        filename = "MacSecurity"
        original_filepath = "MacSecurity"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_clientupdate_exe__x64__bin_2cc6d00976
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "ClientUpdate.exe (x64).bin"
        original_filepath = "ClientUpdate.exe (x64).bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_2a6e_tmp_25866b9c84
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .dll"
        filename = "___2A6E.tmp"
        original_filepath = "___2A6E.tmp"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_8953398de47344e9c2727565af8d6f31_7253784bfd
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "8953398DE47344E9C2727565AF8D6F31"
        original_filepath = "8953398DE47344E9C2727565AF8D6F31"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_c999bf5da5ea3960408d3cba154f965d3436b497ac9d4959b412bfcd956c8491_82b3835967
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "c999bf5da5ea3960408d3cba154f965d3436b497ac9d4959b412bfcd956c8491"
        original_filepath = "c999bf5da5ea3960408d3cba154f965d3436b497ac9d4959b412bfcd956c8491"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_07529fae9e74be81fd302d022603d9f0796b4b9120b0d6131f75d41b979bbca5_58c9236c56
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "07529fae9e74be81fd302d022603d9f0796b4b9120b0d6131f75d41b979bbca5"
        original_filepath = "07529fae9e74be81fd302d022603d9f0796b4b9120b0d6131f75d41b979bbca5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_1001a8c7f33185217e6e1bdbb8dba9780d475da944684fb4bf1fc04809525887_e0af9e21e5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "1001a8c7f33185217e6e1bdbb8dba9780d475da944684fb4bf1fc04809525887"
        original_filepath = "1001a8c7f33185217e6e1bdbb8dba9780d475da944684fb4bf1fc04809525887"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_dropper_ex_dfaf4b9ba2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "dropper.ex_"
        original_filepath = "dropper.ex_"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_2_vir_f2bd7c823c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "2.vir"
        original_filepath = "2.vir"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_3_vir_b50d50bf13
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "3.vir"
        original_filepath = "3.vir"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_2_unpacked_vir_1739ae3987
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like http://, .dll"
        filename = "2.unpacked.vir"
        original_filepath = "2.unpacked.vir"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "http://" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_1_vir_7e9d4082bc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "1.vir"
        original_filepath = "1.vir"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_slide_exe_d13393599b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "slide.exe"
        original_filepath = "slide.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_a3667153a6322fb8d4cf8869c094a05e995e2954fda833fe14304837ed4fd0bd_7a53e94edc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "a3667153a6322fb8d4cf8869c094a05e995e2954fda833fe14304837ed4fd0bd"
        original_filepath = "a3667153a6322fb8d4cf8869c094a05e995e2954fda833fe14304837ed4fd0bd"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_8a0c95be8a40ae5419f7d97bb3e91b2b_9ae05b3717
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "8a0c95be8a40ae5419f7d97bb3e91b2b"
        original_filepath = "8a0c95be8a40ae5419f7d97bb3e91b2b"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_dump_00a10000_00a1d000_exe_vir_c0fb5c4d27
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "DUMP_00A10000-00A1D000.exe.ViR"
        original_filepath = "DUMP_00A10000-00A1D000.exe.ViR"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_win32_agenttesla_exe_7532729ffb
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "Win32.AgentTesla.exe"
        original_filepath = "Win32.AgentTesla.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_7d5ad688d1cdb34f8ee694e60b9d47e894c879f23218c5c29a19a514030e706d_nteps32_ocx_f8b8d6a94c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "7d5ad688d1cdb34f8ee694e60b9d47e894c879f23218c5c29a19a514030e706d_nteps32.ocx"
        original_filepath = "7d5ad688d1cdb34f8ee694e60b9d47e894c879f23218c5c29a19a514030e706d_nteps32.ocx"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_win32_sofacycarberp_exe_00e27faad2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "Win32.SofacyCarberp.exe"
        original_filepath = "Win32.SofacyCarberp.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_58bfb9fa8889550d13f42473956dc2a7ec4f3abb18fd3faeaa38089d513c171f_ec9729c0e1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, .exe, .dll"
        filename = "58bfb9fa8889550d13f42473956dc2a7ec4f3abb18fd3faeaa38089d513c171f"
        original_filepath = "58bfb9fa8889550d13f42473956dc2a7ec4f3abb18fd3faeaa38089d513c171f"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = ".exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_dea53e331d3b9f21354147f60902f6e132f06183ed2f4a28e67816f9cb140a90_5fb19aede9
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "dea53e331d3b9f21354147f60902f6e132f06183ed2f4a28e67816f9cb140a90"
        original_filepath = "dea53e331d3b9f21354147f60902f6e132f06183ed2f4a28e67816f9cb140a90"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_bed0bec3d123e7611dc3d722813eeb197a2b8048396cef4414f29f24af3a29c4_43360a0e19
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, rundll32.exe"
        filename = "bed0bec3d123e7611dc3d722813eeb197a2b8048396cef4414f29f24af3a29c4"
        original_filepath = "bed0bec3d123e7611dc3d722813eeb197a2b8048396cef4414f29f24af3a29c4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = "rundll32.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_366affd094cc63e2c19c5d57a6866b487889dab5d1b07c084fff94262d8a390b_e2dc4f5bd8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "366affd094cc63e2c19c5d57a6866b487889dab5d1b07c084fff94262d8a390b"
        original_filepath = "366affd094cc63e2c19c5d57a6866b487889dab5d1b07c084fff94262d8a390b"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_48b1024f599c3184a49c0d66c5600385265b9868d0936134185326e2db0ab441_c0600d1dfe
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "48b1024f599c3184a49c0d66c5600385265b9868d0936134185326e2db0ab441"
        original_filepath = "48b1024f599c3184a49c0d66c5600385265b9868d0936134185326e2db0ab441"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_19e818d0da361c4feedd456fca63d68d4b024fbbd3d9265f606076c7ee72e8f8_vir_b480890de9
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "19e818d0da361c4feedd456fca63d68d4b024fbbd3d9265f606076c7ee72e8f8.ViR"
        original_filepath = "19e818d0da361c4feedd456fca63d68d4b024fbbd3d9265f606076c7ee72e8f8.ViR"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_5a765351046fea1490d20f25_exe_b571cc4d17
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "5a765351046fea1490d20f25.exe"
        original_filepath = "5a765351046fea1490d20f25.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_15540d149889539308135fa12bedbcbf_4e70e0c1a2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "15540D149889539308135FA12BEDBCBF"
        original_filepath = "15540D149889539308135FA12BEDBCBF"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_d0dd9c624bb2b33de96c29b0ccb5aa5b43ce83a54e2842f1643247811487f8d9_ad1fb2e2b6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "d0dd9c624bb2b33de96c29b0ccb5aa5b43ce83a54e2842f1643247811487f8d9"
        original_filepath = "d0dd9c624bb2b33de96c29b0ccb5aa5b43ce83a54e2842f1643247811487f8d9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = "ftp://" nocase ascii wide
        $g4 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3,$g4)
}


rule Generic_Suspicious_Strings_locky_307b629d99
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Locky"
        original_filepath = "Locky"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_94189147ba9749fd0f184fe94b345b7385348361480360a59f12adf477f61c97_9b19471f09
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .exe"
        filename = "94189147ba9749fd0f184fe94b345b7385348361480360a59f12adf477f61c97"
        original_filepath = "94189147ba9749fd0f184fe94b345b7385348361480360a59f12adf477f61c97"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_win32_mylobot_bin_8b5a01b32b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "Win32.MyLobot.bin"
        original_filepath = "Win32.MyLobot.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_hdsetup_exe_vir_416ed5ee15
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "HDSetup.exe.vir"
        original_filepath = "HDSetup.exe.vir"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_cretclient_exe_vir_d3d627f692
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "CretClient.exe.vir"
        original_filepath = "CretClient.exe.vir"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_install_livemanagerplayer_exe_vir_7cd4d16ea4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "Install_LiveManagerPlayer.exe.vir"
        original_filepath = "Install_LiveManagerPlayer.exe.vir"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_0eb038e7e5edd6ac1b4eee8dd1c51b6d94da24d02ba705e7e7f10b41edf701c2_9eee4013af
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "0eb038e7e5edd6ac1b4eee8dd1c51b6d94da24d02ba705e7e7f10b41edf701c2"
        original_filepath = "0eb038e7e5edd6ac1b4eee8dd1c51b6d94da24d02ba705e7e7f10b41edf701c2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fa5390bbcc4ab768dd81f31eac0950f6_58b327f1b9
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "fa5390bbcc4ab768dd81f31eac0950f6"
        original_filepath = "fa5390bbcc4ab768dd81f31eac0950f6"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_worm_vobfus_smm2_31f01102d2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "WORM_VOBFUS.SMM2"
        original_filepath = "WORM_VOBFUS.SMM2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_3b4497c7f8c89bf22c984854ac7603573a53b95ed147e80c0f19e549e2b65693_3d20117feb
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "3b4497c7f8c89bf22c984854ac7603573a53b95ed147e80c0f19e549e2b65693"
        original_filepath = "3b4497c7f8c89bf22c984854ac7603573a53b95ed147e80c0f19e549e2b65693"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_901fa02ffd43de5b2d7c8c6b8c2f6a43_sidebar_dll_b9f00b6e98
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "901FA02FFD43DE5B2D7C8C6B8C2F6A43_SideBar.dll_"
        original_filepath = "901FA02FFD43DE5B2D7C8C6B8C2F6A43_SideBar.dll_"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_f6e5a3a32fb3aaf3f2c56ee482998b09a6ced0a60c38088e7153f3ca247ab1cc_cf806d8300
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "f6e5a3a32fb3aaf3f2c56ee482998b09a6ced0a60c38088e7153f3ca247ab1cc"
        original_filepath = "f6e5a3a32fb3aaf3f2c56ee482998b09a6ced0a60c38088e7153f3ca247ab1cc"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_26b4699a7b9eeb16e76305d843d4ab05e94d43f3201436927e13b3ebafa90739_bin_97c7b9fec5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "26b4699a7b9eeb16e76305d843d4ab05e94d43f3201436927e13b3ebafa90739.bin"
        original_filepath = "26b4699a7b9eeb16e76305d843d4ab05e94d43f3201436927e13b3ebafa90739.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_c7128e2772b4f8c59943028e205d1b23c07f36206c1c61a05645c7bf143b24ee_0ff06faf59
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll, cmd.exe"
        filename = "c7128e2772b4f8c59943028e205d1b23c07f36206c1c61a05645c7bf143b24ee"
        original_filepath = "c7128e2772b4f8c59943028e205d1b23c07f36206c1c61a05645c7bf143b24ee"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide
        $g2 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_b154ac015c0d1d6250032f63c749f9cf_3173c93ba1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "b154ac015c0d1d6250032f63c749f9cf"
        original_filepath = "b154ac015c0d1d6250032f63c749f9cf"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_worm_vobfus_sma3_df8cafb2d8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "WORM_VOBFUS.SMA3"
        original_filepath = "WORM_VOBFUS.SMA3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_a6ff8dfe654da70390cd71626cdca8a6f6a0d7980cd7d82269373737b04fd206_dd9529b80d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "a6ff8dfe654da70390cd71626cdca8a6f6a0d7980cd7d82269373737b04fd206"
        original_filepath = "a6ff8dfe654da70390cd71626cdca8a6f6a0d7980cd7d82269373737b04fd206"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_malware_exe_0eaaddb92e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "malware.exe"
        original_filepath = "malware.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_equationlaser_752af597e6d9fd70396accc0b9013dbe_c59a4bc684
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "EquationLaser_752AF597E6D9FD70396ACCC0B9013DBE"
        original_filepath = "EquationLaser_752AF597E6D9FD70396ACCC0B9013DBE"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_e906fa3d51e86a61741b3499145a114e9bfb7c56_dc93c774c2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "E906FA3D51E86A61741B3499145A114E9BFB7C56"
        original_filepath = "E906FA3D51E86A61741B3499145A114E9BFB7C56"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_aedd0c47daa35f291e670e3feadaed11d9b8fe12c05982f16c909a57bf39ca35_1b6433eef1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "aedd0c47daa35f291e670e3feadaed11d9b8fe12c05982f16c909a57bf39ca35"
        original_filepath = "aedd0c47daa35f291e670e3feadaed11d9b8fe12c05982f16c909a57bf39ca35"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_malware_exe_d070a421c3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like https://, http://, .dll"
        filename = "malware.exe"
        original_filepath = "malware.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = "https://" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_loader_00400000_embedded01_sys_940e69040d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe"
        filename = "loader_00400000.Embedded01.SYS"
        original_filepath = "loader_00400000.Embedded01.SYS"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_loader_00400000_embedded01_dll_84d8b80d4a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "loader_00400000.Embedded01.DLL"
        original_filepath = "loader_00400000.Embedded01.DLL"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_output_1301364_unpacked_old_d60f7f9bef
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "output.1301364 unpacked.old"
        original_filepath = "output.1301364 unpacked.old"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_thebigbangimplant_bin_2ed10c7b74
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .vbs, .dll"
        filename = "TheBigBangImplant.bin"
        original_filepath = "TheBigBangImplant.bin"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".vbs" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_6f1c31f5944e46b063abbb6296b3a0d4c06037d4bdfd83ed05119e2505adabc5_e1c7f196e4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "6f1c31f5944e46b063abbb6296b3a0d4c06037d4bdfd83ed05119e2505adabc5"
        original_filepath = "6f1c31f5944e46b063abbb6296b3a0d4c06037d4bdfd83ed05119e2505adabc5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_69beb78c8b8de1a86677e27c531c92cb5ca70807d2755b94f70a75887fbc90cf_advnetcfg_ocx_29c3d4b01a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "69beb78c8b8de1a86677e27c531c92cb5ca70807d2755b94f70a75887fbc90cf_advnetcfg.ocx"
        original_filepath = "69beb78c8b8de1a86677e27c531c92cb5ca70807d2755b94f70a75887fbc90cf_advnetcfg.ocx"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_f152ed03e4383592ce7dd548c34f73da53fc457ce8f26d165155a331cde643a9_7a6d10f93d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "f152ed03e4383592ce7dd548c34f73da53fc457ce8f26d165155a331cde643a9"
        original_filepath = "f152ed03e4383592ce7dd548c34f73da53fc457ce8f26d165155a331cde643a9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_equationlaser_45df8669908a259a22c44278c2289721_0db27f9bfe
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "EquationLaser_45DF8669908A259A22C44278C2289721"
        original_filepath = "EquationLaser_45DF8669908A259A22C44278C2289721"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_equationlaser_de356f2a55b25e04742423b5ec56de93_7b0b966a12
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "EquationLaser_DE356F2A55B25E04742423B5EC56DE93"
        original_filepath = "EquationLaser_DE356F2A55B25E04742423B5EC56DE93"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_equationlaser_c96284363374597a3ac4b07c77e8325b_d5e458bb5d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "EquationLaser_C96284363374597A3AC4B07C77E8325B"
        original_filepath = "EquationLaser_C96284363374597A3AC4B07C77E8325B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_equationlaser_6480843080add60b825efe0532dc727b_55ab426437
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "EquationLaser_6480843080ADD60B825EFE0532DC727B"
        original_filepath = "EquationLaser_6480843080ADD60B825EFE0532DC727B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_equationlaser_32c53df631217d0b5f9f46d3a9246715_e72d940098
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "EquationLaser_32C53DF631217D0B5F9F46D3A9246715"
        original_filepath = "EquationLaser_32C53DF631217D0B5F9F46D3A9246715"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_equationlaser_8e2c06b52f530c9f9b5c2c743a5bb28a_3278a8415c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "EquationLaser_8E2C06B52F530C9F9B5C2C743A5BB28A"
        original_filepath = "EquationLaser_8E2C06B52F530C9F9B5C2C743A5BB28A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_fannyworm_bdc3474d7a5566916dc0a2b3075d10be_d92f160038
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_BDC3474D7A5566916DC0A2B3075D10BE"
        original_filepath = "FannyWorm_BDC3474D7A5566916DC0A2B3075D10BE"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_9fb98b0d1a5b38b6a89cb478943c285b_37cf2ebcc8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_9FB98B0D1A5B38B6A89CB478943C285B"
        original_filepath = "FannyWorm_9FB98B0D1A5B38B6A89CB478943C285B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_2c87a3442c60c72f639ca7eb6754746a_71882a2a1d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_2C87A3442C60C72F639CA7EB6754746A"
        original_filepath = "FannyWorm_2C87A3442C60C72F639CA7EB6754746A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_24132e1e00071f33221c405399271b74_c48ef719ad
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_24132E1E00071F33221C405399271B74"
        original_filepath = "FannyWorm_24132E1E00071F33221C405399271B74"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_93b22ecc56a91f251d5e023a5c20b3a4_71b055edc9
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_93B22ECC56A91F251D5E023A5C20B3A4"
        original_filepath = "FannyWorm_93B22ECC56A91F251D5E023A5C20B3A4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_68892e329fa28fe751b9eb16928ea98d_489d516d87
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_68892E329FA28FE751B9EB16928EA98D"
        original_filepath = "FannyWorm_68892E329FA28FE751B9EB16928EA98D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_4a3b537879f3f29cd8d446c53e6b06c3_be69755491
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_4A3B537879F3F29CD8D446C53E6B06C3"
        original_filepath = "FannyWorm_4A3B537879F3F29CD8D446C53E6B06C3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_29f2ab09fdffc4006a4407c05ba11b65_5a7d7cad4b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_29F2AB09FDFFC4006A4407C05BA11B65"
        original_filepath = "FannyWorm_29F2AB09FDFFC4006A4407C05BA11B65"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_c1f171a7689958eb500079ab0185915f_7ad96ad032
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_C1F171A7689958EB500079AB0185915F"
        original_filepath = "FannyWorm_C1F171A7689958EB500079AB0185915F"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_64a58cf7e810a77a5105d56b81ae8200_2bc23e2a4a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_64A58CF7E810A77A5105D56B81AE8200"
        original_filepath = "FannyWorm_64A58CF7E810A77A5105D56B81AE8200"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_6da22f42139a4a2365e7a9068d7b908a_327cac279c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_6DA22F42139A4A2365E7A9068D7B908A"
        original_filepath = "FannyWorm_6DA22F42139A4A2365E7A9068D7B908A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_7e6348f56508e43c900265ee5297b577_4c3458cdaf
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_7E6348F56508E43C900265EE5297B577"
        original_filepath = "FannyWorm_7E6348F56508E43C900265EE5297B577"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_194686907b35b69c508ae1a82d105acd_c093c7a953
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_194686907B35B69C508AE1A82D105ACD"
        original_filepath = "FannyWorm_194686907B35B69C508AE1A82D105ACD"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_600984d541d399b1894745b917e5380b_3b22078d36
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_600984D541D399B1894745B917E5380B"
        original_filepath = "FannyWorm_600984D541D399B1894745B917E5380B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_1643b9b5861ca495f83ed2da14480728_5385c37de9
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_1643B9B5861CA495F83ED2DA14480728"
        original_filepath = "FannyWorm_1643B9B5861CA495F83ED2DA14480728"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_8baadb392a85a187360fca5a4e56e6cf_a0e63d6ae9
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_8BAADB392A85A187360FCA5A4E56E6CF"
        original_filepath = "FannyWorm_8BAADB392A85A187360FCA5A4E56E6CF"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a96dc17d52986bb9ba201550d5d41186_180c9d036f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A96DC17D52986BB9BA201550D5D41186"
        original_filepath = "FannyWorm_A96DC17D52986BB9BA201550D5D41186"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_b747bb2edc15a07ce61bce4fd1a33ead_0faa2da0f9
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_B747BB2EDC15A07CE61BCE4FD1A33EAD"
        original_filepath = "FannyWorm_B747BB2EDC15A07CE61BCE4FD1A33EAD"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_9fc2aa4d538b34651705b904c7823c6f_6810bc44c6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_9FC2AA4D538B34651705B904C7823C6F"
        original_filepath = "FannyWorm_9FC2AA4D538B34651705B904C7823C6F"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a76dc2f716aa5ed5cbbd23bbf1de3005_d9995d055a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A76DC2F716AA5ED5CBBD23BBF1DE3005"
        original_filepath = "FannyWorm_A76DC2F716AA5ED5CBBD23BBF1DE3005"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_02d5eb43f5fc03f7abc89c57b82c75f8_91f8921c07
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_02D5EB43F5FC03F7ABC89C57B82C75F8"
        original_filepath = "FannyWorm_02D5EB43F5FC03F7ABC89C57B82C75F8"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_688526edbea2d61664ec629f6558365c_a6bda4c104
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_688526EDBEA2D61664EC629F6558365C"
        original_filepath = "FannyWorm_688526EDBEA2D61664EC629F6558365C"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_0f256b5884f46a15b80b60bba8876966_b1b37cd177
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_0F256B5884F46A15B80B60BBA8876966"
        original_filepath = "FannyWorm_0F256B5884F46A15B80B60BBA8876966"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_ab75c7bf5ad32af82d331b5ee76f2eca_8e53f3c66c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_AB75C7BF5AD32AF82D331B5EE76F2ECA"
        original_filepath = "FannyWorm_AB75C7BF5AD32AF82D331B5EE76F2ECA"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_72b16929f43533ac4bf953d90a52eb37_e6f56caf34
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_72B16929F43533AC4BF953D90A52EB37"
        original_filepath = "FannyWorm_72B16929F43533AC4BF953D90A52EB37"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_03a64049747b2544a5ee08a2520495d8_9d20f6f07b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_03A64049747B2544A5EE08A2520495D8"
        original_filepath = "FannyWorm_03A64049747B2544A5EE08A2520495D8"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_26c46a09cf1bdff5af503a406575809d_4b28cc1ee3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_26C46A09CF1BDFF5AF503A406575809D"
        original_filepath = "FannyWorm_26C46A09CF1BDFF5AF503A406575809D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_2c029be8e3b0c9448ed5e88b52852ade_489fd1a76f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_2C029BE8E3B0C9448ED5E88B52852ADE"
        original_filepath = "FannyWorm_2C029BE8E3B0C9448ED5E88B52852ADE"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_038e4ffbdf9334dd0b96f92104c4a5c0_2c89fac88d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_038E4FFBDF9334DD0B96F92104C4A5C0"
        original_filepath = "FannyWorm_038E4FFBDF9334DD0B96F92104C4A5C0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_aff10dd15b2d39c18ae9ee96511a9d83_2f8ca61c33
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_AFF10DD15B2D39C18AE9EE96511A9D83"
        original_filepath = "FannyWorm_AFF10DD15B2D39C18AE9EE96511A9D83"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_aaa06c8458f01bedcac5ec638c5c8b24_83d70aeffd
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_AAA06C8458F01BEDCAC5EC638C5C8B24"
        original_filepath = "FannyWorm_AAA06C8458F01BEDCAC5EC638C5C8B24"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_b4b05bb97521494b342da8524a6181ed_c30fabb06b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_B4B05BB97521494B342DA8524A6181ED"
        original_filepath = "FannyWorm_B4B05BB97521494B342DA8524A6181ED"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_ba38163fc6e75bb6acd73bc7cf89089b_4f775afe34
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_BA38163FC6E75BB6ACD73BC7CF89089B"
        original_filepath = "FannyWorm_BA38163FC6E75BB6ACD73BC7CF89089B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_8ad46bb2d0bef97548ebbed2f6eea2e1_26f12e1a2f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_8AD46BB2D0BEF97548EBBED2F6EEA2E1"
        original_filepath = "FannyWorm_8AD46BB2D0BEF97548EBBED2F6EEA2E1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_053895ae9a145a74738ba85667ae2cd1_6f1e559a71
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_053895AE9A145A74738BA85667AE2CD1"
        original_filepath = "FannyWorm_053895AE9A145A74738BA85667AE2CD1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_9a7165d3c7b84fe0e22881f653eadf7f_0bfdce2a38
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_9A7165D3C7B84FE0E22881F653EADF7F"
        original_filepath = "FannyWorm_9A7165D3C7B84FE0E22881F653EADF7F"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_2e0e43f2b0499d631edf1dd92f09bd2c_aa5f9d12ff
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_2E0E43F2B0499D631EDF1DD92F09BD2C"
        original_filepath = "FannyWorm_2E0E43F2B0499D631EDF1DD92F09BD2C"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_63b2f98548174142f92fdfd995a2c70a_1d69e37e97
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_63B2F98548174142F92FDFD995A2C70A"
        original_filepath = "FannyWorm_63B2F98548174142F92FDFD995A2C70A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_97b0a0ef6cb6b1eb8e325eb20ba0a8e3_c055a97f37
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_97B0A0EF6CB6B1EB8E325EB20BA0A8E3"
        original_filepath = "FannyWorm_97B0A0EF6CB6B1EB8E325EB20BA0A8E3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_0047c4a00161a8478df31dbdea44a19e_95c36d90cf
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "FannyWorm_0047C4A00161A8478DF31DBDEA44A19E"
        original_filepath = "FannyWorm_0047C4A00161A8478DF31DBDEA44A19E"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fannyworm_564950a5f4b3ca0e6ade94c5ca5d8de1_1ba95b2238
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_564950A5F4B3CA0E6ADE94C5CA5D8DE1"
        original_filepath = "FannyWorm_564950A5F4B3CA0E6ADE94C5CA5D8DE1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_4902cd32c4ae98008ba24c0f40189e51_1e509fd366
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_4902CD32C4AE98008BA24C0F40189E51"
        original_filepath = "FannyWorm_4902CD32C4AE98008BA24C0F40189E51"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_ba43976bb23531a9d4dc5f0afd07327a_9e3dc24cb6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_BA43976BB23531A9D4DC5F0AFD07327A"
        original_filepath = "FannyWorm_BA43976BB23531A9D4DC5F0AFD07327A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a95b2ec5b67f8fdda547a4a5a4b85543_054a8b3c37
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A95B2EC5B67F8FDDA547A4A5A4B85543"
        original_filepath = "FannyWorm_A95B2EC5B67F8FDDA547A4A5A4B85543"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_7cccaf9b08301d2c2acb647ea04ca8e1_9858da9949
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_7CCCAF9B08301D2C2ACB647EA04CA8E1"
        original_filepath = "FannyWorm_7CCCAF9B08301D2C2ACB647EA04CA8E1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_3a57adb8740da3ebec1673d21f20d0fe_932df3b77a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_3A57ADB8740DA3EBEC1673D21F20D0FE"
        original_filepath = "FannyWorm_3A57ADB8740DA3EBEC1673D21F20D0FE"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_1cb7ae1bc76e139c89684f7797f520a1_87a3b9cf10
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_1CB7AE1BC76E139C89684F7797F520A1"
        original_filepath = "FannyWorm_1CB7AE1BC76E139C89684F7797F520A1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_0915237a0b1f095aace0a50b82356571_dc3951f319
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_0915237A0B1F095AACE0A50B82356571"
        original_filepath = "FannyWorm_0915237A0B1F095AACE0A50B82356571"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_6de614ad2b4d03f9dfcdf0251737d33d_18d4dbf4c4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_6DE614AD2B4D03F9DFCDF0251737D33D"
        original_filepath = "FannyWorm_6DE614AD2B4D03F9DFCDF0251737D33D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_8fe19689cc16fea06bdfc9c39c515fa3_b9fb819d84
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_8FE19689CC16FEA06BDFC9C39C515FA3"
        original_filepath = "FannyWorm_8FE19689CC16FEA06BDFC9C39C515FA3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_00535dca6d6db97128f6e12451c1e04e_223c061dc4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_00535DCA6D6DB97128F6E12451C1E04E"
        original_filepath = "FannyWorm_00535DCA6D6DB97128F6E12451C1E04E"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_2da059a8bf3bc00bb809b28770044ff6_bd90ac21e6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_2DA059A8BF3BC00BB809B28770044FF6"
        original_filepath = "FannyWorm_2DA059A8BF3BC00BB809B28770044FF6"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_303b7527db5b417719daf9b0ae5b89aa_2096967a38
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "FannyWorm_303B7527DB5B417719DAF9B0AE5B89AA"
        original_filepath = "FannyWorm_303B7527DB5B417719DAF9B0AE5B89AA"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fannyworm_5f5abbe2e637d4f0b8afe7f2342c2942_d98ff37c32
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_5F5ABBE2E637D4F0B8AFE7F2342C2942"
        original_filepath = "FannyWorm_5F5ABBE2E637D4F0B8AFE7F2342C2942"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a62be32440d0602c76a72f96235567ac_db8e9cfe94
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A62BE32440D0602C76A72F96235567AC"
        original_filepath = "FannyWorm_A62BE32440D0602C76A72F96235567AC"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_40fee20fe98995acbda82dbcde0b674b_db95e77e38
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_40FEE20FE98995ACBDA82DBCDE0B674B"
        original_filepath = "FannyWorm_40FEE20FE98995ACBDA82DBCDE0B674B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_bcc5d198a60878c03a114e45acdfe417_ce03b0655b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_BCC5D198A60878C03A114E45ACDFE417"
        original_filepath = "FannyWorm_BCC5D198A60878C03A114E45ACDFE417"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_29fdec2fd992c2ab38e1dd41500190b9_62d95e28e8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_29FDEC2FD992C2AB38E1DD41500190B9"
        original_filepath = "FannyWorm_29FDEC2FD992C2AB38E1DD41500190B9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_0333f6533573d7a08b4de47bd186ec65_45873aaf06
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_0333F6533573D7A08B4DE47BD186EC65"
        original_filepath = "FannyWorm_0333F6533573D7A08B4DE47BD186EC65"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_2822d46611ad7fd71dfe5a1f4c79ab4b_ac8ae9cd85
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_2822D46611AD7FD71DFE5A1F4C79AB4B"
        original_filepath = "FannyWorm_2822D46611AD7FD71DFE5A1F4C79AB4B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_0e2313835ca0fa52d95500f83fe9f5d2_4098693f14
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "FannyWorm_0E2313835CA0FA52D95500F83FE9F5D2"
        original_filepath = "FannyWorm_0E2313835CA0FA52D95500F83FE9F5D2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fannyworm_13429f4899618f3529669a8ce850b512_cd8d78c31d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_13429F4899618F3529669A8CE850B512"
        original_filepath = "FannyWorm_13429F4899618F3529669A8CE850B512"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_0a704348bd37ea5ccd2e0a540eb010c2_b761a519d1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_0A704348BD37EA5CCD2E0A540EB010C2"
        original_filepath = "FannyWorm_0A704348BD37EA5CCD2E0A540EB010C2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_c303afe1648d3b70591feeffe78125ed_881fcbf7b5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_C303AFE1648D3B70591FEEFFE78125ED"
        original_filepath = "FannyWorm_C303AFE1648D3B70591FEEFFE78125ED"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_10a9caa724ae8edc30c09f8372241c32_f6e75c5c50
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_10A9CAA724AE8EDC30C09F8372241C32"
        original_filepath = "FannyWorm_10A9CAA724AE8EDC30C09F8372241C32"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_c05255625bb00eb12eaf95cb41fcc7f5_c44d06c14b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_C05255625BB00EB12EAF95CB41FCC7F5"
        original_filepath = "FannyWorm_C05255625BB00EB12EAF95CB41FCC7F5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_1b27ac722847f5a3304e3896f0528fa4_31295b2e4d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_1B27AC722847F5A3304E3896F0528FA4"
        original_filepath = "FannyWorm_1B27AC722847F5A3304E3896F0528FA4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_4c31fe56ff4a46fbcd87b28651235177_eb3f2bcf8e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_4C31FE56FF4A46FBCD87B28651235177"
        original_filepath = "FannyWorm_4C31FE56FF4A46FBCD87B28651235177"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_40000b4f52dcdedb1e1d3bfd5c185cec_56b5c6fba8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_40000B4F52DCDEDB1E1D3BFD5C185CEC"
        original_filepath = "FannyWorm_40000B4F52DCDEDB1E1D3BFD5C185CEC"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_89c216df6b2b1a335738847a1f1a6cbc_91daf136f5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_89C216DF6B2B1A335738847A1F1A6CBC"
        original_filepath = "FannyWorm_89C216DF6B2B1A335738847A1F1A6CBC"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_56ff71e1f28e1f149e0e4cf8ce9811d1_a9855c58ac
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_56FF71E1F28E1F149E0E4CF8CE9811D1"
        original_filepath = "FannyWorm_56FF71E1F28E1F149E0E4CF8CE9811D1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_b1cceb79f74d48c94ca7e680a609bc65_886148364b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_B1CCEB79F74D48C94CA7E680A609BC65"
        original_filepath = "FannyWorm_B1CCEB79F74D48C94CA7E680A609BC65"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_6814b21455deb552df3b452ef0551ec1_e5d412fcbb
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_6814B21455DEB552DF3B452EF0551EC1"
        original_filepath = "FannyWorm_6814B21455DEB552DF3B452EF0551EC1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_74ad35f0f4342f45038860ca0564ab8b_c090f3bc11
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_74AD35F0F4342F45038860CA0564AB8B"
        original_filepath = "FannyWorm_74AD35F0F4342F45038860CA0564AB8B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_0acbdd008b62cd40bb1434aca7500d5b_7adfcb55fe
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_0ACBDD008B62CD40BB1434ACA7500D5B"
        original_filepath = "FannyWorm_0ACBDD008B62CD40BB1434ACA7500D5B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_5821380182c7bfaa6646db4313449917_e4656b7302
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_5821380182C7BFAA6646DB4313449917"
        original_filepath = "FannyWorm_5821380182C7BFAA6646DB4313449917"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_948603bd138dd8487faab3c0da5eb573_3420051a79
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_948603BD138DD8487FAAB3C0DA5EB573"
        original_filepath = "FannyWorm_948603BD138DD8487FAAB3C0DA5EB573"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_1fd210ba936fd11b46781e04bbc0f8b5_d1a21355c0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_1FD210BA936FD11B46781E04BBC0F8B5"
        original_filepath = "FannyWorm_1FD210BA936FD11B46781E04BBC0F8B5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_ae58e6c03d7339da70d061399f6deff3_74a27240c0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_AE58E6C03D7339DA70D061399F6DEFF3"
        original_filepath = "FannyWorm_AE58E6C03D7339DA70D061399F6DEFF3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_72f244452df28865b37317369c33927d_cafc4b2dda
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_72F244452DF28865B37317369C33927D"
        original_filepath = "FannyWorm_72F244452DF28865B37317369C33927D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a5f389947f03902a5abd742b61637363_8fd6bff2af
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A5F389947F03902A5ABD742B61637363"
        original_filepath = "FannyWorm_A5F389947F03902A5ABD742B61637363"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_00fae15224f3a3c46d20f2667fb1ed89_47f70f3bb6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_00FAE15224F3A3C46D20F2667FB1ED89"
        original_filepath = "FannyWorm_00FAE15224F3A3C46D20F2667FB1ED89"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a4e2ed5ff620a786c2f2e15a5f8a2d2f_d45f97ffea
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A4E2ED5FF620A786C2F2E15A5F8A2D2F"
        original_filepath = "FannyWorm_A4E2ED5FF620A786C2F2E15A5F8A2D2F"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_8a41a5ad3ae353f16ff2fd92e8046ac3_f8b929a174
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_8A41A5AD3AE353F16FF2FD92E8046AC3"
        original_filepath = "FannyWorm_8A41A5AD3AE353F16FF2FD92E8046AC3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_c3da3234a3764ca81d694c3935bf55cf_e305c69c51
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_C3DA3234A3764CA81D694C3935BF55CF"
        original_filepath = "FannyWorm_C3DA3234A3764CA81D694C3935BF55CF"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_769c62fdd6e1d2c5d51094e2882886b0_b0d5aaf9c6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_769C62FDD6E1D2C5D51094E2882886B0"
        original_filepath = "FannyWorm_769C62FDD6E1D2C5D51094E2882886B0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_05a0274ddea1d4e2d938ee0804da41db_75bfb56dd8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_05A0274DDEA1D4E2D938EE0804DA41DB"
        original_filepath = "FannyWorm_05A0274DDEA1D4E2D938EE0804DA41DB"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_03a5ae64c62eb66dd7303801785d3f7b_4f30664640
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_03A5AE64C62EB66DD7303801785D3F7B"
        original_filepath = "FannyWorm_03A5AE64C62EB66DD7303801785D3F7B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a82d41cfc3ee376d9252dd4912e35894_1c1f0727ce
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A82D41CFC3EE376D9252DD4912E35894"
        original_filepath = "FannyWorm_A82D41CFC3EE376D9252DD4912E35894"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a801668543b30fcc3a254de8183b2ba5_8452d743b0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A801668543B30FCC3A254DE8183B2BA5"
        original_filepath = "FannyWorm_A801668543B30FCC3A254DE8183B2BA5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_ac50c31d680c763cce26b4d979a11a5c_d7867bcd28
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_AC50C31D680C763CCE26B4D979A11A5C"
        original_filepath = "FannyWorm_AC50C31D680C763CCE26B4D979A11A5C"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_22db66045fa1e39b5bf16fc63a850098_e1c3120761
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_22DB66045FA1E39B5BF16FC63A850098"
        original_filepath = "FannyWorm_22DB66045FA1E39B5BF16FC63A850098"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_2c6595834dd5528235e8a9815276563e_18114005ce
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_2C6595834DD5528235E8A9815276563E"
        original_filepath = "FannyWorm_2C6595834DD5528235E8A9815276563E"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_063ad1284a8dfb82965b539efd965547_e40c97bece
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_063AD1284A8DFB82965B539EFD965547"
        original_filepath = "FannyWorm_063AD1284A8DFB82965B539EFD965547"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_31457cb30ccad20cdbc77b8c4b6f9b3f_6f8dd06a22
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_31457CB30CCAD20CDBC77B8C4B6F9B3F"
        original_filepath = "FannyWorm_31457CB30CCAD20CDBC77B8C4B6F9B3F"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_3fbd798bcd7214fcbf5fab05faf9fd71_4c4c35802e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_3FBD798BCD7214FCBF5FAB05FAF9FD71"
        original_filepath = "FannyWorm_3FBD798BCD7214FCBF5FAB05FAF9FD71"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_7faabce7d2564176480769a9d7b34a2c_6df78c338a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_7FAABCE7D2564176480769A9D7B34A2C"
        original_filepath = "FannyWorm_7FAABCE7D2564176480769A9D7B34A2C"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_72312f1e2ae6900f169a2b7a88e14d93_b4741199e5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_72312F1E2AE6900F169A2B7A88E14D93"
        original_filepath = "FannyWorm_72312F1E2AE6900F169A2B7A88E14D93"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_4ad2f62ce2eb72eff45c61699bdcb1e3_a7045121e2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_4AD2F62CE2EB72EFF45C61699BDCB1E3"
        original_filepath = "FannyWorm_4AD2F62CE2EB72EFF45C61699BDCB1E3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_8bb0c5181d8ab57b879dea3f987fbedf_6ac58a9ae1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "FannyWorm_8BB0C5181D8AB57B879DEA3F987FBEDF"
        original_filepath = "FannyWorm_8BB0C5181D8AB57B879DEA3F987FBEDF"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fannyworm_2062d7b0d9145adbe0131cf1fb1fc35a_98d0ddfac3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_2062D7B0D9145ADBE0131CF1FB1FC35A"
        original_filepath = "FannyWorm_2062D7B0D9145ADBE0131CF1FB1FC35A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_5e171b3a31279f9fcf21888ac0034b06_38724a22ec
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_5E171B3A31279F9FCF21888AC0034B06"
        original_filepath = "FannyWorm_5E171B3A31279F9FCF21888AC0034B06"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_8c7ef91a96e75c3d05ea5e54a0e9356c_104e546b06
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_8C7EF91A96E75C3D05EA5E54A0E9356C"
        original_filepath = "FannyWorm_8C7EF91A96E75C3D05EA5E54A0E9356C"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_5bec4783c551c46b15f7c5b20f94f4b9_e87eb745ae
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_5BEC4783C551C46B15F7C5B20F94F4B9"
        original_filepath = "FannyWorm_5BEC4783C551C46B15F7C5B20F94F4B9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_98e6b678b40329dac41d8f42652c17a2_36164f9205
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_98E6B678B40329DAC41D8F42652C17A2"
        original_filepath = "FannyWorm_98E6B678B40329DAC41D8F42652C17A2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a498fcac85dc2e97281781a08b1c1041_b6d3fd2abe
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A498FCAC85DC2E97281781A08B1C1041"
        original_filepath = "FannyWorm_A498FCAC85DC2E97281781A08B1C1041"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_af8f1bfccb6530e41b2f19ff0de8bab5_9b2d492fee
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_AF8F1BFCCB6530E41B2F19FF0DE8BAB5"
        original_filepath = "FannyWorm_AF8F1BFCCB6530E41B2F19FF0DE8BAB5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_b1c4ed725cb3443d16be55ee5f00dcbd_4de0454182
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_B1C4ED725CB3443D16BE55EE5F00DCBD"
        original_filepath = "FannyWorm_B1C4ED725CB3443D16BE55EE5F00DCBD"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_6e4f77dcdbb034cb4073d8c46bf23ae3_9f87e086eb
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_6E4F77DCDBB034CB4073D8C46BF23AE3"
        original_filepath = "FannyWorm_6E4F77DCDBB034CB4073D8C46BF23AE3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_872e8e7c381fb805b87b88f31f77a772_945f717f53
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "FannyWorm_872E8E7C381FB805B87B88F31F77A772"
        original_filepath = "FannyWorm_872E8E7C381FB805B87B88F31F77A772"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fannyworm_a5e169e47ba828dd68417875aa8c0c94_0d9b705b8e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A5E169E47BA828DD68417875AA8C0C94"
        original_filepath = "FannyWorm_A5E169E47BA828DD68417875AA8C0C94"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_6436a4fb7a8f37ac934c275d325208e6_97144a3903
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_6436A4FB7A8F37AC934C275D325208E6"
        original_filepath = "FannyWorm_6436A4FB7A8F37AC934C275D325208E6"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_5118f69983a1544caf4e3d244e195304_4cdab075a5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_5118F69983A1544CAF4E3D244E195304"
        original_filepath = "FannyWorm_5118F69983A1544CAF4E3D244E195304"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_8051e04bab3a6db6226cc4d08890e934_bbe672f268
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "FannyWorm_8051E04BAB3A6DB6226CC4D08890E934"
        original_filepath = "FannyWorm_8051E04BAB3A6DB6226CC4D08890E934"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_fannyworm_58ef8790939fca73a20c6a04717a2659_b103d14134
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_58EF8790939FCA73A20C6A04717A2659"
        original_filepath = "FannyWorm_58EF8790939FCA73A20C6A04717A2659"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_3a71446564b4c060d99a8ccd2eb5d161_8efe83e2a8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_3A71446564B4C060D99A8CCD2EB5D161"
        original_filepath = "FannyWorm_3A71446564B4C060D99A8CCD2EB5D161"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_7808586dec24d04567582f9cbd26ead8_2910f00b2f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_7808586DEC24D04567582F9CBD26EAD8"
        original_filepath = "FannyWorm_7808586DEC24D04567582F9CBD26EAD8"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_1f1dc3cf1d769d464db9752c8cecc872_674ef6cf59
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "FannyWorm_1F1DC3CF1D769D464DB9752C8CECC872"
        original_filepath = "FannyWorm_1F1DC3CF1D769D464DB9752C8CECC872"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fannyworm_ac7a5c23b475e8bf54a1e60ae1a85f67_bf0cdae26d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_AC7A5C23B475E8BF54A1E60AE1A85F67"
        original_filepath = "FannyWorm_AC7A5C23B475E8BF54A1E60AE1A85F67"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_9120c2a26e1f4dc362ca338b8e014b20_f3ba824113
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_9120C2A26E1F4DC362CA338B8E014B20"
        original_filepath = "FannyWorm_9120C2A26E1F4DC362CA338B8E014B20"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_5dc172e2c96b79ea7d855339f1b2403c_6a2ba3ced3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_5DC172E2C96B79EA7D855339F1B2403C"
        original_filepath = "FannyWorm_5DC172E2C96B79EA7D855339F1B2403C"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_939706730193e6bcfeb991de4387bd3f_46bb58d49e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_939706730193E6BCFEB991DE4387BD3F"
        original_filepath = "FannyWorm_939706730193E6BCFEB991DE4387BD3F"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_0b5f75e67b78d34dc4206bf49c7f09e9_3f3722b8e2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_0B5F75E67B78D34DC4206BF49C7F09E9"
        original_filepath = "FannyWorm_0B5F75E67B78D34DC4206BF49C7F09E9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_bfde4b5cd6cc89c6996c5e30c36f0273_815d3a4e8c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_BFDE4B5CD6CC89C6996C5E30C36F0273"
        original_filepath = "FannyWorm_BFDE4B5CD6CC89C6996C5E30C36F0273"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_13b67c888efeaf60a9a4fb1e4e182f2d_459f673b6a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_13B67C888EFEAF60A9A4FB1E4E182F2D"
        original_filepath = "FannyWorm_13B67C888EFEAF60A9A4FB1E4E182F2D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_8010af50404647200a7bb51de08ab960_277e96bc20
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_8010AF50404647200A7BB51DE08AB960"
        original_filepath = "FannyWorm_8010AF50404647200A7BB51DE08AB960"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_3de3419f6441a7f4d664077a43fb404b_6f701b969d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "FannyWorm_3DE3419F6441A7F4D664077A43FB404B"
        original_filepath = "FannyWorm_3DE3419F6441A7F4D664077A43FB404B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fannyworm_78b1ff3b04fac35c890462225c5fbc49_6118b4d030
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_78B1FF3B04FAC35C890462225C5FBC49"
        original_filepath = "FannyWorm_78B1FF3B04FAC35C890462225C5FBC49"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_002f5e401f705fe91f44263e49d6c216_82f5420a7d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_002F5E401F705FE91F44263E49D6C216"
        original_filepath = "FannyWorm_002F5E401F705FE91F44263E49D6C216"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_05187aa4d312ff06187c93d12dd5f1d0_85b85b690b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_05187AA4D312FF06187C93D12DD5F1D0"
        original_filepath = "FannyWorm_05187AA4D312FF06187C93D12DD5F1D0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_0063bf5852ffb5baabcdc34ad4f8f0bf_1412787d25
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_0063BF5852FFB5BAABCDC34AD4F8F0BF"
        original_filepath = "FannyWorm_0063BF5852FFB5BAABCDC34AD4F8F0BF"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_75ac44f173af6ace7cc06e8406b03d33_1bf5793d26
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_75AC44F173AF6ACE7CC06E8406B03D33"
        original_filepath = "FannyWorm_75AC44F173AF6ACE7CC06E8406B03D33"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_782e5c2d319063405414d4e55d3dcfb3_a3539a2827
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_782E5C2D319063405414D4E55D3DCFB3"
        original_filepath = "FannyWorm_782E5C2D319063405414D4E55D3DCFB3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_151c7da8c611bf9795d813a5806d6364_481d814a21
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_151C7DA8C611BF9795D813A5806D6364"
        original_filepath = "FannyWorm_151C7DA8C611BF9795D813A5806D6364"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_199e39bda0af0a062ccc734faccf9213_fd8be07107
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_199E39BDA0AF0A062CCC734FACCF9213"
        original_filepath = "FannyWorm_199E39BDA0AF0A062CCC734FACCF9213"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_101bc932d760f12a308e450eb97effa5_74f4865fff
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_101BC932D760F12A308E450EB97EFFA5"
        original_filepath = "FannyWorm_101BC932D760F12A308E450EB97EFFA5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_168af91d1ba92a41679d5b5890dc71e7_296a9cf87f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "FannyWorm_168AF91D1BA92A41679D5B5890DC71E7"
        original_filepath = "FannyWorm_168AF91D1BA92A41679D5B5890DC71E7"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fannyworm_05e58526f763f069b4c86d209416f50a_728f4f2b41
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_05E58526F763F069B4C86D209416F50A"
        original_filepath = "FannyWorm_05E58526F763F069B4C86D209416F50A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_48e958e3785be0d5e074ad2cfcf2fee4_c1e5e4eede
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_48E958E3785BE0D5E074AD2CFCF2FEE4"
        original_filepath = "FannyWorm_48E958E3785BE0D5E074AD2CFCF2FEE4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_3b496b8cd19789fabf00584475b607c7_e8575f8678
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_3B496B8CD19789FABF00584475B607C7"
        original_filepath = "FannyWorm_3B496B8CD19789FABF00584475B607C7"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_18cb3574825fa409d5cbc0f67e8cc162_250411adf8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_18CB3574825FA409D5CBC0F67E8CC162"
        original_filepath = "FannyWorm_18CB3574825FA409D5CBC0F67E8CC162"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_2f2a8deca2539923b489d51de9a278f4_829c12e0e5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_2F2A8DECA2539923B489D51DE9A278F4"
        original_filepath = "FannyWorm_2F2A8DECA2539923B489D51DE9A278F4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_57b64a212b4b3982793916a18fa4f489_617e119128
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_57B64A212B4B3982793916A18FA4F489"
        original_filepath = "FannyWorm_57B64A212B4B3982793916A18FA4F489"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_1f69160f1d91bf9a0eda93829b75c583_a950ec39c4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_1F69160F1D91BF9A0EDA93829B75C583"
        original_filepath = "FannyWorm_1F69160F1D91BF9A0EDA93829B75C583"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_8568a1cfa314525f49c98fafbf85d14b_2b8a5616e3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_8568A1CFA314525F49C98FAFBF85D14B"
        original_filepath = "FannyWorm_8568A1CFA314525F49C98FAFBF85D14B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a2c52ad8f66a14f7979c6bafc4978142_32c805adf3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A2C52AD8F66A14F7979C6BAFC4978142"
        original_filepath = "FannyWorm_A2C52AD8F66A14F7979C6BAFC4978142"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_1925b30a657ea0b5bfc62d3914f7855f_f1249a10bf
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_1925B30A657EA0B5BFC62D3914F7855F"
        original_filepath = "FannyWorm_1925B30A657EA0B5BFC62D3914F7855F"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_88e4147efaba886ff16d6f058e8a25a6_8fa148c671
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_88E4147EFABA886FF16D6F058E8A25A6"
        original_filepath = "FannyWorm_88E4147EFABA886FF16D6F058E8A25A6"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_68e6ee88ba44ed0b9de93d6812b5255e_87bda49abe
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_68E6EE88BA44ED0B9DE93D6812B5255E"
        original_filepath = "FannyWorm_68E6EE88BA44ED0B9DE93D6812B5255E"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a7f4eee46463be30615903e395a323c5_0bc43ff0ce
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A7F4EEE46463BE30615903E395A323C5"
        original_filepath = "FannyWorm_A7F4EEE46463BE30615903E395A323C5"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_4fd969cefb161cbbfe26897f097eda71_e912f589bd
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_4FD969CEFB161CBBFE26897F097EDA71"
        original_filepath = "FannyWorm_4FD969CEFB161CBBFE26897F097EDA71"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_74621a05bafb868bda8aeb6562dd36df_4a77b5ef21
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_74621A05BAFB868BDA8AEB6562DD36DF"
        original_filepath = "FannyWorm_74621A05BAFB868BDA8AEB6562DD36DF"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_5a7dacc0c0f34005ab9710e666128500_e15f0ce69a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_5A7DACC0C0F34005AB9710E666128500"
        original_filepath = "FannyWorm_5A7DACC0C0F34005AB9710E666128500"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_bac9a35d7cdf8c217b51c189a7b7b2fd_65531601ae
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_BAC9A35D7CDF8C217B51C189A7B7B2FD"
        original_filepath = "FannyWorm_BAC9A35D7CDF8C217B51C189A7B7B2FD"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_149b980e2495df13edcefed78716ba8d_58dbaa5a43
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_149B980E2495DF13EDCEFED78716BA8D"
        original_filepath = "FannyWorm_149B980E2495DF13EDCEFED78716BA8D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a67e937c6c33b0a9cd83946ccfa666ca_da8dfc873b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A67E937C6C33B0A9CD83946CCFA666CA"
        original_filepath = "FannyWorm_A67E937C6C33B0A9CD83946CCFA666CA"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_b5738307bab3fbf4cf2bdd652b0ac88a_ba3fe1d72e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_B5738307BAB3FBF4CF2BDD652B0AC88A"
        original_filepath = "FannyWorm_B5738307BAB3FBF4CF2BDD652B0AC88A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_2249d5577d2c84ba1043376b77e6c24d_aaa6b7cfa0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_2249D5577D2C84BA1043376B77E6C24D"
        original_filepath = "FannyWorm_2249D5577D2C84BA1043376B77E6C24D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a5f2c5ca6b51a6bf48d795fb5ae63203_b0f4c25811
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A5F2C5CA6B51A6BF48D795FB5AE63203"
        original_filepath = "FannyWorm_A5F2C5CA6B51A6BF48D795FB5AE63203"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_63ecb7fe79a5b541c35765caf424a021_3c93de50bd
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_63ECB7FE79A5B541C35765CAF424A021"
        original_filepath = "FannyWorm_63ECB7FE79A5B541C35765CAF424A021"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a43f67af43730552864f84e2b051deb4_efa9c6927e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A43F67AF43730552864F84E2B051DEB4"
        original_filepath = "FannyWorm_A43F67AF43730552864F84E2B051DEB4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_4f79981d1f7091be6aadcc4595ef5f76_b61a299cf3
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_4F79981D1F7091BE6AADCC4595EF5F76"
        original_filepath = "FannyWorm_4F79981D1F7091BE6AADCC4595EF5F76"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a68a56b4b3412e07436c7d195891e8be_9a16dae110
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A68A56B4B3412E07436C7D195891E8BE"
        original_filepath = "FannyWorm_A68A56B4B3412E07436C7D195891E8BE"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_58786e35fa1d61d1bcd671987d103957_a754a351aa
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_58786E35FA1D61D1BCD671987D103957"
        original_filepath = "FannyWorm_58786E35FA1D61D1BCD671987D103957"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_4509385e247ef538cfb8cd42944ee480_8c2a316726
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_4509385E247EF538CFB8CD42944EE480"
        original_filepath = "FannyWorm_4509385E247EF538CFB8CD42944EE480"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_04ddb75038698f66b9c43304a2c92240_669017282d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_04DDB75038698F66B9C43304A2C92240"
        original_filepath = "FannyWorm_04DDB75038698F66B9C43304A2C92240"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_8e555220bd7f8c183abf58071851e2b4_fb15e71e00
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_8E555220BD7F8C183ABF58071851E2B4"
        original_filepath = "FannyWorm_8E555220BD7F8C183ABF58071851E2B4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_49622ddf195628f7a3400b7a9f98e60a_97ea587923
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_49622DDF195628F7A3400B7A9F98E60A"
        original_filepath = "FannyWorm_49622DDF195628F7A3400B7A9F98E60A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_1dd86b28a2bc986b069c75bf5c6787b9_4acf34c677
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_1DD86B28A2BC986B069C75BF5C6787B9"
        original_filepath = "FannyWorm_1DD86B28A2BC986B069C75BF5C6787B9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_5ff0e69bf258375e7eefcc5ac3bdcf24_58182e3f7e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_5FF0E69BF258375E7EEFCC5AC3BDCF24"
        original_filepath = "FannyWorm_5FF0E69BF258375E7EEFCC5AC3BDCF24"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_bd7a693767de2eae08b4c63aaa84db43_0466ff4356
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_BD7A693767DE2EAE08B4C63AAA84DB43"
        original_filepath = "FannyWorm_BD7A693767DE2EAE08B4C63AAA84DB43"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_b322fb54b5e53f4ea93e04e5a2abccbc_437c133e7f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_B322FB54B5E53F4EA93E04E5A2ABCCBC"
        original_filepath = "FannyWorm_B322FB54B5E53F4EA93E04E5A2ABCCBC"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_54d7826f13c1116b0be9077334713f1a_b121cd6663
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_54D7826F13C1116B0BE9077334713F1A"
        original_filepath = "FannyWorm_54D7826F13C1116B0BE9077334713F1A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_bed58d25c152bd5b4a9c022b5b863c72_aa6c1801c0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_BED58D25C152BD5B4A9C022B5B863C72"
        original_filepath = "FannyWorm_BED58D25C152BD5B4A9C022B5B863C72"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_246272dd6e9193e31745ad54138f875d_8245545f9b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_246272DD6E9193E31745AD54138F875D"
        original_filepath = "FannyWorm_246272DD6E9193E31745AD54138F875D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_9563fd4ab7d619d565b47cd16104dc66_bbce6d2f7a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_9563FD4AB7D619D565B47CD16104DC66"
        original_filepath = "FannyWorm_9563FD4AB7D619D565B47CD16104DC66"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_86d89bac8a165fce91426bf84eb7b7fc_b5856681c8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "FannyWorm_86D89BAC8A165FCE91426BF84EB7B7FC"
        original_filepath = "FannyWorm_86D89BAC8A165FCE91426BF84EB7B7FC"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fannyworm_a8a973b3861c8d2f18039432b9f38335_1411d69d5c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A8A973B3861C8D2F18039432B9F38335"
        original_filepath = "FannyWorm_A8A973B3861C8D2F18039432B9F38335"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_5328361825d0b1ccb0b157ceff4e883e_15bbdfd106
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_5328361825D0B1CCB0B157CEFF4E883E"
        original_filepath = "FannyWorm_5328361825D0B1CCB0B157CEFF4E883E"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_49cb69039308b2613664515c5fa323e1_83a0180e7e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_49CB69039308B2613664515C5FA323E1"
        original_filepath = "FannyWorm_49CB69039308B2613664515C5FA323E1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_1ef39eb63ddff30a3e37feeffb8fc712_4bde965293
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_1EF39EB63DDFF30A3E37FEEFFB8FC712"
        original_filepath = "FannyWorm_1EF39EB63DDFF30A3E37FEEFFB8FC712"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_27c5d028ee23a515df4203ea6026e23e_2a01fcb4e5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_27C5D028EE23A515DF4203EA6026E23E"
        original_filepath = "FannyWorm_27C5D028EE23A515DF4203EA6026E23E"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_152ad931b42a8da9149dd73a8bfcff69_4e381e80de
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_152AD931B42A8DA9149DD73A8BFCFF69"
        original_filepath = "FannyWorm_152AD931B42A8DA9149DD73A8BFCFF69"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_682c987506651fcae56c32ffa1f70170_29a4e1d181
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_682C987506651FCAE56C32FFA1F70170"
        original_filepath = "FannyWorm_682C987506651FCAE56C32FFA1F70170"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_450a3edece8808f483203fe8988c4437_d0a7eda6a6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_450A3EDECE8808F483203FE8988C4437"
        original_filepath = "FannyWorm_450A3EDECE8808F483203FE8988C4437"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_4e58bd45a388e458c9f8ff09eb905cc0_e7ddcd05a0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_4E58BD45A388E458C9F8FF09EB905CC0"
        original_filepath = "FannyWorm_4E58BD45A388E458C9F8FF09EB905CC0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_5a723d3ef02db234061c2f61a6e3b6a4_a01ce581f0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_5A723D3EF02DB234061C2F61A6E3B6A4"
        original_filepath = "FannyWorm_5A723D3EF02DB234061C2F61A6E3B6A4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_99e8d4f1d2069ef84d9725aa206d6ba7_937f9b6f79
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_99E8D4F1D2069EF84D9725AA206D6BA7"
        original_filepath = "FannyWorm_99E8D4F1D2069EF84D9725AA206D6BA7"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_60d21ee6548de4673cbddef2d779ed24_0c855ad50a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_60D21EE6548DE4673CBDDEF2D779ED24"
        original_filepath = "FannyWorm_60D21EE6548DE4673CBDDEF2D779ED24"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_2ebd5bd711ceb8d6b4f6eba38d087bc9_6bf98dec17
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_2EBD5BD711CEB8D6B4F6EBA38D087BC9"
        original_filepath = "FannyWorm_2EBD5BD711CEB8D6B4F6EBA38D087BC9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_0d1248bd21ba2487c08691ee60b8d80e_654b5f16ef
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_0D1248BD21BA2487C08691EE60B8D80E"
        original_filepath = "FannyWorm_0D1248BD21BA2487C08691EE60B8D80E"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_90c8a317cba47d7e3525b69862ddef58_22736596e7
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_90C8A317CBA47D7E3525B69862DDEF58"
        original_filepath = "FannyWorm_90C8A317CBA47D7E3525B69862DDEF58"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_318d5e8b3da6c6f5e5041250ceb5d836_95685f7afc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_318D5E8B3DA6C6F5E5041250CEB5D836"
        original_filepath = "FannyWorm_318D5E8B3DA6C6F5E5041250CEB5D836"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_56d85656c527242b493d9b19cb95370e_c058ce4645
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_56D85656C527242B493D9B19CB95370E"
        original_filepath = "FannyWorm_56D85656C527242B493D9B19CB95370E"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_8738e487218905e86bf6ad7988929ecb_dedfd3c4f7
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_8738E487218905E86BF6AD7988929ECB"
        original_filepath = "FannyWorm_8738E487218905E86BF6AD7988929ECB"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_b38a91b1a5d23d418c5c6d6a0b066c30_8b22cf2d4c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_B38A91B1A5D23D418C5C6D6A0B066C30"
        original_filepath = "FannyWorm_B38A91B1A5D23D418C5C6D6A0B066C30"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_5b0f5f62ef3ae981fe48b6c29d7beab2_a9ae68adbe
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_5B0F5F62EF3AE981FE48B6C29D7BEAB2"
        original_filepath = "FannyWorm_5B0F5F62EF3AE981FE48B6C29D7BEAB2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_1d6c98e55203f0c51c0821fe52218dd8_f01e2be653
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_1D6C98E55203F0C51C0821FE52218DD8"
        original_filepath = "FannyWorm_1D6C98E55203F0C51C0821FE52218DD8"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_b11dbc0c4e98b4ca224c18344cc5191d_0bbf8dfc2f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_B11DBC0C4E98B4CA224C18344CC5191D"
        original_filepath = "FannyWorm_B11DBC0C4E98B4CA224C18344CC5191D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_545bee90a5f356b114ca3a4823f14990_a789ec07ff
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_545BEE90A5F356B114CA3A4823F14990"
        original_filepath = "FannyWorm_545BEE90A5F356B114CA3A4823F14990"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_4605a7396d892bba0646bc73a02b28e9_aba3e5581a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_4605A7396D892BBA0646BC73A02B28E9"
        original_filepath = "FannyWorm_4605A7396D892BBA0646BC73A02B28E9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_48bc620f4c5b14e30f173b0d02887840_bec2d6e790
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_48BC620F4C5B14E30F173B0D02887840"
        original_filepath = "FannyWorm_48BC620F4C5B14E30F173B0D02887840"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_2bb52b4c1bc0788bf701e6f5ee761a9b_2588cca67a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_2BB52B4C1BC0788BF701E6F5EE761A9B"
        original_filepath = "FannyWorm_2BB52B4C1BC0788BF701E6F5EE761A9B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a397a581c20bf93eb5c22cad5a2afcdd_db7ac916ee
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A397A581C20BF93EB5C22CAD5A2AFCDD"
        original_filepath = "FannyWorm_A397A581C20BF93EB5C22CAD5A2AFCDD"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_19507f6adfad9e754c3d26695dd61993_b3cccbe084
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_19507F6ADFAD9E754C3D26695DD61993"
        original_filepath = "FannyWorm_19507F6ADFAD9E754C3D26695DD61993"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_54c7657b4d19c6afaaf003a332704907_230140330b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_54C7657B4D19C6AFAAF003A332704907"
        original_filepath = "FannyWorm_54C7657B4D19C6AFAAF003A332704907"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_0c4bd72bd7119c562f81588978ac9def_b0475a8b32
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_0C4BD72BD7119C562F81588978AC9DEF"
        original_filepath = "FannyWorm_0C4BD72BD7119C562F81588978AC9DEF"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_12298ef995a76c71fa54cbf279455a14_7bd6475924
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_12298EF995A76C71FA54CBF279455A14"
        original_filepath = "FannyWorm_12298EF995A76C71FA54CBF279455A14"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_1355c1f173e78d3c1317ee2fb5cd95f1_1f53c56efb
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_1355C1F173E78D3C1317EE2FB5CD95F1"
        original_filepath = "FannyWorm_1355C1F173E78D3C1317EE2FB5CD95F1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_3ac8bc5e416d59666905489aea3be51e_6e940dd02e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_3AC8BC5E416D59666905489AEA3BE51E"
        original_filepath = "FannyWorm_3AC8BC5E416D59666905489AEA3BE51E"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_af426f4980ce7e2f771742bee1cc43df_668abfd591
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_AF426F4980CE7E2F771742BEE1CC43DF"
        original_filepath = "FannyWorm_AF426F4980CE7E2F771742BEE1CC43DF"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_963a24b864524dfa64ba4310537ce0e1_98200e53cc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_963A24B864524DFA64BA4310537CE0E1"
        original_filepath = "FannyWorm_963A24B864524DFA64BA4310537CE0E1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_19eb57e93ed64f2bb9aab0307ece4291_e0ce8715ee
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_19EB57E93ED64F2BB9AAB0307ECE4291"
        original_filepath = "FannyWorm_19EB57E93ED64F2BB9AAB0307ECE4291"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_263b761fcea771137f2ea9918e381b47_d2c4a63cff
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_263B761FCEA771137F2EA9918E381B47"
        original_filepath = "FannyWorm_263B761FCEA771137F2EA9918E381B47"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_487e79347d92f44507200792a7795c7b_8d7872906f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "FannyWorm_487E79347D92F44507200792A7795C7B"
        original_filepath = "FannyWorm_487E79347D92F44507200792A7795C7B"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fannyworm_1163ad598b617ef336dd75d119182ad4_c468934d71
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_1163AD598B617EF336DD75D119182AD4"
        original_filepath = "FannyWorm_1163AD598B617EF336DD75D119182AD4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_06a1824482848997877da3f5cb83f196_88ab31b22e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_06A1824482848997877DA3F5CB83F196"
        original_filepath = "FannyWorm_06A1824482848997877DA3F5CB83F196"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_2d088e08fd1b90342cae128770063dbe_9b98e8fd71
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_2D088E08FD1B90342CAE128770063DBE"
        original_filepath = "FannyWorm_2D088E08FD1B90342CAE128770063DBE"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_102a411051ef606241fbdc4361e55301_ec4fd2338d
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_102A411051EF606241FBDC4361E55301"
        original_filepath = "FannyWorm_102A411051EF606241FBDC4361E55301"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_bd9e6f35dc7fe987eefa048adc94d346_5b7a43d9cb
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_BD9E6F35DC7FE987EEFA048ADC94D346"
        original_filepath = "FannyWorm_BD9E6F35DC7FE987EEFA048ADC94D346"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_b59f5c408fba0e2cf503e0942ac46c56_6c5e824ca0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_B59F5C408FBA0E2CF503E0942AC46C56"
        original_filepath = "FannyWorm_B59F5C408FBA0E2CF503E0942AC46C56"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_21a6959a33909e3cdf27a455064d4d4d_5c70cf20dd
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_21A6959A33909E3CDF27A455064D4D4D"
        original_filepath = "FannyWorm_21A6959A33909E3CDF27A455064D4D4D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_595b08353458a0749d292e0e81c0fc01_47fe04ef74
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_595B08353458A0749D292E0E81C0FC01"
        original_filepath = "FannyWorm_595B08353458A0749D292E0E81C0FC01"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a84fd0164200ad1ad0e34eee9c663949_c53587b8dd
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A84FD0164200AD1AD0E34EEE9C663949"
        original_filepath = "FannyWorm_A84FD0164200AD1AD0E34EEE9C663949"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_38430b3311314a4dc01c2cdcd29a0d10_e4cbbcd670
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_38430B3311314A4DC01C2CDCD29A0D10"
        original_filepath = "FannyWorm_38430B3311314A4DC01C2CDCD29A0D10"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_0a78f4f0c5fc09c08dc1b54d7412bc58_cf4b8e50fb
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_0A78F4F0C5FC09C08DC1B54D7412BC58"
        original_filepath = "FannyWorm_0A78F4F0C5FC09C08DC1B54D7412BC58"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_a00101cfc1edd423cb34f758f8d0c62e_c77c2fd6aa
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_A00101CFC1EDD423CB34F758F8D0C62E"
        original_filepath = "FannyWorm_A00101CFC1EDD423CB34F758F8D0C62E"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_2c35ed272225b4e134333bea2b657a3f_6a1d202942
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "FannyWorm_2C35ED272225B4E134333BEA2B657A3F"
        original_filepath = "FannyWorm_2C35ED272225B4E134333BEA2B657A3F"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fannyworm_00f5f27098d25a1961df56a1c58398e2_6c217daed4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_00F5F27098D25A1961DF56A1C58398E2"
        original_filepath = "FannyWorm_00F5F27098D25A1961DF56A1C58398E2"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_4984608139e2c5430a87028f84a2bbb7_13d4204ebb
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_4984608139E2C5430A87028F84A2BBB7"
        original_filepath = "FannyWorm_4984608139E2C5430A87028F84A2BBB7"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_0fd329c0ecc34c45a87414e3daad5819_d4774fa235
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_0FD329C0ECC34C45A87414E3DAAD5819"
        original_filepath = "FannyWorm_0FD329C0ECC34C45A87414E3DAAD5819"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_21a9c4073dbb1cb6127fdb932c95372c_8ffdac002b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_21A9C4073DBB1CB6127FDB932C95372C"
        original_filepath = "FannyWorm_21A9C4073DBB1CB6127FDB932C95372C"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_1b9901d0f5f28c9275a697134d6e487a_4190c4d491
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_1B9901D0F5F28C9275A697134D6E487A"
        original_filepath = "FannyWorm_1B9901D0F5F28C9275A697134D6E487A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_abff989fba8b34539cddbdff0a79ee8d_f39f8db31b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_ABFF989FBA8B34539CDDBDFF0A79EE8D"
        original_filepath = "FannyWorm_ABFF989FBA8B34539CDDBDFF0A79EE8D"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_5a5bed7fae336b93c44b370a955182da_d0bf2d1ca9
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_5A5BED7FAE336B93C44B370A955182DA"
        original_filepath = "FannyWorm_5A5BED7FAE336B93C44B370A955182DA"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_07988b3b1af58a47f7ee884e734d9a45_049b9dd8c4
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_07988B3B1AF58A47F7EE884E734D9A45"
        original_filepath = "FannyWorm_07988B3B1AF58A47F7EE884E734D9A45"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_878a3d4b91875e10f032b58d5da3ddf1_37ce3a0974
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_878A3D4B91875E10F032B58D5DA3DDF1"
        original_filepath = "FannyWorm_878A3D4B91875E10F032B58D5DA3DDF1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_09344144f44e598e516793b36de7822a_7dfd104e32
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "FannyWorm_09344144F44E598E516793B36DE7822A"
        original_filepath = "FannyWorm_09344144F44E598E516793B36DE7822A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fannyworm_56897704c43dbfb60847a6dca00de2b0_763b08bf43
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_56897704C43DBFB60847A6DCA00DE2B0"
        original_filepath = "FannyWorm_56897704C43DBFB60847A6DCA00DE2B0"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_4810559ed364a18843178f1c4fca49fc_dd5eeb2bd6
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_4810559ED364A18843178F1C4FCA49FC"
        original_filepath = "FannyWorm_4810559ED364A18843178F1C4FCA49FC"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_6f073003704cc5b5265a0a9f8ee851d1_d9d716ba08
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_6F073003704CC5B5265A0A9F8EE851D1"
        original_filepath = "FannyWorm_6F073003704CC5B5265A0A9F8EE851D1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_2e208b3d5953bd92c84031d3a7b8a231_7505afa772
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_2E208B3D5953BD92C84031D3A7B8A231"
        original_filepath = "FannyWorm_2E208B3D5953BD92C84031D3A7B8A231"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_1173639e045c327554962500b6240eeb_9bb8db863e
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_1173639E045C327554962500B6240EEB"
        original_filepath = "FannyWorm_1173639E045C327554962500B6240EEB"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_70b0214530810773e46afa469a723ce3_26dc10249a
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_70B0214530810773E46AFA469A723CE3"
        original_filepath = "FannyWorm_70B0214530810773E46AFA469A723CE3"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_41d1e22fabd1ce4d21f5f7be352b3a07_e1947b7ddb
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "FannyWorm_41D1E22FABD1CE4D21F5F7BE352B3A07"
        original_filepath = "FannyWorm_41D1E22FABD1CE4D21F5F7BE352B3A07"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fannyworm_687f8bec9484257500976c336e103a08_245cab5c00
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_687F8BEC9484257500976C336E103A08"
        original_filepath = "FannyWorm_687F8BEC9484257500976C336E103A08"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_242a7137788b0f0aefcea5c233c951b7_56a43845cb
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_242A7137788B0F0AEFCEA5C233C951B7"
        original_filepath = "FannyWorm_242A7137788B0F0AEFCEA5C233C951B7"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_66a2a7ac521be856deed54fd8072d0e8_5c0748fbb1
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_66A2A7AC521BE856DEED54FD8072D0E8"
        original_filepath = "FannyWorm_66A2A7AC521BE856DEED54FD8072D0E8"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_91b1f4a4fa5c26473ab678408edcb913_385a57fe23
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_91B1F4A4FA5C26473AB678408EDCB913"
        original_filepath = "FannyWorm_91B1F4A4FA5C26473AB678408EDCB913"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_4ea931a432bb9555483b41b3bc8e78e4_f3c3925a65
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_4EA931A432BB9555483B41B3BC8E78E4"
        original_filepath = "FannyWorm_4EA931A432BB9555483B41B3BC8E78E4"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "cmd.exe" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_fannyworm_3a3fee2e8e1abdd99a020eeb8ee2d271_a2d243ffbc
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_3A3FEE2E8E1ABDD99A020EEB8EE2D271"
        original_filepath = "FannyWorm_3A3FEE2E8E1ABDD99A020EEB8EE2D271"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_17d287e868ab1dbafca87eb48b0f848f_89f139e0e0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_17D287E868AB1DBAFCA87EB48B0F848F"
        original_filepath = "FannyWorm_17D287E868AB1DBAFCA87EB48B0F848F"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_b78e9c9a49aa507cb1f905fdd455ca35_d3f3bf5524
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_B78E9C9A49AA507CB1F905FDD455CA35"
        original_filepath = "FannyWorm_B78E9C9A49AA507CB1F905FDD455CA35"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_205fb6034381dfd9d19d076141397cf6_6f0b5d386c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_205FB6034381DFD9D19D076141397CF6"
        original_filepath = "FannyWorm_205FB6034381DFD9D19D076141397CF6"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_bb5aa3e042c802c294fa233c4db41393_dcbe715566
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_BB5AA3E042C802C294FA233C4DB41393"
        original_filepath = "FannyWorm_BB5AA3E042C802C294FA233C4DB41393"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_85cee5aaa59cacad80bf9792869845ba_fb229ae028
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_85CEE5AAA59CACAD80BF9792869845BA"
        original_filepath = "FannyWorm_85CEE5AAA59CACAD80BF9792869845BA"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_3a431d965b9537721be721a48cccdf0a_2dcda2e61f
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_3A431D965B9537721BE721A48CCCDF0A"
        original_filepath = "FannyWorm_3A431D965B9537721BE721A48CCCDF0A"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_5686e5cdb415f7fb65a4a3d971f24e1c_4c388c55f2
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_5686E5CDB415F7FB65A4A3D971F24E1C"
        original_filepath = "FannyWorm_5686E5CDB415F7FB65A4A3D971F24E1C"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_8b1fe26a399f54cee44493859c6e82ac_c91165fa9c
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_8B1FE26A399F54CEE44493859C6E82AC"
        original_filepath = "FannyWorm_8B1FE26A399F54CEE44493859C6E82AC"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_44bd4cf5e28d78cc66b828a57c99ca74_99dbbdd5c5
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_44BD4CF5E28D78CC66B828A57C99CA74"
        original_filepath = "FannyWorm_44BD4CF5E28D78CC66B828A57C99CA74"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_fannyworm_94271ae895e359b606252395df952f5f_70bca45e73
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, explorer.exe, .dll"
        filename = "FannyWorm_94271AE895E359B606252395DF952F5F"
        original_filepath = "FannyWorm_94271AE895E359B606252395DF952F5F"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "explorer.exe" nocase ascii wide
        $g2 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2)
}


rule Generic_Suspicious_Strings_dellxt_dll_72566e18f8
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, rundll32.exe, explorer.exe"
        filename = "DELLXT.dll"
        original_filepath = "DELLXT.dll"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "rundll32.exe" nocase ascii wide
        $g2 = "explorer.exe" nocase ascii wide
        $g3 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_4e39bc95e35323ab586d740725a1c8cbcde01fe453f7c4cac7cced9a26e42cc9_c8941d4f0b
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "4e39bc95e35323ab586d740725a1c8cbcde01fe453f7c4cac7cced9a26e42cc9"
        original_filepath = "4e39bc95e35323ab586d740725a1c8cbcde01fe453f7c4cac7cced9a26e42cc9"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}


rule Generic_Suspicious_Strings_jpeg1x32_dll_c2ba81c0de01038a54703de26b18e9ee_c6e8ea8cb0
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "jpeg1x32.dll_C2BA81C0DE01038A54703DE26B18E9EE"
        original_filepath = "jpeg1x32.dll_C2BA81C0DE01038A54703DE26B18E9EE"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_jigsaw_9e674c31ee
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, http://, .dll"
        filename = "jigsaw"
        original_filepath = "jigsaw"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = "http://" nocase ascii wide
        $g2 = ".dll" nocase ascii wide
        $g3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase ascii wide

    condition:
        any of ($g0,$g1,$g2,$g3)
}


rule Generic_Suspicious_Strings_3_4_exe_68f1571394
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .dll"
        filename = "3_4.exe"
        original_filepath = "3_4.exe"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".dll" nocase ascii wide

    condition:
        any of ($g0)
}


rule Generic_Suspicious_Strings_20240431d6eb6816453651b58b37f53950fcc3f0929813806525c5fd97cdc0e1_a5ddd3e258
{
    meta:
        author = "Your Team"
        date = "N/A"
        description = "Detects generic suspicious strings like .exe, .dll"
        filename = "20240431d6eb6816453651b58b37f53950fcc3f0929813806525c5fd97cdc0e1"
        original_filepath = "20240431d6eb6816453651b58b37f53950fcc3f0929813806525c5fd97cdc0e1"
        source = "MCP Rule Generator - Generic Strings"
        severity = "low"
        category = "Generic"

    strings:
        $g0 = ".exe" nocase ascii wide
        $g1 = ".dll" nocase ascii wide

    condition:
        any of ($g0,$g1)
}

