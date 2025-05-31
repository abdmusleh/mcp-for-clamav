import "hash"

// Part 3 of 1442 rules


rule SuspiciousStrings_FannyWorm_1B27AC722847F5A3304E3896F0528FA4_1b27ac722847f5a3304e3896f0528fa4
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1B27AC722847F5A3304E3896F0528FA4"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1B9901D0F5F28C9275A697134D6E487A_1b9901d0f5f28c9275a697134d6e487a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1B9901D0F5F28C9275A697134D6E487A"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1CB7AE1BC76E139C89684F7797F520A1_1cb7ae1bc76e139c89684f7797f520a1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1CB7AE1BC76E139C89684F7797F520A1"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1D6C98E55203F0C51C0821FE52218DD8_1d6c98e55203f0c51c0821fe52218dd8
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1D6C98E55203F0C51C0821FE52218DD8"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1DD86B28A2BC986B069C75BF5C6787B9_1dd86b28a2bc986b069c75bf5c6787b9
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1DD86B28A2BC986B069C75BF5C6787B9"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1EF39EB63DDFF30A3E37FEEFFB8FC712_1ef39eb63ddff30a3e37feeffb8fc712
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1EF39EB63DDFF30A3E37FEEFFB8FC712"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1F1DC3CF1D769D464DB9752C8CECC872_1f1dc3cf1d769d464db9752c8cecc872
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1F1DC3CF1D769D464DB9752C8CECC872"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "rundll32.exe" nocase
            $s3 = "explorer.exe" nocase
            $s4 = "createprocess" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "advapi32.dll" nocase
            $s8 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1F69160F1D91BF9A0EDA93829B75C583_1f69160f1d91bf9a0eda93829b75c583
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1F69160F1D91BF9A0EDA93829B75C583"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_1FD210BA936FD11B46781E04BBC0F8B5_1fd210ba936fd11b46781e04bbc0f8b5
{
    meta:
        description = "Detects suspicious strings in FannyWorm_1FD210BA936FD11B46781E04BBC0F8B5"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_205FB6034381DFD9D19D076141397CF6_205fb6034381dfd9d19d076141397cf6
{
    meta:
        description = "Detects suspicious strings in FannyWorm_205FB6034381DFD9D19D076141397CF6"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2062D7B0D9145ADBE0131CF1FB1FC35A_2062d7b0d9145adbe0131cf1fb1fc35a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2062D7B0D9145ADBE0131CF1FB1FC35A"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_21A6959A33909E3CDF27A455064D4D4D_21a6959a33909e3cdf27a455064d4d4d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_21A6959A33909E3CDF27A455064D4D4D"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_21A9C4073DBB1CB6127FDB932C95372C_21a9c4073dbb1cb6127fdb932c95372c
{
    meta:
        description = "Detects suspicious strings in FannyWorm_21A9C4073DBB1CB6127FDB932C95372C"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2249D5577D2C84BA1043376B77E6C24D_2249d5577d2c84ba1043376b77e6c24d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2249D5577D2C84BA1043376B77E6C24D"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_22DB66045FA1E39B5BF16FC63A850098_22db66045fa1e39b5bf16fc63a850098
{
    meta:
        description = "Detects suspicious strings in FannyWorm_22DB66045FA1E39B5BF16FC63A850098"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_24132E1E00071F33221C405399271B74_24132e1e00071f33221c405399271b74
{
    meta:
        description = "Detects suspicious strings in FannyWorm_24132E1E00071F33221C405399271B74"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_242A7137788B0F0AEFCEA5C233C951B7_242a7137788b0f0aefcea5c233c951b7
{
    meta:
        description = "Detects suspicious strings in FannyWorm_242A7137788B0F0AEFCEA5C233C951B7"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_246272DD6E9193E31745AD54138F875D_246272dd6e9193e31745ad54138f875d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_246272DD6E9193E31745AD54138F875D"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_263B761FCEA771137F2EA9918E381B47_263b761fcea771137f2ea9918e381b47
{
    meta:
        description = "Detects suspicious strings in FannyWorm_263B761FCEA771137F2EA9918E381B47"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_26C46A09CF1BDFF5AF503A406575809D_26c46a09cf1bdff5af503a406575809d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_26C46A09CF1BDFF5AF503A406575809D"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_27C5D028EE23A515DF4203EA6026E23E_27c5d028ee23a515df4203ea6026e23e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_27C5D028EE23A515DF4203EA6026E23E"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2822D46611AD7FD71DFE5A1F4C79AB4B_2822d46611ad7fd71dfe5a1f4c79ab4b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2822D46611AD7FD71DFE5A1F4C79AB4B"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_29F2AB09FDFFC4006A4407C05BA11B65_29f2ab09fdffc4006a4407c05ba11b65
{
    meta:
        description = "Detects suspicious strings in FannyWorm_29F2AB09FDFFC4006A4407C05BA11B65"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_29FDEC2FD992C2AB38E1DD41500190B9_29fdec2fd992c2ab38e1dd41500190b9
{
    meta:
        description = "Detects suspicious strings in FannyWorm_29FDEC2FD992C2AB38E1DD41500190B9"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2BB52B4C1BC0788BF701E6F5EE761A9B_2bb52b4c1bc0788bf701e6f5ee761a9b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2BB52B4C1BC0788BF701E6F5EE761A9B"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2C029BE8E3B0C9448ED5E88B52852ADE_2c029be8e3b0c9448ed5e88b52852ade
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2C029BE8E3B0C9448ED5E88B52852ADE"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2C35ED272225B4E134333BEA2B657A3F_2c35ed272225b4e134333bea2b657a3f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2C35ED272225B4E134333BEA2B657A3F"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "rundll32.exe" nocase
            $s3 = "explorer.exe" nocase
            $s4 = "createprocess" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "advapi32.dll" nocase
            $s8 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2C6595834DD5528235E8A9815276563E_2c6595834dd5528235e8a9815276563e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2C6595834DD5528235E8A9815276563E"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2C87A3442C60C72F639CA7EB6754746A_2c87a3442c60c72f639ca7eb6754746a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2C87A3442C60C72F639CA7EB6754746A"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2D088E08FD1B90342CAE128770063DBE_2d088e08fd1b90342cae128770063dbe
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2D088E08FD1B90342CAE128770063DBE"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2DA059A8BF3BC00BB809B28770044FF6_2da059a8bf3bc00bb809b28770044ff6
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2DA059A8BF3BC00BB809B28770044FF6"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2E0E43F2B0499D631EDF1DD92F09BD2C_2e0e43f2b0499d631edf1dd92f09bd2c
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2E0E43F2B0499D631EDF1DD92F09BD2C"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2E208B3D5953BD92C84031D3A7B8A231_2e208b3d5953bd92c84031d3a7b8a231
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2E208B3D5953BD92C84031D3A7B8A231"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2EBD5BD711CEB8D6B4F6EBA38D087BC9_2ebd5bd711ceb8d6b4f6eba38d087bc9
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2EBD5BD711CEB8D6B4F6EBA38D087BC9"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_2F2A8DECA2539923B489D51DE9A278F4_2f2a8deca2539923b489d51de9a278f4
{
    meta:
        description = "Detects suspicious strings in FannyWorm_2F2A8DECA2539923B489D51DE9A278F4"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_303B7527DB5B417719DAF9B0AE5B89AA_303b7527db5b417719daf9b0ae5b89aa
{
    meta:
        description = "Detects suspicious strings in FannyWorm_303B7527DB5B417719DAF9B0AE5B89AA"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "rundll32.exe" nocase
            $s3 = "explorer.exe" nocase
            $s4 = "createprocess" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "advapi32.dll" nocase
            $s8 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_31457CB30CCAD20CDBC77B8C4B6F9B3F_31457cb30ccad20cdbc77b8c4b6f9b3f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_31457CB30CCAD20CDBC77B8C4B6F9B3F"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_318D5E8B3DA6C6F5E5041250CEB5D836_318d5e8b3da6c6f5e5041250ceb5d836
{
    meta:
        description = "Detects suspicious strings in FannyWorm_318D5E8B3DA6C6F5E5041250CEB5D836"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_38430B3311314A4DC01C2CDCD29A0D10_38430b3311314a4dc01c2cdcd29a0d10
{
    meta:
        description = "Detects suspicious strings in FannyWorm_38430B3311314A4DC01C2CDCD29A0D10"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3A3FEE2E8E1ABDD99A020EEB8EE2D271_3a3fee2e8e1abdd99a020eeb8ee2d271
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3A3FEE2E8E1ABDD99A020EEB8EE2D271"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3A431D965B9537721BE721A48CCCDF0A_3a431d965b9537721be721a48cccdf0a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3A431D965B9537721BE721A48CCCDF0A"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3A57ADB8740DA3EBEC1673D21F20D0FE_3a57adb8740da3ebec1673d21f20d0fe
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3A57ADB8740DA3EBEC1673D21F20D0FE"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3A71446564B4C060D99A8CCD2EB5D161_3a71446564b4c060d99a8ccd2eb5d161
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3A71446564B4C060D99A8CCD2EB5D161"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3AC8BC5E416D59666905489AEA3BE51E_3ac8bc5e416d59666905489aea3be51e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3AC8BC5E416D59666905489AEA3BE51E"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3B496B8CD19789FABF00584475B607C7_3b496b8cd19789fabf00584475b607c7
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3B496B8CD19789FABF00584475B607C7"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3DE3419F6441A7F4D664077A43FB404B_3de3419f6441a7f4d664077a43fb404b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3DE3419F6441A7F4D664077A43FB404B"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "rundll32.exe" nocase
            $s3 = "explorer.exe" nocase
            $s4 = "createprocess" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "advapi32.dll" nocase
            $s8 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_3FBD798BCD7214FCBF5FAB05FAF9FD71_3fbd798bcd7214fcbf5fab05faf9fd71
{
    meta:
        description = "Detects suspicious strings in FannyWorm_3FBD798BCD7214FCBF5FAB05FAF9FD71"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_40000B4F52DCDEDB1E1D3BFD5C185CEC_40000b4f52dcdedb1e1d3bfd5c185cec
{
    meta:
        description = "Detects suspicious strings in FannyWorm_40000B4F52DCDEDB1E1D3BFD5C185CEC"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_40FEE20FE98995ACBDA82DBCDE0B674B_40fee20fe98995acbda82dbcde0b674b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_40FEE20FE98995ACBDA82DBCDE0B674B"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_41D1E22FABD1CE4D21F5F7BE352B3A07_41d1e22fabd1ce4d21f5f7be352b3a07
{
    meta:
        description = "Detects suspicious strings in FannyWorm_41D1E22FABD1CE4D21F5F7BE352B3A07"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "rundll32.exe" nocase
            $s3 = "explorer.exe" nocase
            $s4 = "createprocess" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "advapi32.dll" nocase
            $s8 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_44BD4CF5E28D78CC66B828A57C99CA74_44bd4cf5e28d78cc66b828a57c99ca74
{
    meta:
        description = "Detects suspicious strings in FannyWorm_44BD4CF5E28D78CC66B828A57C99CA74"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4509385E247EF538CFB8CD42944EE480_4509385e247ef538cfb8cd42944ee480
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4509385E247EF538CFB8CD42944EE480"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_450A3EDECE8808F483203FE8988C4437_450a3edece8808f483203fe8988c4437
{
    meta:
        description = "Detects suspicious strings in FannyWorm_450A3EDECE8808F483203FE8988C4437"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4605A7396D892BBA0646BC73A02B28E9_4605a7396d892bba0646bc73a02b28e9
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4605A7396D892BBA0646BC73A02B28E9"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4810559ED364A18843178F1C4FCA49FC_4810559ed364a18843178f1c4fca49fc
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4810559ED364A18843178F1C4FCA49FC"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_487E79347D92F44507200792A7795C7B_487e79347d92f44507200792a7795c7b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_487E79347D92F44507200792A7795C7B"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "rundll32.exe" nocase
            $s3 = "explorer.exe" nocase
            $s4 = "createprocess" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "advapi32.dll" nocase
            $s8 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_48BC620F4C5B14E30F173B0D02887840_48bc620f4c5b14e30f173b0d02887840
{
    meta:
        description = "Detects suspicious strings in FannyWorm_48BC620F4C5B14E30F173B0D02887840"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_48E958E3785BE0D5E074AD2CFCF2FEE4_48e958e3785be0d5e074ad2cfcf2fee4
{
    meta:
        description = "Detects suspicious strings in FannyWorm_48E958E3785BE0D5E074AD2CFCF2FEE4"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4902CD32C4AE98008BA24C0F40189E51_4902cd32c4ae98008ba24c0f40189e51
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4902CD32C4AE98008BA24C0F40189E51"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_49622DDF195628F7A3400B7A9F98E60A_49622ddf195628f7a3400b7a9f98e60a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_49622DDF195628F7A3400B7A9F98E60A"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4984608139E2C5430A87028F84A2BBB7_4984608139e2c5430a87028f84a2bbb7
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4984608139E2C5430A87028F84A2BBB7"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_49CB69039308B2613664515C5FA323E1_49cb69039308b2613664515c5fa323e1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_49CB69039308B2613664515C5FA323E1"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4A3B537879F3F29CD8D446C53E6B06C3_4a3b537879f3f29cd8d446c53e6b06c3
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4A3B537879F3F29CD8D446C53E6B06C3"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4AD2F62CE2EB72EFF45C61699BDCB1E3_4ad2f62ce2eb72eff45c61699bdcb1e3
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4AD2F62CE2EB72EFF45C61699BDCB1E3"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4C31FE56FF4A46FBCD87B28651235177_4c31fe56ff4a46fbcd87b28651235177
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4C31FE56FF4A46FBCD87B28651235177"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4E58BD45A388E458C9F8FF09EB905CC0_4e58bd45a388e458c9f8ff09eb905cc0
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4E58BD45A388E458C9F8FF09EB905CC0"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4EA931A432BB9555483B41B3BC8E78E4_4ea931a432bb9555483b41b3bc8e78e4
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4EA931A432BB9555483B41B3BC8E78E4"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "cmd.exe" nocase
            $s3 = "explorer.exe" nocase
            $s4 = "createprocess" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "advapi32.dll" nocase
            $s8 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4F79981D1F7091BE6AADCC4595EF5F76_4f79981d1f7091be6aadcc4595ef5f76
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4F79981D1F7091BE6AADCC4595EF5F76"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_4FD969CEFB161CBBFE26897F097EDA71_4fd969cefb161cbbfe26897f097eda71
{
    meta:
        description = "Detects suspicious strings in FannyWorm_4FD969CEFB161CBBFE26897F097EDA71"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5118F69983A1544CAF4E3D244E195304_5118f69983a1544caf4e3d244e195304
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5118F69983A1544CAF4E3D244E195304"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5328361825D0B1CCB0B157CEFF4E883E_5328361825d0b1ccb0b157ceff4e883e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5328361825D0B1CCB0B157CEFF4E883E"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_545BEE90A5F356B114CA3A4823F14990_545bee90a5f356b114ca3a4823f14990
{
    meta:
        description = "Detects suspicious strings in FannyWorm_545BEE90A5F356B114CA3A4823F14990"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_54C7657B4D19C6AFAAF003A332704907_54c7657b4d19c6afaaf003a332704907
{
    meta:
        description = "Detects suspicious strings in FannyWorm_54C7657B4D19C6AFAAF003A332704907"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_54D7826F13C1116B0BE9077334713F1A_54d7826f13c1116b0be9077334713f1a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_54D7826F13C1116B0BE9077334713F1A"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_564950A5F4B3CA0E6ADE94C5CA5D8DE1_564950a5f4b3ca0e6ade94c5ca5d8de1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_564950A5F4B3CA0E6ADE94C5CA5D8DE1"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5686E5CDB415F7FB65A4A3D971F24E1C_5686e5cdb415f7fb65a4a3d971f24e1c
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5686E5CDB415F7FB65A4A3D971F24E1C"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_56897704C43DBFB60847A6DCA00DE2B0_56897704c43dbfb60847a6dca00de2b0
{
    meta:
        description = "Detects suspicious strings in FannyWorm_56897704C43DBFB60847A6DCA00DE2B0"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_56D85656C527242B493D9B19CB95370E_56d85656c527242b493d9b19cb95370e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_56D85656C527242B493D9B19CB95370E"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_56FF71E1F28E1F149E0E4CF8CE9811D1_56ff71e1f28e1f149e0e4cf8ce9811d1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_56FF71E1F28E1F149E0E4CF8CE9811D1"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_57B64A212B4B3982793916A18FA4F489_57b64a212b4b3982793916a18fa4f489
{
    meta:
        description = "Detects suspicious strings in FannyWorm_57B64A212B4B3982793916A18FA4F489"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5821380182C7BFAA6646DB4313449917_5821380182c7bfaa6646db4313449917
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5821380182C7BFAA6646DB4313449917"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_58786E35FA1D61D1BCD671987D103957_58786e35fa1d61d1bcd671987d103957
{
    meta:
        description = "Detects suspicious strings in FannyWorm_58786E35FA1D61D1BCD671987D103957"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_58EF8790939FCA73A20C6A04717A2659_58ef8790939fca73a20c6a04717a2659
{
    meta:
        description = "Detects suspicious strings in FannyWorm_58EF8790939FCA73A20C6A04717A2659"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_595B08353458A0749D292E0E81C0FC01_595b08353458a0749d292e0e81c0fc01
{
    meta:
        description = "Detects suspicious strings in FannyWorm_595B08353458A0749D292E0E81C0FC01"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5A5BED7FAE336B93C44B370A955182DA_5a5bed7fae336b93c44b370a955182da
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5A5BED7FAE336B93C44B370A955182DA"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5A723D3EF02DB234061C2F61A6E3B6A4_5a723d3ef02db234061c2f61a6e3b6a4
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5A723D3EF02DB234061C2F61A6E3B6A4"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5A7DACC0C0F34005AB9710E666128500_5a7dacc0c0f34005ab9710e666128500
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5A7DACC0C0F34005AB9710E666128500"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5B0F5F62EF3AE981FE48B6C29D7BEAB2_5b0f5f62ef3ae981fe48b6c29d7beab2
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5B0F5F62EF3AE981FE48B6C29D7BEAB2"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5BEC4783C551C46B15F7C5B20F94F4B9_5bec4783c551c46b15f7c5b20f94f4b9
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5BEC4783C551C46B15F7C5B20F94F4B9"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5DC172E2C96B79EA7D855339F1B2403C_5dc172e2c96b79ea7d855339f1b2403c
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5DC172E2C96B79EA7D855339F1B2403C"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5E171B3A31279F9FCF21888AC0034B06_5e171b3a31279f9fcf21888ac0034b06
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5E171B3A31279F9FCF21888AC0034B06"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5F5ABBE2E637D4F0B8AFE7F2342C2942_5f5abbe2e637d4f0b8afe7f2342c2942
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5F5ABBE2E637D4F0B8AFE7F2342C2942"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_5FF0E69BF258375E7EEFCC5AC3BDCF24_5ff0e69bf258375e7eefcc5ac3bdcf24
{
    meta:
        description = "Detects suspicious strings in FannyWorm_5FF0E69BF258375E7EEFCC5AC3BDCF24"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_600984D541D399B1894745B917E5380B_600984d541d399b1894745b917e5380b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_600984D541D399B1894745B917E5380B"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_60D21EE6548DE4673CBDDEF2D779ED24_60d21ee6548de4673cbddef2d779ed24
{
    meta:
        description = "Detects suspicious strings in FannyWorm_60D21EE6548DE4673CBDDEF2D779ED24"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_63B2F98548174142F92FDFD995A2C70A_63b2f98548174142f92fdfd995a2c70a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_63B2F98548174142F92FDFD995A2C70A"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_63ECB7FE79A5B541C35765CAF424A021_63ecb7fe79a5b541c35765caf424a021
{
    meta:
        description = "Detects suspicious strings in FannyWorm_63ECB7FE79A5B541C35765CAF424A021"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_6436A4FB7A8F37AC934C275D325208E6_6436a4fb7a8f37ac934c275d325208e6
{
    meta:
        description = "Detects suspicious strings in FannyWorm_6436A4FB7A8F37AC934C275D325208E6"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_64A58CF7E810A77A5105D56B81AE8200_64a58cf7e810a77a5105d56b81ae8200
{
    meta:
        description = "Detects suspicious strings in FannyWorm_64A58CF7E810A77A5105D56B81AE8200"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_66A2A7AC521BE856DEED54FD8072D0E8_66a2a7ac521be856deed54fd8072d0e8
{
    meta:
        description = "Detects suspicious strings in FannyWorm_66A2A7AC521BE856DEED54FD8072D0E8"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_6814B21455DEB552DF3B452EF0551EC1_6814b21455deb552df3b452ef0551ec1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_6814B21455DEB552DF3B452EF0551EC1"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_682C987506651FCAE56C32FFA1F70170_682c987506651fcae56c32ffa1f70170
{
    meta:
        description = "Detects suspicious strings in FannyWorm_682C987506651FCAE56C32FFA1F70170"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_687F8BEC9484257500976C336E103A08_687f8bec9484257500976c336e103a08
{
    meta:
        description = "Detects suspicious strings in FannyWorm_687F8BEC9484257500976C336E103A08"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_688526EDBEA2D61664EC629F6558365C_688526edbea2d61664ec629f6558365c
{
    meta:
        description = "Detects suspicious strings in FannyWorm_688526EDBEA2D61664EC629F6558365C"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_68892E329FA28FE751B9EB16928EA98D_68892e329fa28fe751b9eb16928ea98d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_68892E329FA28FE751B9EB16928EA98D"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_68E6EE88BA44ED0B9DE93D6812B5255E_68e6ee88ba44ed0b9de93d6812b5255e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_68E6EE88BA44ED0B9DE93D6812B5255E"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_6DA22F42139A4A2365E7A9068D7B908A_6da22f42139a4a2365e7a9068d7b908a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_6DA22F42139A4A2365E7A9068D7B908A"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_6DE614AD2B4D03F9DFCDF0251737D33D_6de614ad2b4d03f9dfcdf0251737d33d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_6DE614AD2B4D03F9DFCDF0251737D33D"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_6E4F77DCDBB034CB4073D8C46BF23AE3_6e4f77dcdbb034cb4073d8c46bf23ae3
{
    meta:
        description = "Detects suspicious strings in FannyWorm_6E4F77DCDBB034CB4073D8C46BF23AE3"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_6F073003704CC5B5265A0A9F8EE851D1_6f073003704cc5b5265a0a9f8ee851d1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_6F073003704CC5B5265A0A9F8EE851D1"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_70B0214530810773E46AFA469A723CE3_70b0214530810773e46afa469a723ce3
{
    meta:
        description = "Detects suspicious strings in FannyWorm_70B0214530810773E46AFA469A723CE3"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_72312F1E2AE6900F169A2B7A88E14D93_72312f1e2ae6900f169a2b7a88e14d93
{
    meta:
        description = "Detects suspicious strings in FannyWorm_72312F1E2AE6900F169A2B7A88E14D93"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_72B16929F43533AC4BF953D90A52EB37_72b16929f43533ac4bf953d90a52eb37
{
    meta:
        description = "Detects suspicious strings in FannyWorm_72B16929F43533AC4BF953D90A52EB37"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_72F244452DF28865B37317369C33927D_72f244452df28865b37317369c33927d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_72F244452DF28865B37317369C33927D"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_74621A05BAFB868BDA8AEB6562DD36DF_74621a05bafb868bda8aeb6562dd36df
{
    meta:
        description = "Detects suspicious strings in FannyWorm_74621A05BAFB868BDA8AEB6562DD36DF"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_74AD35F0F4342F45038860CA0564AB8B_74ad35f0f4342f45038860ca0564ab8b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_74AD35F0F4342F45038860CA0564AB8B"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_75AC44F173AF6ACE7CC06E8406B03D33_75ac44f173af6ace7cc06e8406b03d33
{
    meta:
        description = "Detects suspicious strings in FannyWorm_75AC44F173AF6ACE7CC06E8406B03D33"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_769C62FDD6E1D2C5D51094E2882886B0_769c62fdd6e1d2c5d51094e2882886b0
{
    meta:
        description = "Detects suspicious strings in FannyWorm_769C62FDD6E1D2C5D51094E2882886B0"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_7808586DEC24D04567582F9CBD26EAD8_7808586dec24d04567582f9cbd26ead8
{
    meta:
        description = "Detects suspicious strings in FannyWorm_7808586DEC24D04567582F9CBD26EAD8"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_782E5C2D319063405414D4E55D3DCFB3_782e5c2d319063405414d4e55d3dcfb3
{
    meta:
        description = "Detects suspicious strings in FannyWorm_782E5C2D319063405414D4E55D3DCFB3"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_78B1FF3B04FAC35C890462225C5FBC49_78b1ff3b04fac35c890462225c5fbc49
{
    meta:
        description = "Detects suspicious strings in FannyWorm_78B1FF3B04FAC35C890462225C5FBC49"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_7CCCAF9B08301D2C2ACB647EA04CA8E1_7cccaf9b08301d2c2acb647ea04ca8e1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_7CCCAF9B08301D2C2ACB647EA04CA8E1"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_7E6348F56508E43C900265EE5297B577_7e6348f56508e43c900265ee5297b577
{
    meta:
        description = "Detects suspicious strings in FannyWorm_7E6348F56508E43C900265EE5297B577"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_7FAABCE7D2564176480769A9D7B34A2C_7faabce7d2564176480769a9d7b34a2c
{
    meta:
        description = "Detects suspicious strings in FannyWorm_7FAABCE7D2564176480769A9D7B34A2C"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8010AF50404647200A7BB51DE08AB960_8010af50404647200a7bb51de08ab960
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8010AF50404647200A7BB51DE08AB960"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8051E04BAB3A6DB6226CC4D08890E934_8051e04bab3a6db6226cc4d08890e934
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8051E04BAB3A6DB6226CC4D08890E934"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
            $s6 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8568A1CFA314525F49C98FAFBF85D14B_8568a1cfa314525f49c98fafbf85d14b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8568A1CFA314525F49C98FAFBF85D14B"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_85CEE5AAA59CACAD80BF9792869845BA_85cee5aaa59cacad80bf9792869845ba
{
    meta:
        description = "Detects suspicious strings in FannyWorm_85CEE5AAA59CACAD80BF9792869845BA"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_86D89BAC8A165FCE91426BF84EB7B7FC_86d89bac8a165fce91426bf84eb7b7fc
{
    meta:
        description = "Detects suspicious strings in FannyWorm_86D89BAC8A165FCE91426BF84EB7B7FC"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "rundll32.exe" nocase
            $s3 = "explorer.exe" nocase
            $s4 = "createprocess" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "advapi32.dll" nocase
            $s8 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_872E8E7C381FB805B87B88F31F77A772_872e8e7c381fb805b87b88f31f77a772
{
    meta:
        description = "Detects suspicious strings in FannyWorm_872E8E7C381FB805B87B88F31F77A772"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "rundll32.exe" nocase
            $s3 = "explorer.exe" nocase
            $s4 = "createprocess" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "advapi32.dll" nocase
            $s8 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8738E487218905E86BF6AD7988929ECB_8738e487218905e86bf6ad7988929ecb
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8738E487218905E86BF6AD7988929ECB"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_878A3D4B91875E10F032B58D5DA3DDF1_878a3d4b91875e10f032b58d5da3ddf1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_878A3D4B91875E10F032B58D5DA3DDF1"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_88E4147EFABA886FF16D6F058E8A25A6_88e4147efaba886ff16d6f058e8a25a6
{
    meta:
        description = "Detects suspicious strings in FannyWorm_88E4147EFABA886FF16D6F058E8A25A6"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_89C216DF6B2B1A335738847A1F1A6CBC_89c216df6b2b1a335738847a1f1a6cbc
{
    meta:
        description = "Detects suspicious strings in FannyWorm_89C216DF6B2B1A335738847A1F1A6CBC"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8A41A5AD3AE353F16FF2FD92E8046AC3_8a41a5ad3ae353f16ff2fd92e8046ac3
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8A41A5AD3AE353F16FF2FD92E8046AC3"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8AD46BB2D0BEF97548EBBED2F6EEA2E1_8ad46bb2d0bef97548ebbed2f6eea2e1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8AD46BB2D0BEF97548EBBED2F6EEA2E1"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8B1FE26A399F54CEE44493859C6E82AC_8b1fe26a399f54cee44493859c6e82ac
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8B1FE26A399F54CEE44493859C6E82AC"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8BAADB392A85A187360FCA5A4E56E6CF_8baadb392a85a187360fca5a4e56e6cf
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8BAADB392A85A187360FCA5A4E56E6CF"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8BB0C5181D8AB57B879DEA3F987FBEDF_8bb0c5181d8ab57b879dea3f987fbedf
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8BB0C5181D8AB57B879DEA3F987FBEDF"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "rundll32.exe" nocase
            $s3 = "explorer.exe" nocase
            $s4 = "createprocess" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "advapi32.dll" nocase
            $s8 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8C7EF91A96E75C3D05EA5E54A0E9356C_8c7ef91a96e75c3d05ea5e54a0e9356c
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8C7EF91A96E75C3D05EA5E54A0E9356C"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8E555220BD7F8C183ABF58071851E2B4_8e555220bd7f8c183abf58071851e2b4
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8E555220BD7F8C183ABF58071851E2B4"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_8FE19689CC16FEA06BDFC9C39C515FA3_8fe19689cc16fea06bdfc9c39c515fa3
{
    meta:
        description = "Detects suspicious strings in FannyWorm_8FE19689CC16FEA06BDFC9C39C515FA3"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_90C8A317CBA47D7E3525B69862DDEF58_90c8a317cba47d7e3525b69862ddef58
{
    meta:
        description = "Detects suspicious strings in FannyWorm_90C8A317CBA47D7E3525B69862DDEF58"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_9120C2A26E1F4DC362CA338B8E014B20_9120c2a26e1f4dc362ca338b8e014b20
{
    meta:
        description = "Detects suspicious strings in FannyWorm_9120C2A26E1F4DC362CA338B8E014B20"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_91B1F4A4FA5C26473AB678408EDCB913_91b1f4a4fa5c26473ab678408edcb913
{
    meta:
        description = "Detects suspicious strings in FannyWorm_91B1F4A4FA5C26473AB678408EDCB913"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_939706730193E6BCFEB991DE4387BD3F_939706730193e6bcfeb991de4387bd3f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_939706730193E6BCFEB991DE4387BD3F"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_93B22ECC56A91F251D5E023A5C20B3A4_93b22ecc56a91f251d5e023a5c20b3a4
{
    meta:
        description = "Detects suspicious strings in FannyWorm_93B22ECC56A91F251D5E023A5C20B3A4"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_94271AE895E359B606252395DF952F5F_94271ae895e359b606252395df952f5f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_94271AE895E359B606252395DF952F5F"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_948603BD138DD8487FAAB3C0DA5EB573_948603bd138dd8487faab3c0da5eb573
{
    meta:
        description = "Detects suspicious strings in FannyWorm_948603BD138DD8487FAAB3C0DA5EB573"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_9563FD4AB7D619D565B47CD16104DC66_9563fd4ab7d619d565b47cd16104dc66
{
    meta:
        description = "Detects suspicious strings in FannyWorm_9563FD4AB7D619D565B47CD16104DC66"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_963A24B864524DFA64BA4310537CE0E1_963a24b864524dfa64ba4310537ce0e1
{
    meta:
        description = "Detects suspicious strings in FannyWorm_963A24B864524DFA64BA4310537CE0E1"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_97B0A0EF6CB6B1EB8E325EB20BA0A8E3_97b0a0ef6cb6b1eb8e325eb20ba0a8e3
{
    meta:
        description = "Detects suspicious strings in FannyWorm_97B0A0EF6CB6B1EB8E325EB20BA0A8E3"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_98E6B678B40329DAC41D8F42652C17A2_98e6b678b40329dac41d8f42652c17a2
{
    meta:
        description = "Detects suspicious strings in FannyWorm_98E6B678B40329DAC41D8F42652C17A2"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_99E8D4F1D2069EF84D9725AA206D6BA7_99e8d4f1d2069ef84d9725aa206d6ba7
{
    meta:
        description = "Detects suspicious strings in FannyWorm_99E8D4F1D2069EF84D9725AA206D6BA7"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_9A7165D3C7B84FE0E22881F653EADF7F_9a7165d3c7b84fe0e22881f653eadf7f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_9A7165D3C7B84FE0E22881F653EADF7F"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_9FB98B0D1A5B38B6A89CB478943C285B_9fb98b0d1a5b38b6a89cb478943c285b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_9FB98B0D1A5B38B6A89CB478943C285B"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_9FC2AA4D538B34651705B904C7823C6F_9fc2aa4d538b34651705b904c7823c6f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_9FC2AA4D538B34651705B904C7823C6F"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A00101CFC1EDD423CB34F758F8D0C62E_a00101cfc1edd423cb34f758f8d0c62e
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A00101CFC1EDD423CB34F758F8D0C62E"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A2C52AD8F66A14F7979C6BAFC4978142_a2c52ad8f66a14f7979c6bafc4978142
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A2C52AD8F66A14F7979C6BAFC4978142"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A397A581C20BF93EB5C22CAD5A2AFCDD_a397a581c20bf93eb5c22cad5a2afcdd
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A397A581C20BF93EB5C22CAD5A2AFCDD"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A43F67AF43730552864F84E2B051DEB4_a43f67af43730552864f84e2b051deb4
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A43F67AF43730552864F84E2B051DEB4"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A498FCAC85DC2E97281781A08B1C1041_a498fcac85dc2e97281781a08b1c1041
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A498FCAC85DC2E97281781A08B1C1041"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A4E2ED5FF620A786C2F2E15A5F8A2D2F_a4e2ed5ff620a786c2f2e15a5f8a2d2f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A4E2ED5FF620A786C2F2E15A5F8A2D2F"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A5E169E47BA828DD68417875AA8C0C94_a5e169e47ba828dd68417875aa8c0c94
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A5E169E47BA828DD68417875AA8C0C94"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A5F2C5CA6B51A6BF48D795FB5AE63203_a5f2c5ca6b51a6bf48d795fb5ae63203
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A5F2C5CA6B51A6BF48D795FB5AE63203"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A5F389947F03902A5ABD742B61637363_a5f389947f03902a5abd742b61637363
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A5F389947F03902A5ABD742B61637363"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A62BE32440D0602C76A72F96235567AC_a62be32440d0602c76a72f96235567ac
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A62BE32440D0602C76A72F96235567AC"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A67E937C6C33B0A9CD83946CCFA666CA_a67e937c6c33b0a9cd83946ccfa666ca
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A67E937C6C33B0A9CD83946CCFA666CA"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A68A56B4B3412E07436C7D195891E8BE_a68a56b4b3412e07436c7d195891e8be
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A68A56B4B3412E07436C7D195891E8BE"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A76DC2F716AA5ED5CBBD23BBF1DE3005_a76dc2f716aa5ed5cbbd23bbf1de3005
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A76DC2F716AA5ED5CBBD23BBF1DE3005"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A7F4EEE46463BE30615903E395A323C5_a7f4eee46463be30615903e395a323c5
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A7F4EEE46463BE30615903E395A323C5"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A801668543B30FCC3A254DE8183B2BA5_a801668543b30fcc3a254de8183b2ba5
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A801668543B30FCC3A254DE8183B2BA5"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A82D41CFC3EE376D9252DD4912E35894_a82d41cfc3ee376d9252dd4912e35894
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A82D41CFC3EE376D9252DD4912E35894"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A84FD0164200AD1AD0E34EEE9C663949_a84fd0164200ad1ad0e34eee9c663949
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A84FD0164200AD1AD0E34EEE9C663949"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A8A973B3861C8D2F18039432B9F38335_a8a973b3861c8d2f18039432b9f38335
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A8A973B3861C8D2F18039432B9F38335"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A95B2EC5B67F8FDDA547A4A5A4B85543_a95b2ec5b67f8fdda547a4a5a4b85543
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A95B2EC5B67F8FDDA547A4A5A4B85543"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_A96DC17D52986BB9BA201550D5D41186_a96dc17d52986bb9ba201550d5d41186
{
    meta:
        description = "Detects suspicious strings in FannyWorm_A96DC17D52986BB9BA201550D5D41186"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AAA06C8458F01BEDCAC5EC638C5C8B24_aaa06c8458f01bedcac5ec638c5c8b24
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AAA06C8458F01BEDCAC5EC638C5C8B24"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AB75C7BF5AD32AF82D331B5EE76F2ECA_ab75c7bf5ad32af82d331b5ee76f2eca
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AB75C7BF5AD32AF82D331B5EE76F2ECA"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_ABFF989FBA8B34539CDDBDFF0A79EE8D_abff989fba8b34539cddbdff0a79ee8d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_ABFF989FBA8B34539CDDBDFF0A79EE8D"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AC50C31D680C763CCE26B4D979A11A5C_ac50c31d680c763cce26b4d979a11a5c
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AC50C31D680C763CCE26B4D979A11A5C"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AC7A5C23B475E8BF54A1E60AE1A85F67_ac7a5c23b475e8bf54a1e60ae1a85f67
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AC7A5C23B475E8BF54A1E60AE1A85F67"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AE58E6C03D7339DA70D061399F6DEFF3_ae58e6c03d7339da70d061399f6deff3
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AE58E6C03D7339DA70D061399F6DEFF3"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AF426F4980CE7E2F771742BEE1CC43DF_af426f4980ce7e2f771742bee1cc43df
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AF426F4980CE7E2F771742BEE1CC43DF"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AF8F1BFCCB6530E41B2F19FF0DE8BAB5_af8f1bfccb6530e41b2f19ff0de8bab5
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AF8F1BFCCB6530E41B2F19FF0DE8BAB5"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_AFF10DD15B2D39C18AE9EE96511A9D83_aff10dd15b2d39c18ae9ee96511a9d83
{
    meta:
        description = "Detects suspicious strings in FannyWorm_AFF10DD15B2D39C18AE9EE96511A9D83"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B11DBC0C4E98B4CA224C18344CC5191D_b11dbc0c4e98b4ca224c18344cc5191d
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B11DBC0C4E98B4CA224C18344CC5191D"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B1C4ED725CB3443D16BE55EE5F00DCBD_b1c4ed725cb3443d16be55ee5f00dcbd
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B1C4ED725CB3443D16BE55EE5F00DCBD"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B1CCEB79F74D48C94CA7E680A609BC65_b1cceb79f74d48c94ca7e680a609bc65
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B1CCEB79F74D48C94CA7E680A609BC65"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B322FB54B5E53F4EA93E04E5A2ABCCBC_b322fb54b5e53f4ea93e04e5a2abccbc
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B322FB54B5E53F4EA93E04E5A2ABCCBC"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B38A91B1A5D23D418C5C6D6A0B066C30_b38a91b1a5d23d418c5c6d6a0b066c30
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B38A91B1A5D23D418C5C6D6A0B066C30"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B4B05BB97521494B342DA8524A6181ED_b4b05bb97521494b342da8524a6181ed
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B4B05BB97521494B342DA8524A6181ED"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B5738307BAB3FBF4CF2BDD652B0AC88A_b5738307bab3fbf4cf2bdd652b0ac88a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B5738307BAB3FBF4CF2BDD652B0AC88A"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B59F5C408FBA0E2CF503E0942AC46C56_b59f5c408fba0e2cf503e0942ac46c56
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B59F5C408FBA0E2CF503E0942AC46C56"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B747BB2EDC15A07CE61BCE4FD1A33EAD_b747bb2edc15a07ce61bce4fd1a33ead
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B747BB2EDC15A07CE61BCE4FD1A33EAD"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_B78E9C9A49AA507CB1F905FDD455CA35_b78e9c9a49aa507cb1f905fdd455ca35
{
    meta:
        description = "Detects suspicious strings in FannyWorm_B78E9C9A49AA507CB1F905FDD455CA35"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BA38163FC6E75BB6ACD73BC7CF89089B_ba38163fc6e75bb6acd73bc7cf89089b
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BA38163FC6E75BB6ACD73BC7CF89089B"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BA43976BB23531A9D4DC5F0AFD07327A_ba43976bb23531a9d4dc5f0afd07327a
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BA43976BB23531A9D4DC5F0AFD07327A"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BAC9A35D7CDF8C217B51C189A7B7B2FD_bac9a35d7cdf8c217b51c189a7b7b2fd
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BAC9A35D7CDF8C217B51C189A7B7B2FD"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BB5AA3E042C802C294FA233C4DB41393_bb5aa3e042c802c294fa233c4db41393
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BB5AA3E042C802C294FA233C4DB41393"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BCC5D198A60878C03A114E45ACDFE417_bcc5d198a60878c03a114e45acdfe417
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BCC5D198A60878C03A114E45ACDFE417"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BD7A693767DE2EAE08B4C63AAA84DB43_bd7a693767de2eae08b4c63aaa84db43
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BD7A693767DE2EAE08B4C63AAA84DB43"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BD9E6F35DC7FE987EEFA048ADC94D346_bd9e6f35dc7fe987eefa048adc94d346
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BD9E6F35DC7FE987EEFA048ADC94D346"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BDC3474D7A5566916DC0A2B3075D10BE_bdc3474d7a5566916dc0a2b3075d10be
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BDC3474D7A5566916DC0A2B3075D10BE"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BED58D25C152BD5B4A9C022B5B863C72_bed58d25c152bd5b4a9c022b5b863c72
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BED58D25C152BD5B4A9C022B5B863C72"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_BFDE4B5CD6CC89C6996C5E30C36F0273_bfde4b5cd6cc89c6996c5e30c36f0273
{
    meta:
        description = "Detects suspicious strings in FannyWorm_BFDE4B5CD6CC89C6996C5E30C36F0273"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_C05255625BB00EB12EAF95CB41FCC7F5_c05255625bb00eb12eaf95cb41fcc7f5
{
    meta:
        description = "Detects suspicious strings in FannyWorm_C05255625BB00EB12EAF95CB41FCC7F5"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_C1F171A7689958EB500079AB0185915F_c1f171a7689958eb500079ab0185915f
{
    meta:
        description = "Detects suspicious strings in FannyWorm_C1F171A7689958EB500079AB0185915F"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_C303AFE1648D3B70591FEEFFE78125ED_c303afe1648d3b70591feeffe78125ed
{
    meta:
        description = "Detects suspicious strings in FannyWorm_C303AFE1648D3B70591FEEFFE78125ED"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_FannyWorm_C3DA3234A3764CA81D694C3935BF55CF_c3da3234a3764ca81d694c3935bf55cf
{
    meta:
        description = "Detects suspicious strings in FannyWorm_C3DA3234A3764CA81D694C3935BF55CF"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Fanny_0A209AC0DE4AC033F31D6BA9191A8F7A_0a209ac0de4ac033f31d6ba9191a8f7a
{
    meta:
        description = "Detects suspicious strings in Fanny_0A209AC0DE4AC033F31D6BA9191A8F7A"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_GROK_24A6EC8EBF9C0867ED1C097F4A653B8D_24a6ec8ebf9c0867ed1c097f4a653b8d
{
    meta:
        description = "Detects suspicious strings in GROK_24A6EC8EBF9C0867ED1C097F4A653B8D"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_GrayFish_9B1CA66AAB784DC5F1DFE635D8F8A904_9b1ca66aab784dc5f1dfe635d8f8a904
{
    meta:
        description = "Detects suspicious strings in GrayFish_9B1CA66AAB784DC5F1DFE635D8F8A904"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "createprocess" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
            $s4 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_HEAD_6e0e5ef3aa67a43e837a8361523a5829
{
    meta:
        description = "Detects suspicious strings in HEAD"
        author = "Auto-generated"
        
    strings:
                    $s0 = "https://" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Locky_b06d9dd17c69ed2ae75d9e40b2631b42
{
    meta:
        description = "Detects suspicious strings in Locky"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "inject" nocase
            $s2 = "hook" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_MacSecurity_88cee1ab72fc09c99deaff33f8699f74
{
    meta:
        description = "Detects suspicious strings in MacSecurity"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "malware" nocase
            $s2 = "virus" nocase
            $s3 = "backdoor" nocase
            $s4 = "execute" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Matsnu_MBRwipingRansomware_1B2D2A4B97C7C2727D571BBF9376F54F__1b2d2a4b97c7c2727d571bbf9376f54f
{
    meta:
        description = "Detects suspicious strings in Matsnu-MBRwipingRansomware_1B2D2A4B97C7C2727D571BBF9376F54F_Inkasso Rechnung vom 27.05.2013 .com_"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "cmd.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_New_Xagent_Mac_Malware_Linked_with_the_APT28___Bitdefender_L_fbcfeeacc711310395da6ef87e34a616
{
    meta:
        description = "Detects suspicious strings in New Xagent Mac Malware Linked with the APT28 _ Bitdefender Labs.pdf"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = "malware" nocase
            $s3 = "virus" nocase
            $s4 = "trojan" nocase
            $s5 = "backdoor" nocase
            $s6 = "download" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Noi_dung_chi_tiet_d802aa9938e87dc33cf2c7a07e920b0b
{
    meta:
        description = "Detects suspicious strings in Noi dung chi tiet"
        author = "Auto-generated"
        
    strings:
                    $s0 = "execute" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_PlugX_RTF_dropper_42fba80f105aa53dfbf50aeba2d73cae_42fba80f105aa53dfbf50aeba2d73cae
{
    meta:
        description = "Detects suspicious strings in PlugX_RTF_dropper_42fba80f105aa53dfbf50aeba2d73cae"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_1stVersion_0C7183D761F15772B7E9C788BE601D29_0c7183d761f15772b7e9c788be601d29
{
    meta:
        description = "Detects suspicious strings in Potao_1stVersion_0C7183D761F15772B7E9C788BE601D29"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_1stVersion_14634D446471B9E2F55158D9AC09D0B2_14634d446471b9e2f55158d9ac09d0b2
{
    meta:
        description = "Detects suspicious strings in Potao_1stVersion_14634D446471B9E2F55158D9AC09D0B2"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_1stVersion_3B7D88A069631111D5585B1B10CCCC86_3b7d88a069631111d5585b1b10cccc86
{
    meta:
        description = "Detects suspicious strings in Potao_1stVersion_3B7D88A069631111D5585B1B10CCCC86"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_1stVersion_502F35002B1A95F1AE135BAFF6CFF836_502f35002b1a95f1ae135baff6cff836
{
    meta:
        description = "Detects suspicious strings in Potao_1stVersion_502F35002B1A95F1AE135BAFF6CFF836"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_1stVersion_85B0E3264820008A30F17CA19332FA19_85b0e3264820008a30f17ca19332fa19
{
    meta:
        description = "Detects suspicious strings in Potao_1stVersion_85B0E3264820008A30F17CA19332FA19"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
            $s3 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_1stVersion_A35E48909A49334A7EBB5448A78DCFF9_a35e48909a49334a7ebb5448a78dcff9
{
    meta:
        description = "Detects suspicious strings in Potao_1stVersion_A35E48909A49334A7EBB5448A78DCFF9"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
            $s3 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_1stVersion_A446CED5DB1DE877CF78F77741E2A804_a446ced5db1de877cf78f77741e2a804
{
    meta:
        description = "Detects suspicious strings in Potao_1stVersion_A446CED5DB1DE877CF78F77741E2A804"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".dll" nocase
            $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_1stVersion_AC854A3C91D52BFC09605506E76975AE_ac854a3c91d52bfc09605506e76975ae
{
    meta:
        description = "Detects suspicious strings in Potao_1stVersion_AC854A3C91D52BFC09605506E76975AE"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_1stVersion_D1658B792DD1569ABC27966083F59D44_d1658b792dd1569abc27966083f59d44
{
    meta:
        description = "Detects suspicious strings in Potao_1stVersion_D1658B792DD1569ABC27966083F59D44"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
            $s3 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_1stVersion_D939A05E1E3C9D7B6127D503C025DBC4_d939a05e1e3c9d7b6127d503c025dbc4
{
    meta:
        description = "Detects suspicious strings in Potao_1stVersion_D939A05E1E3C9D7B6127D503C025DBC4"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_DebugVersion_5199FCD031987834ED3121FB316F4970_5199fcd031987834ed3121fb316f4970
{
    meta:
        description = "Detects suspicious strings in Potao_DebugVersion_5199FCD031987834ED3121FB316F4970"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "hook" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_DebugVersion_7263A328F0D47C76B4E103546B648484_7263a328f0d47c76b4e103546b648484
{
    meta:
        description = "Detects suspicious strings in Potao_DebugVersion_7263A328F0D47C76B4E103546B648484"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_DebugVersion_BDC9255DF5385F534FEA83B497C371C8_bdc9255df5385f534fea83b497c371c8
{
    meta:
        description = "Detects suspicious strings in Potao_DebugVersion_BDC9255DF5385F534FEA83B497C371C8"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Droppersfrompostalsites_07E99B2F572B84AF5C4504C23F1653_07e99b2f572b84af5c4504c23f1653bb
{
    meta:
        description = "Detects suspicious strings in Potao_Droppersfrompostalsites_07E99B2F572B84AF5C4504C23F1653BB"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Droppersfrompostalsites_1927A80CD45F0D27B1AE034C11DDED_1927a80cd45f0d27b1ae034c11ddedb0
{
    meta:
        description = "Detects suspicious strings in Potao_Droppersfrompostalsites_1927A80CD45F0D27B1AE034C11DDEDB0"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Droppersfrompostalsites_579AD4A596602A10B7CF4659B6B690_579ad4a596602a10b7cf4659b6b6909d
{
    meta:
        description = "Detects suspicious strings in Potao_Droppersfrompostalsites_579AD4A596602A10B7CF4659B6B6909D"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Droppersfrompostalsites_65F494580C95E10541D1F377C0A7BD_65f494580c95e10541d1f377c0a7bd49
{
    meta:
        description = "Detects suspicious strings in Potao_Droppersfrompostalsites_65F494580C95E10541D1F377C0A7BD49"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Droppersfrompostalsites_A4B0615CB639607E6905437DD900C0_a4b0615cb639607e6905437dd900c059
{
    meta:
        description = "Detects suspicious strings in Potao_Droppersfrompostalsites_A4B0615CB639607E6905437DD900C059"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Droppersfrompostalsites_E64EB8B571F655B744C9154D8032CA_e64eb8b571f655b744c9154d8032caef
{
    meta:
        description = "Detects suspicious strings in Potao_Droppersfrompostalsites_E64EB8B571F655B744C9154D8032CAEF"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Dropperswdecoy_5A24A7370F35DBDBB81ADF52E769A442_5a24a7370f35dbdbb81adf52e769a442
{
    meta:
        description = "Detects suspicious strings in Potao_Dropperswdecoy_5A24A7370F35DBDBB81ADF52E769A442"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Dropperswdecoy_73E7EE83133A175B815059F1AF79AB1B_73e7ee83133a175b815059f1af79ab1b
{
    meta:
        description = "Detects suspicious strings in Potao_Dropperswdecoy_73E7EE83133A175B815059F1AF79AB1B"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "execute" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Dropperswdecoy_B4D909077AA25F31386722E716A5305C_b4d909077aa25f31386722e716a5305c
{
    meta:
        description = "Detects suspicious strings in Potao_Dropperswdecoy_B4D909077AA25F31386722E716A5305C"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "execute" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Dropperswdecoy_D755E52BA5658A639C778C22D1A906A3_d755e52ba5658a639c778c22d1a906a3
{
    meta:
        description = "Detects suspicious strings in Potao_Dropperswdecoy_D755E52BA5658A639C778C22D1A906A3"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "hook" nocase
            $s2 = "execute" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Dropperswdecoy_EEBBCB1ED5F5606AEC296168DEE39166_eebbcb1ed5f5606aec296168dee39166
{
    meta:
        description = "Detects suspicious strings in Potao_Dropperswdecoy_EEBBCB1ED5F5606AEC296168DEE39166"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_Dropperswdecoy_FC4B285088413127B6D827656B9D0481_fc4b285088413127b6d827656b9d0481
{
    meta:
        description = "Detects suspicious strings in Potao_Dropperswdecoy_FC4B285088413127B6D827656B9D0481"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_FakeTrueCryptSetup_83F3EC97A95595EBE40A75E94C98A7BD_83f3ec97a95595ebe40a75e94c98a7bd
{
    meta:
        description = "Detects suspicious strings in Potao_FakeTrueCryptSetup_83F3EC97A95595EBE40A75E94C98A7BD"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = ".exe" nocase
            $s3 = ".dll" nocase
            $s4 = "malware" nocase
            $s5 = "virus" nocase
            $s6 = "download" nocase
            $s7 = "execute" nocase
            $s8 = "createprocess" nocase
            $s9 = "kernel32.dll" nocase
            $s10 = "user32.dll" nocase
            $s11 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_FakeTrueCryptSetup_BABD17701CBE876149DC07E68EC7CA4F_babd17701cbe876149dc07e68ec7ca4f
{
    meta:
        description = "Detects suspicious strings in Potao_FakeTrueCryptSetup_BABD17701CBE876149DC07E68EC7CA4F"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = ".exe" nocase
            $s3 = ".dll" nocase
            $s4 = "download" nocase
            $s5 = "execute" nocase
            $s6 = "createprocess" nocase
            $s7 = "kernel32.dll" nocase
            $s8 = "user32.dll" nocase
            $s9 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_FakeTrueCryptSetup_CFC8901FE6A9A8299087BFC73AE8909E_cfc8901fe6a9a8299087bfc73ae8909e
{
    meta:
        description = "Detects suspicious strings in Potao_FakeTrueCryptSetup_CFC8901FE6A9A8299087BFC73AE8909E"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = ".exe" nocase
            $s3 = ".dll" nocase
            $s4 = "download" nocase
            $s5 = "execute" nocase
            $s6 = "createprocess" nocase
            $s7 = "kernel32.dll" nocase
            $s8 = "user32.dll" nocase
            $s9 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_FakeTrueCryptSetup_F34B77F7B2233EE6F727D59FB28F438A_f34b77f7b2233ee6f727d59fb28f438a
{
    meta:
        description = "Detects suspicious strings in Potao_FakeTrueCryptSetup_F34B77F7B2233EE6F727D59FB28F438A"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = ".exe" nocase
            $s3 = ".dll" nocase
            $s4 = "download" nocase
            $s5 = "execute" nocase
            $s6 = "createprocess" nocase
            $s7 = "kernel32.dll" nocase
            $s8 = "user32.dll" nocase
            $s9 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_FakeTrueCryptextracted_exe_7CA6101C2AE4838FBBD7CEB0B23_7ca6101c2ae4838fbbd7ceb0b2354e43
{
    meta:
        description = "Detects suspicious strings in Potao_FakeTrueCryptextracted exe_7CA6101C2AE4838FBBD7CEB0B2354E43"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = ".exe" nocase
            $s3 = ".dll" nocase
            $s4 = "inject" nocase
            $s5 = "hook" nocase
            $s6 = "download" nocase
            $s7 = "upload" nocase
            $s8 = "execute" nocase
            $s9 = "createprocess" nocase
            $s10 = "kernel32.dll" nocase
            $s11 = "user32.dll" nocase
            $s12 = "advapi32.dll" nocase
            $s13 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_FakeTrueCryptextracted_exe_B64DBE5817B24D17A0404E9B260_b64dbe5817b24d17a0404e9b2606ad96
{
    meta:
        description = "Detects suspicious strings in Potao_FakeTrueCryptextracted exe_B64DBE5817B24D17A0404E9B2606AD96"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = ".exe" nocase
            $s3 = ".dll" nocase
            $s4 = "inject" nocase
            $s5 = "hook" nocase
            $s6 = "download" nocase
            $s7 = "upload" nocase
            $s8 = "execute" nocase
            $s9 = "createprocess" nocase
            $s10 = "kernel32.dll" nocase
            $s11 = "user32.dll" nocase
            $s12 = "advapi32.dll" nocase
            $s13 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_FakeTrueCryptextracted_exe_C1F715FF0AFC78AF81D215D485C_c1f715ff0afc78af81d215d485cc235c
{
    meta:
        description = "Detects suspicious strings in Potao_FakeTrueCryptextracted exe_C1F715FF0AFC78AF81D215D485CC235C"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = ".exe" nocase
            $s3 = ".dll" nocase
            $s4 = "malware" nocase
            $s5 = "virus" nocase
            $s6 = "c:\\windows\\temp\\" nocase
            $s7 = "inject" nocase
            $s8 = "hook" nocase
            $s9 = "download" nocase
            $s10 = "upload" nocase
            $s11 = "execute" nocase
            $s12 = "createprocess" nocase
            $s13 = "kernel32.dll" nocase
            $s14 = "user32.dll" nocase
            $s15 = "advapi32.dll" nocase
            $s16 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_FakeTrueCryptextracted_exe_F64704ED25F4C728AF996EEE3EE_f64704ed25f4c728af996eee3ee85411
{
    meta:
        description = "Detects suspicious strings in Potao_FakeTrueCryptextracted exe_F64704ED25F4C728AF996EEE3EE85411"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = ".exe" nocase
            $s3 = ".dll" nocase
            $s4 = "inject" nocase
            $s5 = "hook" nocase
            $s6 = "download" nocase
            $s7 = "upload" nocase
            $s8 = "execute" nocase
            $s9 = "createprocess" nocase
            $s10 = "kernel32.dll" nocase
            $s11 = "user32.dll" nocase
            $s12 = "advapi32.dll" nocase
            $s13 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_02D438DF779AFFDDAF02CA995C60CECB_02d438df779affddaf02ca995c60cecb
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_02D438DF779AFFDDAF02CA995C60CECB"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_043F99A875424CA0023A21739DBA51EF_043f99a875424ca0023a21739dba51ef
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_043F99A875424CA0023A21739DBA51EF"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_11B4E7EA6BAE19A29343AE3FF3FB00CA_11b4e7ea6bae19a29343ae3ff3fb00ca
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_11B4E7EA6BAE19A29343AE3FF3FB00CA"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_1AB8D45656E245ACA4E59AA0519F6BA0_1ab8d45656e245aca4e59aa0519f6ba0
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_1AB8D45656E245ACA4E59AA0519F6BA0"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_27D74523B182AE630C4E5236897E11F3_27d74523b182ae630c4e5236897e11f3
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_27D74523B182AE630C4E5236897E11F3"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_360DF4C2F2B99052C07E08EDBE15AB2C_360df4c2f2b99052c07e08edbe15ab2c
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_360DF4C2F2B99052C07E08EDBE15AB2C"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_38E708FEA8016520CB25D3CB933F2244_38e708fea8016520cb25d3cb933f2244
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_38E708FEA8016520CB25D3CB933F2244"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "hook" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_6BA88E8E74B12C914483C026AE92EB42_6ba88e8e74b12c914483c026ae92eb42
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_6BA88E8E74B12C914483C026AE92EB42"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_OtherDroppers_89A3EA3967745E04199EBF222494452E_89a3ea3967745e04199ebf222494452e
{
    meta:
        description = "Detects suspicious strings in Potao_OtherDroppers_89A3EA3967745E04199EBF222494452E"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_057028E46EA797834DA401E4DB7C860A_057028e46ea797834da401e4db7c860a
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_057028E46EA797834DA401E4DB7C860A"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_1234BF4F0F5DEBC800D85C1BD2255671_1234bf4f0f5debc800d85c1bd2255671
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_1234BF4F0F5DEBC800D85C1BD2255671"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_2646F7159E1723F089D63E08C8BFAFFB_2646f7159e1723f089d63e08c8bfaffb
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_2646F7159E1723F089D63E08C8BFAFFB"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_2BD0D2B5EE4E93717EA71445B102E38E_2bd0d2b5ee4e93717ea71445b102e38e
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_2BD0D2B5EE4E93717EA71445B102E38E"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_35724E234F6258E601257FB219DB9079_35724e234f6258e601257fb219db9079
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_35724E234F6258E601257FB219DB9079"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
            $s3 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_3813B848162261CC5982DD64C741B450_3813b848162261cc5982dd64c741b450
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_3813B848162261CC5982DD64C741B450"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_39B67CC6DAE5214328022C44F28CED8B_39b67cc6dae5214328022c44f28ced8b
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_39B67CC6DAE5214328022C44F28CED8B"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_514423670DE210F13092D6CB8916748E_514423670de210f13092d6cb8916748e
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_514423670DE210F13092D6CB8916748E"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_542B00F903F945AD3A9291CB0AF73446_542b00f903f945ad3a9291cb0af73446
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_542B00F903F945AD3A9291CB0AF73446"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
            $s3 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_609ABB2A86C324BBB9BA1E253595E573_609abb2a86c324bbb9ba1e253595e573
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_609ABB2A86C324BBB9BA1E253595E573"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_76DDA7CA15323FD658054E0550149B7B_76dda7ca15323fd658054e0550149b7b
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_76DDA7CA15323FD658054E0550149B7B"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
            $s3 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_9179F4683ECE450C1AC7A819B32BDB6D_9179f4683ece450c1ac7a819b32bdb6d
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_9179F4683ECE450C1AC7A819B32BDB6D"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_A2BB01B764491DD61FA3A7BA5AFC709C_a2bb01b764491dd61fa3a7ba5afc709c
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_A2BB01B764491DD61FA3A7BA5AFC709C"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_A427FF7ABB17AF6CF5FB70C49E9BF4E1_a427ff7abb17af6cf5fb70c49e9bf4e1
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_A427FF7ABB17AF6CF5FB70C49E9BF4E1"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
            $s3 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_A59053CC3F66E72540634EB7895824AC_a59053cc3f66e72540634eb7895824ac
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_A59053CC3F66E72540634EB7895824AC"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_ABB9F4FAB64DD7A03574ABDD1076B5EA_abb9f4fab64dd7a03574abdd1076b5ea
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_ABB9F4FAB64DD7A03574ABDD1076B5EA"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_AE552FC43F1BA8684655D8BF8C6AF869_ae552fc43f1ba8684655d8bf8c6af869
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_AE552FC43F1BA8684655D8BF8C6AF869"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_CA1A3618088F91B8FB2A30C9A9AA4ACA_ca1a3618088f91b8fb2a30c9a9aa4aca
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_CA1A3618088F91B8FB2A30C9A9AA4ACA"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = ".exe" nocase
            $s3 = ".dll" nocase
            $s4 = "createprocess" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_CDC60EB93B594FB5E7E5895E2B441240_cdc60eb93b594fb5e7e5895e2b441240
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_CDC60EB93B594FB5E7E5895E2B441240"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Potao_USBSpreaders_E685EA8B37F707F3706D7281B8F6816A_e685ea8b37f707f3706d7281b8f6816a
{
    meta:
        description = "Detects suspicious strings in Potao_USBSpreaders_E685EA8B37F707F3706D7281B8F6816A"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_SNOOPY_002c8d481ae05cca6bb3a27ebe1ca23b
{
    meta:
        description = "Detects suspicious strings in SNOOPY"
        author = "Auto-generated"
        
    strings:
                    $s0 = "virus" nocase
            $s1 = "/tmp/" nocase
            $s2 = "/var/tmp/" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Shylock_skype_8FBEB78B06985C3188562E2F1B82D57D_8fbeb78b06985c3188562e2f1b82d57d
{
    meta:
        description = "Detects suspicious strings in Shylock-skype_8FBEB78B06985C3188562E2F1B82D57D"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "download" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
            $s4 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Torpig_miniloader_011C1CA6030EE091CE7C20CD3AAECFA0_011c1ca6030ee091ce7c20cd3aaecfa0
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_011C1CA6030EE091CE7C20CD3AAECFA0"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Torpig_miniloader_0F82964CF39056402EE2DE9193635B34_0f82964cf39056402ee2de9193635b34
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_0F82964CF39056402EE2DE9193635B34"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Torpig_miniloader_2DACC4556FAD30027A384875C8D9D900_2dacc4556fad30027a384875c8d9d900
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_2DACC4556FAD30027A384875C8D9D900"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Torpig_miniloader_4A3543E6771BC78D32AE46820AED1391_4a3543e6771bc78d32ae46820aed1391
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_4A3543E6771BC78D32AE46820AED1391"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Torpig_miniloader_809910F29AA63913EFA76D00FA8C7C0B_809910f29aa63913efa76d00fa8c7c0b
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_809910F29AA63913EFA76D00FA8C7C0B"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Torpig_miniloader_83419EEA712182C1054615E4EC7B8CBE_83419eea712182c1054615e4ec7b8cbe
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_83419EEA712182C1054615E4EC7B8CBE"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Torpig_miniloader_87851480DEB151D3A0AA9A425FD74E61_87851480deb151d3a0aa9a425fd74e61
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_87851480DEB151D3A0AA9A425FD74E61"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_Torpig_miniloader_C3366B6006ACC1F8DF875EAA114796F0_c3366b6006acc1f8df875eaa114796f0
{
    meta:
        description = "Detects suspicious strings in Torpig miniloader_C3366B6006ACC1F8DF875EAA114796F0"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_TripleFantasy_9180D5AFFE1E5DF0717D7385E7F54386_9180d5affe1e5df0717d7385e7f54386
{
    meta:
        description = "Detects suspicious strings in TripleFantasy_9180D5AFFE1E5DF0717D7385E7F54386"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_WTEpZSFwgb_5bd44a35094fe6f7794d895122ddfa62
{
    meta:
        description = "Detects suspicious strings in WTEpZSFwgb"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = ".exe" nocase
            $s3 = "/tmp/" nocase
            $s4 = "inject" nocase
            $s5 = "hook" nocase
            $s6 = "download" nocase
            $s7 = "upload" nocase
            $s8 = "execute" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_X21_9fbaf9989188bef5aa6d784bf0e2f3eb
{
    meta:
        description = "Detects suspicious strings in X21"
        author = "Auto-generated"
        
    strings:
                    $s0 = "virus" nocase
            $s1 = "/tmp/" nocase
            $s2 = "/var/tmp/" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_X23_557413e48092528af2d8495d9851b922
{
    meta:
        description = "Detects suspicious strings in X23"
        author = "Auto-generated"
        
    strings:
                    $s0 = "virus" nocase
            $s1 = "/tmp/" nocase
            $s2 = "/var/tmp/" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a08e0d1839b86d0d56a52d07123719211a3c3d43a6aa05aa34531a72ed12_8ccb9e82a89352c0b271032b6b9edc0b
{
    meta:
        description = "Detects suspicious strings in a08e0d1839b86d0d56a52d07123719211a3c3d43a6aa05aa34531a72ed1207dc"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a0d82c3730bc41e267711480c8009883d1412b68977ab175421eabc34e4e_b29ca4f22ae7b7b25f79c1d4a421139d
{
    meta:
        description = "Detects suspicious strings in a0d82c3730bc41e267711480c8009883d1412b68977ab175421eabc34e4ef355"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a1b468e9550f9960c5e60f7c52ca3c058de19d42eafa760b9d5282eb24b7_f001329114937fbc439f251c803ba825
{
    meta:
        description = "Detects suspicious strings in a1b468e9550f9960c5e60f7c52ca3c058de19d42eafa760b9d5282eb24b7c55f"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = ".exe" nocase
            $s3 = ".dll" nocase
            $s4 = "inject" nocase
            $s5 = "hook" nocase
            $s6 = "execute" nocase
            $s7 = "createprocess" nocase
            $s8 = "kernel32.dll" nocase
            $s9 = "advapi32.dll" nocase
            $s10 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a2c3073fa5587f8a70d7def7fd8355e1f6d20eb906c3cd4df8c744826cb8_20b4ac6be041b72862e1645953a951eb
{
    meta:
        description = "Detects suspicious strings in a2c3073fa5587f8a70d7def7fd8355e1f6d20eb906c3cd4df8c744826cb81d91"
        author = "Auto-generated"
        
    strings:
                    $s0 = "download" nocase
            $s1 = "upload" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a3667153a6322fb8d4cf8869c094a05e995e2954fda833fe14304837ed4f_68bfa1b82dc0e2de10d0cf8551938dea
{
    meta:
        description = "Detects suspicious strings in a3667153a6322fb8d4cf8869c094a05e995e2954fda833fe14304837ed4fd0bd"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "cmd.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a38df3ec8b9fe52a32860cf5756d2fe345badafd7e74466cd349eb32ba5c_a5bd39bf17d389340b2d80d060860d7b
{
    meta:
        description = "Detects suspicious strings in a38df3ec8b9fe52a32860cf5756d2fe345badafd7e74466cd349eb32ba5cc339"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a3c930f64cbb4e0b259fe6e966ebfb27caa90b540d193e4627b6256962b2_d076814db477d73051610386fae69fca
{
    meta:
        description = "Detects suspicious strings in a3c930f64cbb4e0b259fe6e966ebfb27caa90b540d193e4627b6256962b28864"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a4f59d4d42e42b882068cacf8b70f314add963e2cbbf7a52e70df130bfe2_e191da6e7970220552f48b50197b6f3e
{
    meta:
        description = "Detects suspicious strings in a4f59d4d42e42b882068cacf8b70f314add963e2cbbf7a52e70df130bfe23dff"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = ".exe" nocase
            $s3 = ".dll" nocase
            $s4 = "cmd.exe" nocase
            $s5 = "keylogger" nocase
            $s6 = "inject" nocase
            $s7 = "hook" nocase
            $s8 = "download" nocase
            $s9 = "upload" nocase
            $s10 = "execute" nocase
            $s11 = "createprocess" nocase
            $s12 = "kernel32.dll" nocase
            $s13 = "user32.dll" nocase
            $s14 = "advapi32.dll" nocase
            $s15 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a6ff8dfe654da70390cd71626cdca8a6f6a0d7980cd7d82269373737b04f_0df40b226a4913a57668b83b7c7b443c
{
    meta:
        description = "Detects suspicious strings in a6ff8dfe654da70390cd71626cdca8a6f6a0d7980cd7d82269373737b04fd206"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a7493fac96345a989b1a03772444075754a2ef11daa22a7600466adc1f69_b269894f434657db2b15949641a67532
{
    meta:
        description = "Detects suspicious strings in a7493fac96345a989b1a03772444075754a2ef11daa22a7600466adc1f69a669"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a77c61e86bc69fdc909560bb7a0fa1dd61ee6c86afceb9ea17462a97e711_198f27f5ab972bfd99e89802e40d6ba7
{
    meta:
        description = "Detects suspicious strings in a77c61e86bc69fdc909560bb7a0fa1dd61ee6c86afceb9ea17462a97e7114ab0"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "download" nocase
            $s3 = "execute" nocase
            $s4 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a7c387b4929f51e38706d8b0f8641e032253b07bc2869a450dfa3df5663d_67ef79ee308b8625d5f20ea3e5379436
{
    meta:
        description = "Detects suspicious strings in a7c387b4929f51e38706d8b0f8641e032253b07bc2869a450dfa3df5663d7392"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "download" nocase
            $s3 = "execute" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a7e3ad8ea7edf1ca10b0e5b0d976675c3016e5933219f97e94900dea0d47_187044596bc1328efa0ed636d8aa4a5c
{
    meta:
        description = "Detects suspicious strings in a7e3ad8ea7edf1ca10b0e5b0d976675c3016e5933219f97e94900dea0d470abe"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a880d7c77491fcc6f9c88bae064f075a339e6753ef9fa9410b928565887c_cebc3a9192d6b516e7937038acb689b0
{
    meta:
        description = "Detects suspicious strings in a880d7c77491fcc6f9c88bae064f075a339e6753ef9fa9410b928565887c13b7"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "advapi32.dll" nocase
            $s5 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a917c1cc198cf36c0f2f6c24652e5c2e94e28d963b128d54f00144d216b2_40e698f961eb796728a57ddf81f52b9a
{
    meta:
        description = "Detects suspicious strings in a917c1cc198cf36c0f2f6c24652e5c2e94e28d963b128d54f00144d216b2d118"
        author = "Auto-generated"
        
    strings:
                    $s0 = "https://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "upload" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "advapi32.dll" nocase
            $s6 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a98099541168c7f36b107e24e9c80c9125fefb787ae720799b03bb4425ab_44b5a3af895f31e22f6bc4eb66bd3eb7
{
    meta:
        description = "Detects suspicious strings in a98099541168c7f36b107e24e9c80c9125fefb787ae720799b03bb4425aba1a9"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "hook" nocase
            $s4 = "execute" nocase
            $s5 = "createprocess" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "user32.dll" nocase
            $s8 = "advapi32.dll" nocase
            $s9 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_a99bf162a8588b2f318c9460aef78851bd64e4826c2cb124984d2ab357a6_c3570b178f305753b69a37b0619fffa7
{
    meta:
        description = "Detects suspicious strings in a99bf162a8588b2f318c9460aef78851bd64e4826c2cb124984d2ab357a6beea"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "hook" nocase
            $s2 = "execute" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_acb930a41abdc4b055e2e3806aad85068be8d85e0e0610be35e784bfd7cf_0a5852e0dd9ac8cc990d852ea1b7fdee
{
    meta:
        description = "Detects suspicious strings in acb930a41abdc4b055e2e3806aad85068be8d85e0e0610be35e784bfd7cf5b0e"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_acfcf97ee4ff5cc7f5ecdc6f92ea132e29c48400ab6244de64f9b9de4368_6c52c837ba6ebe6615d18bfb15f26dce
{
    meta:
        description = "Detects suspicious strings in acfcf97ee4ff5cc7f5ecdc6f92ea132e29c48400ab6244de64f9b9de4368deb2"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ad8965e531424cb34120bf0c1b4b98d4ab769bed534d9a36583364e95723_2d540860d91cd25cc8d61555523c76ff
{
    meta:
        description = "Detects suspicious strings in ad8965e531424cb34120bf0c1b4b98d4ab769bed534d9a36583364e9572332fa"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "download" nocase
            $s3 = "execute" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ae66e009e16f0fad3b70ad20801f48f2edb904fa5341a89e126a26fd3fc8_03b76a5130d0df8134a6bdea7fe97bcd
{
    meta:
        description = "Detects suspicious strings in ae66e009e16f0fad3b70ad20801f48f2edb904fa5341a89e126a26fd3fc80f75"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "trojan" nocase
            $s3 = "hook" nocase
            $s4 = "download" nocase
            $s5 = "execute" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "user32.dll" nocase
            $s8 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_aed230b6b772aeb5c25e9336086e9dd4d6081d3efc205f9f9214b51f2f8c_a158607e499d658b54d123daf0fdb1b6
{
    meta:
        description = "Detects suspicious strings in aed230b6b772aeb5c25e9336086e9dd4d6081d3efc205f9f9214b51f2f8c3655"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".dll" nocase
            $s2 = "download" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_aedd0c47daa35f291e670e3feadaed11d9b8fe12c05982f16c909a57bf39_406ac1595991ea7ca97bc908a6538131
{
    meta:
        description = "Detects suspicious strings in aedd0c47daa35f291e670e3feadaed11d9b8fe12c05982f16c909a57bf39ca35"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_afa8d185de2f357082ed4042fc057a6d7300f603d3bfdbe7e6c351868e45_ec9ae4c3935b717769a5b3a3fa712943
{
    meta:
        description = "Detects suspicious strings in afa8d185de2f357082ed4042fc057a6d7300f603d3bfdbe7e6c351868e45e477"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b000a0095a8fda38227103f253b6d79134b862a83df50315d7d9c5b537fd_674216ba213ec73ef359ac5b08135be5
{
    meta:
        description = "Detects suspicious strings in b000a0095a8fda38227103f253b6d79134b862a83df50315d7d9c5b537fd994b"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "execute" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "advapi32.dll" nocase
            $s6 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b06ab1f3abf8262f32c3deab9d344d241e4203235043fe996cb499ed2fdf_a4d3b78941da8b6f4edad7cb6f35134b
{
    meta:
        description = "Detects suspicious strings in b06ab1f3abf8262f32c3deab9d344d241e4203235043fe996cb499ed2fdf17c4"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "createprocess" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b1102ed4bca6dae6f2f498ade2f73f76af527fa803f0e0b46e100d4cf515_9b02dd2a1a15e94922be3f85129083ac
{
    meta:
        description = "Detects suspicious strings in b1102ed4bca6dae6f2f498ade2f73f76af527fa803f0e0b46e100d4cf5150682"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "hook" nocase
            $s4 = "download" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b12c7d57507286bbbe36d7acf9b34c22c96606ffd904e3c23008399a4a50_ffb0b9b5b610191051a7bdf0806e1e47
{
    meta:
        description = "Detects suspicious strings in b12c7d57507286bbbe36d7acf9b34c22c96606ffd904e3c23008399a4a50c047"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b154ac015c0d1d6250032f63c749f9cf_b154ac015c0d1d6250032f63c749f9cf
{
    meta:
        description = "Detects suspicious strings in b154ac015c0d1d6250032f63c749f9cf"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b19a46f99b649dc731ed5c8410bda7e0385d15e1b9aab1e467b05dccd775_c3a9173aa8d47797ea28f0d0b2687fbb
{
    meta:
        description = "Detects suspicious strings in b19a46f99b649dc731ed5c8410bda7e0385d15e1b9aab1e467b05dccd7753865"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b275c8978d18832bd3da9975d0f43cbc90e09a99718f4efaf1be7b43db46_c19e91a91a2fa55e869c42a70da9a506
{
    meta:
        description = "Detects suspicious strings in b275c8978d18832bd3da9975d0f43cbc90e09a99718f4efaf1be7b43db46cf95"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "execute" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b2ca4093b2e0271cb7a3230118843fccc094e0160a0968994ed9f10c8702_344d431a88391fc89f97f3ccf87a603e
{
    meta:
        description = "Detects suspicious strings in b2ca4093b2e0271cb7a3230118843fccc094e0160a0968994ed9f10c8702d867"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "download" nocase
            $s3 = "execute" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b34893e23666ab3d1d1476a78eb8e921be41273f5a3b653f1d425801278b_b100c0cfbe59fa66cbb75de65c505ce2
{
    meta:
        description = "Detects suspicious strings in b34893e23666ab3d1d1476a78eb8e921be41273f5a3b653f1d425801278be39b"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b4c470be7e434dac0b61919a6b0c5b10cf7a01a22c5403c4540afdb5f2c7_5f9f9c1ef7b8d640e84bc3def4161da5
{
    meta:
        description = "Detects suspicious strings in b4c470be7e434dac0b61919a6b0c5b10cf7a01a22c5403c4540afdb5f2c79fab"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = ".dll" nocase
            $s3 = "execute" nocase
            $s4 = "createprocess" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b74bd5660baf67038353136978ed16dbc7d105c60c121cf64c61d8f3d31d_08c988d6cebdd55f3b123f2d9d5507a6
{
    meta:
        description = "Detects suspicious strings in b74bd5660baf67038353136978ed16dbc7d105c60c121cf64c61d8f3d31de32c"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "hook" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
            $s4 = "advapi32.dll" nocase
            $s5 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b7f36159aec7f3512e00bfa8aa189cbb97f9cc4752a635bc272c7a5ac171_9ee75cd19b3bed6179e81297ae92bd7b
{
    meta:
        description = "Detects suspicious strings in b7f36159aec7f3512e00bfa8aa189cbb97f9cc4752a635bc272c7a5ac1710e0b"
        author = "Auto-generated"
        
    strings:
                    $s0 = "https://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "download" nocase
            $s4 = "upload" nocase
            $s5 = "execute" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "advapi32.dll" nocase
            $s8 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b81b10bdf4f29347979ea8a1715cbfc560e3452ba9fffcc33cd19a3dc470_ad44a7c5e18e9958dda66ccfc406cd44
{
    meta:
        description = "Detects suspicious strings in b81b10bdf4f29347979ea8a1715cbfc560e3452ba9fffcc33cd19a3dc47083a4"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "explorer.exe" nocase
            $s3 = "virus" nocase
            $s4 = "download" nocase
            $s5 = "createprocess" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "user32.dll" nocase
            $s8 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b8f2da1eefa09077d86a443ad688080b98672f171918c06e2b3652df783b_0f6e0ff20e797b2a6153510a9b0275fd
{
    meta:
        description = "Detects suspicious strings in b8f2da1eefa09077d86a443ad688080b98672f171918c06e2b3652df783be03a"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_b96bd6bbf0e3f4f98b606a2ab5db4a69_b96bd6bbf0e3f4f98b606a2ab5db4a69
{
    meta:
        description = "Detects suspicious strings in b96bd6bbf0e3f4f98b606a2ab5db4a69"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ba0a74f2227e32f4cee2e7358979547cf15fd19ea6c72144773f087621bd_66c783e41480e65e287081ff853cc737
{
    meta:
        description = "Detects suspicious strings in ba0a74f2227e32f4cee2e7358979547cf15fd19ea6c72144773f087621bdb4b4"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bac8489de573f614d988097e9eae53ffc2eb4e7dcb0e68c349f549a26d21_cab76ac00e342f77bdfec3e85b6b85a9
{
    meta:
        description = "Detects suspicious strings in bac8489de573f614d988097e9eae53ffc2eb4e7dcb0e68c349f549a26d2130a8"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "createprocess" nocase
            $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bb4e7b0c969895fc9836640b80e2bdc6572d214ba2ee55b77588f8a4eede_f19db72372bcb16332f94ced6774a9d8
{
    meta:
        description = "Detects suspicious strings in bb4e7b0c969895fc9836640b80e2bdc6572d214ba2ee55b77588f8a4eedea5a4"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".dll" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
            $s4 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bb8e52face5b076cc890bbfaaf4bb73e_bb8e52face5b076cc890bbfaaf4bb73e
{
    meta:
        description = "Detects suspicious strings in bb8e52face5b076cc890bbfaaf4bb73e"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "upload" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
            $s4 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bc12d7052e6cfce8f16625ca8b88803cd4e58356eb32fe62667336d4dee7_ea53e618432ca0c823fafc06dc60b726
{
    meta:
        description = "Detects suspicious strings in bc12d7052e6cfce8f16625ca8b88803cd4e58356eb32fe62667336d4dee708a3"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "hook" nocase
            $s4 = "execute" nocase
            $s5 = "createprocess" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "user32.dll" nocase
            $s8 = "advapi32.dll" nocase
            $s9 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bc422a4e1b6a351ac6fe73d496015cfa6a9dbd5e38566c6f44a59faff83e_e7b7bf4c2ed49575bedabdce2385c8d5
{
    meta:
        description = "Detects suspicious strings in bc422a4e1b6a351ac6fe73d496015cfa6a9dbd5e38566c6f44a59faff83ee95a"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bc4ae56434b45818f57724f4cd19354a13e5964fd097d1933a30e2e31c9b_92e724291056a5e30eca038ee637a23f
{
    meta:
        description = "Detects suspicious strings in bc4ae56434b45818f57724f4cd19354a13e5964fd097d1933a30e2e31c9bdfa5.bin"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = ".exe" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bc6c2fda18f8ee36930b469f6500e28096eb6795e5fd17c44273c67bc9fa_e57f8364372e3ba866389c2895b42628
{
    meta:
        description = "Detects suspicious strings in bc6c2fda18f8ee36930b469f6500e28096eb6795e5fd17c44273c67bc9fa6a6d"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bd039bb73f297062ab65f695dd6defafd146f6f233c451e5ac967a720b41_5b505d0286378efcca4df38ed4a26c90
{
    meta:
        description = "Detects suspicious strings in bd039bb73f297062ab65f695dd6defafd146f6f233c451e5ac967a720b41fc14"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "hook" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
            $s4 = "advapi32.dll" nocase
            $s5 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bdef2ddcd8d4d66a42c9cbafd5cf7d86c4c0e3ed8c45cc734742c5da2fb5_c7ac6193245b76cc8cebc2835ee13532
{
    meta:
        description = "Detects suspicious strings in bdef2ddcd8d4d66a42c9cbafd5cf7d86c4c0e3ed8c45cc734742c5da2fb573f7"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "hook" nocase
            $s4 = "execute" nocase
            $s5 = "createprocess" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "user32.dll" nocase
            $s8 = "advapi32.dll" nocase
            $s9 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bed0bec3d123e7611dc3d722813eeb197a2b8048396cef4414f29f24af3a_740c47c663f5205365ae9fb08adfb127
{
    meta:
        description = "Detects suspicious strings in bed0bec3d123e7611dc3d722813eeb197a2b8048396cef4414f29f24af3a29c4"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "execute" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bf830191215e0c8db207ea320d8e795990cf6b3e6698932e6e0c9c0588fc_decd6b94792a22119e1b5a1ed99e8961
{
    meta:
        description = "Detects suspicious strings in bf830191215e0c8db207ea320d8e795990cf6b3e6698932e6e0c9c0588fc9eff"
        author = "Auto-generated"
        
    strings:
                    $s0 = "download" nocase
            $s1 = "upload" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_bfc63b30624332f4fc2e510f95b69d18dd0241eb0d2fcd33ed2e81b7275a_981234d969a4c5e6edea50df009efedd
{
    meta:
        description = "Detects suspicious strings in bfc63b30624332f4fc2e510f95b69d18dd0241eb0d2fcd33ed2e81b7275ab488"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "hook" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c0cf40b8830d666a24bdd4febdc162e95aa30ed968fa3675e26ad97b2e88_a890e2f924dea3cb3e46a95431ffae39
{
    meta:
        description = "Detects suspicious strings in c0cf40b8830d666a24bdd4febdc162e95aa30ed968fa3675e26ad97b2e88e03a"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "explorer.exe" nocase
            $s4 = "execute" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c0cf8e008fbfa0cb2c61d968057b4a077d62f64d7320769982d28107db37_1c024e599ac055312a4ab75b3950040a
{
    meta:
        description = "Detects suspicious strings in c0cf8e008fbfa0cb2c61d968057b4a077d62f64d7320769982d28107db370513"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c14f6ac5bcd8645eb80a612a6bf6d58c31b0e28e50be871f278c341ed1fa_14322a51747ee601c47cae739e40c8ee
{
    meta:
        description = "Detects suspicious strings in c14f6ac5bcd8645eb80a612a6bf6d58c31b0e28e50be871f278c341ed1fa8c7c"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "cmd.exe" nocase
            $s4 = "upload" nocase
            $s5 = "createprocess" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "user32.dll" nocase
            $s8 = "advapi32.dll" nocase
            $s9 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c161134bf3330c82eb0278fe54b2975c26301bdfdc4fc35d5344f9becf55_5458a2e4d784abb1a1127263bd5006b5
{
    meta:
        description = "Detects suspicious strings in c161134bf3330c82eb0278fe54b2975c26301bdfdc4fc35d5344f9becf5574c7"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "download" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c16410c49dc40a371be22773f420b7dd3cfd4d8205cf39909ad9a6f26f55_10e16e36fe459f6f2899a8cea1303f06
{
    meta:
        description = "Detects suspicious strings in c16410c49dc40a371be22773f420b7dd3cfd4d8205cf39909ad9a6f26f55718e"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
            $s3 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c34e5d36bd3a9a6fca92e900ab015aa50bb20d2cd6c0b6e03d070efe09ee_e815078b81bda42fd1d8029f82f63f8c
{
    meta:
        description = "Detects suspicious strings in c34e5d36bd3a9a6fca92e900ab015aa50bb20d2cd6c0b6e03d070efe09ee689a"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c377b79732e93f981998817e6f0e8664578b474445ba11b402c70b4b0357_d1071aea85c521933d2e27e12bd38811
{
    meta:
        description = "Detects suspicious strings in c377b79732e93f981998817e6f0e8664578b474445ba11b402c70b4b0357caab"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c460fc0d4fdaf5c68623e18de106f1c3601d7bd6ba80ddad86c10fd6ea12_d6d956267a268c9dcf48445629d2803e
{
    meta:
        description = "Detects suspicious strings in c460fc0d4fdaf5c68623e18de106f1c3601d7bd6ba80ddad86c10fd6ea123850"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "download" nocase
            $s3 = "execute" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c4762489488f797b4b33382c8b1b71c94a42c846f1f28e0e118c83fe0328_8632e7433fd46a491d4fb8cad11ab8c5
{
    meta:
        description = "Detects suspicious strings in c4762489488f797b4b33382c8b1b71c94a42c846f1f28e0e118c83fe032848f0"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "download" nocase
            $s3 = "execute" nocase
            $s4 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c7128e2772b4f8c59943028e205d1b23c07f36206c1c61a05645c7bf143b_e0e092ea23f534d8c89b9f607d50168b
{
    meta:
        description = "Detects suspicious strings in c7128e2772b4f8c59943028e205d1b23c07f36206c1c61a05645c7bf143b24ee"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "cmd.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c999bf5da5ea3960408d3cba154f965d3436b497ac9d4959b412bfcd956c_35c29de908e04eca97b39b96b3cadc2d
{
    meta:
        description = "Detects suspicious strings in c999bf5da5ea3960408d3cba154f965d3436b497ac9d4959b412bfcd956c8491"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "download" nocase
            $s3 = "execute" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_c9d5dc956841e000bfd8762e2f0b48b66c79b79500e894b4efa7fb9ba17e_f01a9a2d1e31332ed36c1a4d2839f412
{
    meta:
        description = "Detects suspicious strings in c9d5dc956841e000bfd8762e2f0b48b66c79b79500e894b4efa7fb9ba17e4e9e"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".dll" nocase
            $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ca467e332368cbae652245faa4978aa4_ca467e332368cbae652245faa4978aa4
{
    meta:
        description = "Detects suspicious strings in ca467e332368cbae652245faa4978aa4"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
            $s3 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ccd4a648cc2c4a5bbcd148f9c182f4c9595440a41dd3ea289a11609063c8_2a3ec4ae8546325a6a19b89bfccf5bc4
{
    meta:
        description = "Detects suspicious strings in ccd4a648cc2c4a5bbcd148f9c182f4c9595440a41dd3ea289a11609063c86a6d"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "execute" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_cf4bf26b2d6f1c6055534bbe9decb579ef0180e0f8c467c1a26e2ead7567_675593b67e2c028e1f4270ea4c7ad757
{
    meta:
        description = "Detects suspicious strings in cf4bf26b2d6f1c6055534bbe9decb579ef0180e0f8c467c1a26e2ead7567058a"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "backdoor" nocase
            $s4 = "shellcode" nocase
            $s5 = "inject" nocase
            $s6 = "download" nocase
            $s7 = "execute" nocase
            $s8 = "createprocess" nocase
            $s9 = "kernel32.dll" nocase
            $s10 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_cf65cc6e4b2b0c3f602b16398c8c30c277b8cfaed689fe7cb61b92560d4e_a8e3b108e5ccf3d1d0d8fb34e5f96391
{
    meta:
        description = "Detects suspicious strings in cf65cc6e4b2b0c3f602b16398c8c30c277b8cfaed689fe7cb61b92560d4e5b1b"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "backdoor" nocase
            $s4 = "shellcode" nocase
            $s5 = "inject" nocase
            $s6 = "download" nocase
            $s7 = "execute" nocase
            $s8 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_cf8533849ee5e82023ad7adbdbd6543cb6db596c53048b1a0c00b3643a72_c52f20a854efb013a0a1248fd84aaa95
{
    meta:
        description = "Detects suspicious strings in cf8533849ee5e82023ad7adbdbd6543cb6db596c53048b1a0c00b3643a72db30"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "download" nocase
            $s3 = "execute" nocase
            $s4 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_cfca38c408c95e45cdf797723dc5cdb0d6dadb1b8338a5fda6808ce9a04e_934b91c62fec7c99e56dc564e89831cb
{
    meta:
        description = "Detects suspicious strings in cfca38c408c95e45cdf797723dc5cdb0d6dadb1b8338a5fda6808ce9a04e6486"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_cff49c25b053f775db8980a431a958020bdf969ea08872de4cef5a5f344f_bb49e068c25707c7149acff2834f89c9
{
    meta:
        description = "Detects suspicious strings in cff49c25b053f775db8980a431a958020bdf969ea08872de4cef5a5f344f534c"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_conficker_566119e4e5f4bda545b3b8af33c23698
{
    meta:
        description = "Detects suspicious strings in conficker"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".dll" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
            $s4 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_config_354a7a40e200a855654ebf1bc6c3356a
{
    meta:
        description = "Detects suspicious strings in config"
        author = "Auto-generated"
        
    strings:
                    $s0 = "https://" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d096c3a67634599bc47151f0e01a7423a3eb873377371b2b928c0d4f5763_ec3aa5f57934b9530fbe7eebb1361a3d
{
    meta:
        description = "Detects suspicious strings in d096c3a67634599bc47151f0e01a7423a3eb873377371b2b928c0d4f57635a1f"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "createprocess" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
            $s4 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d0dd9c624bb2b33de96c29b0ccb5aa5b43ce83a54e2842f1643247811487_b748ce395a511824dc753a247fdeed93
{
    meta:
        description = "Detects suspicious strings in d0dd9c624bb2b33de96c29b0ccb5aa5b43ce83a54e2842f1643247811487f8d9"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = ".exe" nocase
            $s3 = ".dll" nocase
            $s4 = "download" nocase
            $s5 = "upload" nocase
            $s6 = "execute" nocase
            $s7 = "kernel32.dll" nocase
            $s8 = "advapi32.dll" nocase
            $s9 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d0f059ba21f06021579835a55220d1e822d1233f95879ea6f7cb9d301408_7dbc46559efafe8ec8446b836129598c
{
    meta:
        description = "Detects suspicious strings in d0f059ba21f06021579835a55220d1e822d1233f95879ea6f7cb9d301408c821"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "hook" nocase
            $s4 = "execute" nocase
            $s5 = "createprocess" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "user32.dll" nocase
            $s8 = "advapi32.dll" nocase
            $s9 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d12cd9490fd75e192ea053a05e869ed2f3f9748bf1563e6e496e7153fb4e_8783ac3cc0168ebaef9c448fbe7e937f
{
    meta:
        description = "Detects suspicious strings in d12cd9490fd75e192ea053a05e869ed2f3f9748bf1563e6e496e7153fb4e6c98"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
            $s3 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d176951b9ff3239b659ad57b729edb0845785e418852ecfeef1669f4c6fe_5022f69c4d88bc33457bb5248d97a045
{
    meta:
        description = "Detects suspicious strings in d176951b9ff3239b659ad57b729edb0845785e418852ecfeef1669f4c6fed61b"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".dll" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
            $s4 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d17fe5bc3042baf219e81cbbf991749dfcd8b6d73cf6506a8228e19910da_703bd29d65106d29651132d8c633a1c9
{
    meta:
        description = "Detects suspicious strings in d17fe5bc3042baf219e81cbbf991749dfcd8b6d73cf6506a8228e19910da3578"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".dll" nocase
            $s2 = "upload" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d2642d3731508b52efa34adf57701f18e2f8b70addf31e33e445e75b9a90_4bb44c229b5ebd44bfabffdbb3635d8b
{
    meta:
        description = "Detects suspicious strings in d2642d3731508b52efa34adf57701f18e2f8b70addf31e33e445e75b9a909822"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d2cc1135c314f526f88fbe19f25d94899d52de7e3422f334437f32388d04_80c32b291a7074423e179769183897f2
{
    meta:
        description = "Detects suspicious strings in d2cc1135c314f526f88fbe19f25d94899d52de7e3422f334437f32388d040d71"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d30f306d4d866a07372b94f7657a7a2b0500137fe7ef51678d0ef4249895_6f11a67803e1299a22c77c8e24072b82
{
    meta:
        description = "Detects suspicious strings in d30f306d4d866a07372b94f7657a7a2b0500137fe7ef51678d0ef4249895c2c5"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "hook" nocase
            $s3 = "execute" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d31d135bc450eafa698e6b7fb5d11b4926948163af09122ca1c568284d8b_1de9b3824870d8cc2d36448b32d145d8
{
    meta:
        description = "Detects suspicious strings in d31d135bc450eafa698e6b7fb5d11b4926948163af09122ca1c568284d8b33b3"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "cmd.exe" nocase
            $s4 = "upload" nocase
            $s5 = "createprocess" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "user32.dll" nocase
            $s8 = "advapi32.dll" nocase
            $s9 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d43c10a2c983049d4a32487ab1e8fe7727646052228554e0112f6651f483_b61068f85f030ee23d5b33b5b0c03930
{
    meta:
        description = "Detects suspicious strings in d43c10a2c983049d4a32487ab1e8fe7727646052228554e0112f6651f4833d2c"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "download" nocase
            $s3 = "execute" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d5c57788cf12b020c4083eb228911260b744a2a67c88662c9bab8faebca9_85f5feeed15b75cacb63f9935331cf4e
{
    meta:
        description = "Detects suspicious strings in d5c57788cf12b020c4083eb228911260b744a2a67c88662c9bab8faebca98fa2"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
            $s3 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d86af736644e20e62807f03c49f4d0ad7de9cbd0723049f34ec79f8c7308_c0321a1a0d33cd88bb04ec0250f8e924
{
    meta:
        description = "Detects suspicious strings in d86af736644e20e62807f03c49f4d0ad7de9cbd0723049f34ec79f8c7308fdd5"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "download" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d8823ee70109ce789639748933a45c723060040597d17925cb605ad8f7f8_2c3a634953a9a2c227a51e8eeac9f137
{
    meta:
        description = "Detects suspicious strings in d8823ee70109ce789639748933a45c723060040597d17925cb605ad8f7f85a14"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d8a849654ab97debaf28ae5b749c3b1ff1812ea49978713853333db48c39_a6dcae1c11c0d4dd146937368050f655
{
    meta:
        description = "Detects suspicious strings in d8a849654ab97debaf28ae5b749c3b1ff1812ea49978713853333db48c3972c3"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_d8fdcdaad652c19f4f4676cd2f89ae834dbc19e2759a206044b18601875f_4f8b989bc424a39649805b5b93318295
{
    meta:
        description = "Detects suspicious strings in d8fdcdaad652c19f4f4676cd2f89ae834dbc19e2759a206044b18601875f2726"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "hook" nocase
            $s4 = "execute" nocase
            $s5 = "createprocess" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "user32.dll" nocase
            $s8 = "advapi32.dll" nocase
            $s9 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_da1c9cb862b0be89819a94335eea8bf5ab56e08a1f4ca0ef92fe8d46fd2b_5ae89d3551dbb4a67618489f3bf2a370
{
    meta:
        description = "Detects suspicious strings in da1c9cb862b0be89819a94335eea8bf5ab56e08a1f4ca0ef92fe8d46fd2b1577"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_db36ad77875bbf622d96ae8086f44924c37034dd95e9eb6d6369cc6accd2_62779df699c84d665c17c2e217015269
{
    meta:
        description = "Detects suspicious strings in db36ad77875bbf622d96ae8086f44924c37034dd95e9eb6d6369cc6accd2a40d"
        author = "Auto-generated"
        
    strings:
                    $s0 = "https://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "download" nocase
            $s4 = "upload" nocase
            $s5 = "execute" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "advapi32.dll" nocase
            $s8 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_dd469fbf68f6bf71e495b3e497e31d17aa1d0af918a943f8637dd3304f84_96f35de25bdb252f0bf171475010b3c4
{
    meta:
        description = "Detects suspicious strings in dd469fbf68f6bf71e495b3e497e31d17aa1d0af918a943f8637dd3304f840740"
        author = "Auto-generated"
        
    strings:
                    $s0 = "https://" nocase
            $s1 = ".dll" nocase
            $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_dea53e331d3b9f21354147f60902f6e132f06183ed2f4a28e67816f9cb14_1dcac3178a1b85d5179ce75eace04d10
{
    meta:
        description = "Detects suspicious strings in dea53e331d3b9f21354147f60902f6e132f06183ed2f4a28e67816f9cb140a90"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "hook" nocase
            $s4 = "execute" nocase
            $s5 = "createprocess" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "user32.dll" nocase
            $s8 = "advapi32.dll" nocase
            $s9 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e049d8f69ddee0c2d360c27b98fa9e61b7202bb0d3884dd3ca63f8aa2884_994bd0b23cce98b86e58218b9032ffab
{
    meta:
        description = "Detects suspicious strings in e049d8f69ddee0c2d360c27b98fa9e61b7202bb0d3884dd3ca63f8aa288422dc"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "download" nocase
            $s3 = "execute" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e0f109836a025d4531ea895cebecc9bdefb84a0cc747861986c4bc231e1d_89ca5b5a6e4e320f80a6c9595f3f83e6
{
    meta:
        description = "Detects suspicious strings in e0f109836a025d4531ea895cebecc9bdefb84a0cc747861986c4bc231e1d4213"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".dll" nocase
            $s2 = "upload" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e1ba03a10a40aab909b2ba58dcdfd378b4d264f1f4a554b669797bbb8c8a_6662c390b2bbbd291ec7987388fc75d7
{
    meta:
        description = "Detects suspicious strings in e1ba03a10a40aab909b2ba58dcdfd378b4d264f1f4a554b669797bbb8c8ac902"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e1d852f2ea8436ac33bc8fe200aca4af4fb15f33ecda6441741589daa441_0e7db6b6a6e4993a01a01df578d65bf0
{
    meta:
        description = "Detects suspicious strings in e1d852f2ea8436ac33bc8fe200aca4af4fb15f33ecda6441741589daa44115c5"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "cmd.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e2e6ed82703de21eb4c5885730ba3db42f3ddda8b94beb2ee0c3af61bc43_eb7042ad32f41c0e577b5b504c7558ea
{
    meta:
        description = "Detects suspicious strings in e2e6ed82703de21eb4c5885730ba3db42f3ddda8b94beb2ee0c3af61bc435747"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "hook" nocase
            $s4 = "execute" nocase
            $s5 = "createprocess" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "user32.dll" nocase
            $s8 = "advapi32.dll" nocase
            $s9 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e49778d20a2f9b1f8b00ddd24b6bcee81af381ed02cfe0a3c9ab3111cda5_adb5c262ca4f95fee36ae4b9b5d41d45
{
    meta:
        description = "Detects suspicious strings in e49778d20a2f9b1f8b00ddd24b6bcee81af381ed02cfe0a3c9ab3111cda5f573"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "explorer.exe" nocase
            $s4 = "execute" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e5b68ab68b12c3eaff612ada09eb2d4c403f923cdec8a5c8fe253c677320_66e2adf710261e925db588b5fac98ad8
{
    meta:
        description = "Detects suspicious strings in e5b68ab68b12c3eaff612ada09eb2d4c403f923cdec8a5c8fe253c6773208baf"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "hook" nocase
            $s4 = "execute" nocase
            $s5 = "createprocess" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "user32.dll" nocase
            $s8 = "advapi32.dll" nocase
            $s9 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e77306d2e3d656fa04856f658885803243aef204760889ca2c09fbe9ba36_7f9596b332134a60f9f6b85ab616b141
{
    meta:
        description = "Detects suspicious strings in e77306d2e3d656fa04856f658885803243aef204760889ca2c09fbe9ba36581d"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "download" nocase
            $s3 = "execute" nocase
            $s4 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e784e95fb5b0188f0c7c82add9a3c89c5bc379eaf356a4d3876d9493a986_ff76d7009d93b6b9c9d8af81a3a77587
{
    meta:
        description = "Detects suspicious strings in e784e95fb5b0188f0c7c82add9a3c89c5bc379eaf356a4d3876d9493a986e343"
        author = "Auto-generated"
        
    strings:
                    $s0 = "https://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "download" nocase
            $s4 = "upload" nocase
            $s5 = "execute" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "advapi32.dll" nocase
            $s8 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e83c6c36dbd143ee0fd36aff30fb43529a34129817dc2530f251121527cb_856752482c29bd93a5c2b62ff50df2f0
{
    meta:
        description = "Detects suspicious strings in e83c6c36dbd143ee0fd36aff30fb43529a34129817dc2530f251121527cbf4b4"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
            $s3 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e89614e3b0430d706bef2d1f13b30b43e5c53db9a477e2ff60ef5464e1e9_9f9723c5ff4ec1b7f08eb2005632b8b1
{
    meta:
        description = "Detects suspicious strings in e89614e3b0430d706bef2d1f13b30b43e5c53db9a477e2ff60ef5464e1e9add4.exe"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "createprocess" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
            $s4 = "advapi32.dll" nocase
            $s5 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_e93d6f4ce34d4f594d7aed76cfde0fad_e93d6f4ce34d4f594d7aed76cfde0fad
{
    meta:
        description = "Detects suspicious strings in e93d6f4ce34d4f594d7aed76cfde0fad"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ea140cc8da39014c1454c3f6a036d5f43aa26c215cb9981ab2b7076f2388_d1bbd312476c5c0d56fc85460b33d6aa
{
    meta:
        description = "Detects suspicious strings in ea140cc8da39014c1454c3f6a036d5f43aa26c215cb9981ab2b7076f2388b73e"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ea335556fecaf983f6f26b9788b286fbf5bd85ff403bb4a1db604496d011_edaca6fb1896a120237b2ce13f6bc3e6
{
    meta:
        description = "Detects suspicious strings in ea335556fecaf983f6f26b9788b286fbf5bd85ff403bb4a1db604496d011be29"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "download" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
            $s4 = "advapi32.dll" nocase
            $s5 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_eac776c3c83c9db1a770ffaf6df9e94611c8293cbd41cb9257148603b8f2_518f52aabd9a059d181bfe864097091e
{
    meta:
        description = "Detects suspicious strings in eac776c3c83c9db1a770ffaf6df9e94611c8293cbd41cb9257148603b8f2be0b"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "execute" nocase
            $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e_84c82835a5d21bbcf75a61706d8ab549
{
    meta:
        description = "Detects suspicious strings in ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.exe"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "cmd.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
            $s7 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ee21378abf78e31d79f9170e76d01ffb74aa65ce885937fb5bc1e71dff68_60e0f1362da65e11bb268be5b1ad1053
{
    meta:
        description = "Detects suspicious strings in ee21378abf78e31d79f9170e76d01ffb74aa65ce885937fb5bc1e71dff68627d"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "hook" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ee41eb21f439b1168ae815ca067ee91d84d6947397d71e214edc6868dbf4_c19b3c9566bd76ee632a0ca16f7b66d2
{
    meta:
        description = "Detects suspicious strings in ee41eb21f439b1168ae815ca067ee91d84d6947397d71e214edc6868dbf4f272"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "cmd.exe" nocase
            $s4 = "upload" nocase
            $s5 = "createprocess" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "user32.dll" nocase
            $s8 = "advapi32.dll" nocase
            $s9 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_eefa052da01c3faa1d1f516ddfefa8ceb8a5185bb9b5368142ffdf839aea_8ed9a60127aee45336102bf12059a850
{
    meta:
        description = "Detects suspicious strings in eefa052da01c3faa1d1f516ddfefa8ceb8a5185bb9b5368142ffdf839aea4506"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ef47aaf4e964e1e1b7787c480e60a744550de847618510d2bf54bbc5bda5_22872f40f5aad3354bbf641fe90f2fd6
{
    meta:
        description = "Detects suspicious strings in ef47aaf4e964e1e1b7787c480e60a744550de847618510d2bf54bbc5bda57470"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "execute" nocase
            $s4 = "kernel32.dll" nocase
            $s5 = "user32.dll" nocase
            $s6 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ef4a2cfe4d9d3495d4957a65299f608f7b823fab0699fded728fd3900c0b_5331f7b2aeb1936f4be5a0278a18fe32
{
    meta:
        description = "Detects suspicious strings in ef4a2cfe4d9d3495d4957a65299f608f7b823fab0699fded728fd3900c0b2bb4"
        author = "Auto-generated"
        
    strings:
                    $s0 = "https://" nocase
            $s1 = ".dll" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
            $s4 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_efd470cfa90b918e5d558e5c8c3821343af06eedfd484dfeb20c4605f9bd_d45931632ed9e11476325189ccb6b530
{
    meta:
        description = "Detects suspicious strings in efd470cfa90b918e5d558e5c8c3821343af06eedfd484dfeb20c4605f9bdc30e.bin"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "c:\\windows\\temp\\" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f152ed03e4383592ce7dd548c34f73da53fc457ce8f26d165155a331cde6_43451a1691ff539bccff261ecf6e5912
{
    meta:
        description = "Detects suspicious strings in f152ed03e4383592ce7dd548c34f73da53fc457ce8f26d165155a331cde643a9"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f1d903251db466d35533c28e3c032b7212aa43c8d64ddf8c5521b43031e6_06665b96e293b23acc80451abb413e50
{
    meta:
        description = "Detects suspicious strings in f1d903251db466d35533c28e3c032b7212aa43c8d64ddf8c5521b43031e69e1e"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f34bd1d485de437fe18360d1e850c3fd64415e49d691e610711d8d232071_89ae36448f1922870f1a09c29f17c775
{
    meta:
        description = "Detects suspicious strings in f34bd1d485de437fe18360d1e850c3fd64415e49d691e610711d8d232071a0b1"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f4ea99dc41cb7922d01955eef9303ec3a24b88c3318138855346de1e830e_a284c8b14e4be0e2e561e5ff64e82dc7
{
    meta:
        description = "Detects suspicious strings in f4ea99dc41cb7922d01955eef9303ec3a24b88c3318138855346de1e830ed09e"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f5b6c0d73c513c3c8efbcc967d7f6865559e90d59fb78b2b15394f22fd73_b00d6c58282f94d7d0c729c57608f515
{
    meta:
        description = "Detects suspicious strings in f5b6c0d73c513c3c8efbcc967d7f6865559e90d59fb78b2b15394f22fd7315cb"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f5ca1277b7fde07880a691f7f3794a11980a408c510442fde486793ee56a_fb8eac22caa97d5fe5f96e3f79455096
{
    meta:
        description = "Detects suspicious strings in f5ca1277b7fde07880a691f7f3794a11980a408c510442fde486793ee56ad291"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f60b29cfb7eab3aeb391f46e94d4d8efadde5498583a2f5c71bd8212d8ae_9a6e4b8a6ba5b4f5a408919d2c169d92
{
    meta:
        description = "Detects suspicious strings in f60b29cfb7eab3aeb391f46e94d4d8efadde5498583a2f5c71bd8212d8ae92da"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = "/tmp/" nocase
            $s3 = "/var/tmp/" nocase
            $s4 = "download" nocase
            $s5 = "upload" nocase
            $s6 = "execute" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f65fa71e8ffe11bb6e7c6c84c3d365f4fe729e1e9c38cb4f073d2b650584_ca0403ea24fe2a7771b99cea55826c9b
{
    meta:
        description = "Detects suspicious strings in f65fa71e8ffe11bb6e7c6c84c3d365f4fe729e1e9c38cb4f073d2b65058465fa"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f66a6b49a23cf3cc842a84d955c0292e7d1c0718ec4e78d4513e18b6c53a_fcbe26bc77e65df9141d55a01856e270
{
    meta:
        description = "Detects suspicious strings in f66a6b49a23cf3cc842a84d955c0292e7d1c0718ec4e78d4513e18b6c53a94ac"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".dll" nocase
            $s2 = "createprocess" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
            $s5 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f6993e767306d4cbf676bf3c4a56fc2ad1d5cb6c4f67563f6de2f28b79f2_6396f4adb2287acc11d0ff786b801d79
{
    meta:
        description = "Detects suspicious strings in f6993e767306d4cbf676bf3c4a56fc2ad1d5cb6c4f67563f6de2f28b79f2b934"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_f6e5a3a32fb3aaf3f2c56ee482998b09a6ced0a60c38088e7153f3ca247a_2ec79d0605a4756f4732aba16ef41b22
{
    meta:
        description = "Detects suspicious strings in f6e5a3a32fb3aaf3f2c56ee482998b09a6ced0a60c38088e7153f3ca247ab1cc"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_fa5390bbcc4ab768dd81f31eac0950f6_fa5390bbcc4ab768dd81f31eac0950f6
{
    meta:
        description = "Detects suspicious strings in fa5390bbcc4ab768dd81f31eac0950f6"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_fc085d9be18f3d8d7ca68fbe1d9e29abbe53e7582453f61a9cd65da06961_7cd87c4976f1b34a0b060a23faddbd19
{
    meta:
        description = "Detects suspicious strings in fc085d9be18f3d8d7ca68fbe1d9e29abbe53e7582453f61a9cd65da06961f751"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "hook" nocase
            $s4 = "execute" nocase
            $s5 = "createprocess" nocase
            $s6 = "kernel32.dll" nocase
            $s7 = "user32.dll" nocase
            $s8 = "advapi32.dll" nocase
            $s9 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_fc75410aa8f76154f5ae8fe035b9a13c76f6e132077346101a0d673ed9f3_5e8e046cb09f73b1e02aa4ac69c5765e
{
    meta:
        description = "Detects suspicious strings in fc75410aa8f76154f5ae8fe035b9a13c76f6e132077346101a0d673ed9f3a0dd"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "download" nocase
            $s3 = "execute" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_fcf603f5d5e788c21acd4a1c7b36d6bc8f980b42cf1ef3f88e8973551263_f94541b48f85af92ea43e53d8b011aad
{
    meta:
        description = "Detects suspicious strings in fcf603f5d5e788c21acd4a1c7b36d6bc8f980b42cf1ef3f88e89735512637c24"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_fd042b14ae659e420a15c3b7db25649d3b21d92c586fe8594f88c21ae677_1e19b857a5f5a9680555fa9623a88e99
{
    meta:
        description = "Detects suspicious strings in fd042b14ae659e420a15c3b7db25649d3b21d92c586fe8594f88c21ae6770956"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_fe4fad660bb44e108ab07d812f8b1bbf16852c1b881a5e721a9f811cae31_f42d999a3be9354031eb0fc57065dd2d
{
    meta:
        description = "Detects suspicious strings in fe4fad660bb44e108ab07d812f8b1bbf16852c1b881a5e721a9f811cae317f39"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".dll" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
            $s4 = "advapi32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_fef436e4196ae779ec1d6dd6dcfeec045bc1f848efed5b24e287354a18c6_6aa3115fa1f3adb8f0539e93d2cf21ca
{
    meta:
        description = "Detects suspicious strings in fef436e4196ae779ec1d6dd6dcfeec045bc1f848efed5b24e287354a18c6dd85"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "execute" nocase
            $s2 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ff301b3295959a3ac5f3d0a5ea0d9f0aedcd8da7c4207b18f4bbb6ddaa0c_c1d73ce5bf0559a86bae0f9045a82e0a
{
    meta:
        description = "Detects suspicious strings in ff301b3295959a3ac5f3d0a5ea0d9f0aedcd8da7c4207b18f4bbb6ddaa0cdf22"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_ffef75582ad185c58135cf02e347c0ad6d46751fcfbb803dc3e70b73729e_fc5f3bea0b5efa55f2dae285a51ad90d
{
    meta:
        description = "Detects suspicious strings in ffef75582ad185c58135cf02e347c0ad6d46751fcfbb803dc3e70b73729e6136"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_index_36ad56b6dee8df522d6ff1bfa8352d17
{
    meta:
        description = "Detects suspicious strings in index"
        author = "Auto-generated"
        
    strings:
                    $s0 = "download" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_install_126e7840a978ae90dfa731a66afbe9be
{
    meta:
        description = "Detects suspicious strings in install"
        author = "Auto-generated"
        
    strings:
                    $s0 = "execute" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_jigsaw_2773e3dc59472296cb0024ba7715a64e
{
    meta:
        description = "Detects suspicious strings in jigsaw"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "download" nocase
            $s3 = "kernel32.dll" nocase
            $s4 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_linux_chapros__E022DE72CCE8129BD5AC8A0675996318_e022de72cce8129bd5ac8a0675996318
{
    meta:
        description = "Detects suspicious strings in linux-chapros_ E022DE72CCE8129BD5AC8A0675996318"
        author = "Auto-generated"
        
    strings:
                    $s0 = "inject" nocase
            $s1 = "hook" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_loader_9b313e9c79921b22b488a11344b280d4cec9dd09c2201f9e5aaf0_2f08d1f1b1968be7f9669e2ff94dea76
{
    meta:
        description = "Detects suspicious strings in loader_9b313e9c79921b22b488a11344b280d4cec9dd09c2201f9e5aaf08a115650b25"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "kernel32.dll" nocase
            $s2 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_master_6e0e5ef3aa67a43e837a8361523a5829
{
    meta:
        description = "Detects suspicious strings in master"
        author = "Auto-generated"
        
    strings:
                    $s0 = "https://" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_payload_f8eccfebda8a1e0caabbe23a8b94d7ced980353a9b3673a4173e_cb10fb803dc1f81b4bd324a5859b3ed5
{
    meta:
        description = "Detects suspicious strings in payload_f8eccfebda8a1e0caabbe23a8b94d7ced980353a9b3673a4173e24958a3bdbb9"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".dll" nocase
            $s2 = "malware" nocase
            $s3 = "execute" nocase
            $s4 = "createprocess" nocase
            $s5 = "kernel32.dll" nocase
            $s6 = "user32.dll" nocase
            $s7 = "advapi32.dll" nocase
            $s8 = "ws2_32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_php_5c4dc9e4448796027c79bc6c72f00daa
{
    meta:
        description = "Detects suspicious strings in php"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = "https://" nocase
            $s2 = "hook" nocase
            $s3 = "upload" nocase
            $s4 = "execute" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_stabuniq_F31B797831B36A4877AA0FD173A7A4A2_f31b797831b36a4877aa0fd173a7a4a2
{
    meta:
        description = "Detects suspicious strings in stabuniq_F31B797831B36A4877AA0FD173A7A4A2"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".dll" nocase
            $s1 = "createprocess" nocase
            $s2 = "kernel32.dll" nocase
            $s3 = "user32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_the_zeus_binary_chapros_3840a6506d9d5c2443687d1cf07e25d0
{
    meta:
        description = "Detects suspicious strings in the_zeus_binary_chapros"
        author = "Auto-generated"
        
    strings:
                    $s0 = ".exe" nocase
            $s1 = ".dll" nocase
            $s2 = "cmd.exe" nocase
            $s3 = "createprocess" nocase
            $s4 = "kernel32.dll" nocase
        
    condition:
        any of them
}


rule SuspiciousStrings_zerolocker_d4c62215df74753371db33a19a69fccdc4b375c893a4b7f8b_bd0a3c308a6d3372817a474b7c653097
{
    meta:
        description = "Detects suspicious strings in zerolocker_d4c62215df74753371db33a19a69fccdc4b375c893a4b7f8b30172710fbd4cfa"
        author = "Auto-generated"
        
    strings:
                    $s0 = "http://" nocase
            $s1 = ".exe" nocase
            $s2 = ".dll" nocase
            $s3 = "download" nocase
            $s4 = "execute" nocase
        
    condition:
        any of them
}

