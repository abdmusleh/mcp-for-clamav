import hashlib
import re
import yara
import math
import sys

def create_yara_rules(features, filename):
    rules = []
    imports = set()

    if not features or features.get("error"):
        return rules, imports

    file_hash = features.get("hash", hashlib.md5(filename.encode()).hexdigest())
    clean_name = clean_filename(filename)

    # Check what imports we need
    if features.get("hash"):
        imports.add('import "hash"')
    if features.get("is_pe"):
        imports.add('import "pe"')
        imports.add('import "math"')

    # Rule 1: File hash detection
    if features.get("hash"):
        hash_rule = f'''
rule Hash_{clean_name}_{file_hash}
{{
    meta:
        description = "Detects {filename} by MD5 hash"
        author = "Auto-generated"
        hash = "{features['hash']}"
        
    condition:
        hash.md5(0, filesize) == "{features['hash']}"
}}'''
        
        if validate_rule(hash_rule, imports):
            rules.append(hash_rule)

    # Rule 2: Suspicious API imports for PE files
    if features.get("is_pe") and features.get("imports"):
        suspicious_apis = [
            "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
            "SetWindowsHookEx", "URLDownloadToFileA", "WinExec",
            "LoadLibrary", "GetProcAddress"
        ]

        imports_list = features.get("imports", [])
        if not isinstance(imports_list, list):
            imports_list = []

        found_apis = [api for api in imports_list if isinstance(api, str) and api in suspicious_apis]
        if found_apis:
            conditions = [f'pe.imports("{api}")' for api in found_apis[:10]]
            if conditions:
                import_rule = f'''
rule SuspiciousImports_{clean_name}_{file_hash}
{{
    meta:
        description = "Detects suspicious API imports in {filename}"
        author = "Auto-generated"
        
    condition:
        uint16(0) == 0x5A4D and ({" or ".join(conditions)})
}}'''
                
                if validate_rule(import_rule, imports):
                    rules.append(import_rule)

    # Rule 3: High entropy sections for PE files
    if features.get("is_pe") and features.get("sections"):
        sections_list = features.get("sections", [])
        if not isinstance(sections_list, list):
            sections_list = []

        MAX_SECTION_SIZE = 10 * 1024 * 1024  # 10 MB limit

        for section in sections_list:
            if isinstance(section, dict) and section.get("entropy", 0) > 7.5:
                section_size = section.get("size", 0)
                if section_size == 0 or section.get("offset") is None:
                    continue

                if section_size > MAX_SECTION_SIZE:
                    sys.stderr.write(f"Skipping large section in {filename} ({section_size} bytes)\n")
                    continue

                section_name = escape_string(section.get("name", "unknown_section"))

                entropy_rule = f'''
rule HighEntropy_{clean_name}_{file_hash}
{{
    meta:
        description = "Detects high entropy section '{section_name}' in {filename}"
        author = "Auto-generated"
        
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].name == "{section_name}" and
            math.entropy(pe.sections[i].offset, pe.sections[i].size) > 7.5
        )
}}'''
                
                if validate_rule(entropy_rule, imports):
                    rules.append(entropy_rule)
                    break  # Only create one entropy rule per file

    # Rule 4: Suspicious strings
    if features.get("strings"):
        strings_list = features.get("strings", [])
        if not isinstance(strings_list, list):
            strings_list = []

        suspicious_strings = [
            "http://", "https://", ".exe", ".dll", "cmd.exe",
            "powershell.exe", "rundll32.exe", "regedit.exe", "explorer.exe",
            "malware", "virus", "trojan", "keylogger", "backdoor",
            "c:\\windows\\temp\\", "/tmp/", "/var/tmp/",
            "shellcode", "process hollowing", "inject", "hook",
            "download", "upload", "execute", "createprocess",
            "kernel32.dll", "user32.dll", "advapi32.dll", "ws2_32.dll"
        ]

        found_strings = []
        for bad_str in suspicious_strings:
            if any(isinstance(s, str) and bad_str.lower() in s.lower() for s in strings_list):
                found_strings.append(bad_str)
        
        if found_strings and len(found_strings) <= 20:
            string_defs = []
            for i, s in enumerate(found_strings):
                escaped = escape_string(s)
                if escaped.strip():
                    string_defs.append(f'$s{i} = "{escaped}" nocase')

            if string_defs:
                string_rule = f'''
rule SuspiciousStrings_{clean_name}_{file_hash}
{{
    meta:
        description = "Detects suspicious strings in {filename}"
        author = "Auto-generated"
        
    strings:
        {chr(10).join(f"            {s}" for s in string_defs)}
        
    condition:
        any of them
}}'''
                
                if validate_rule(string_rule, imports):
                    rules.append(string_rule)

    return rules, imports

def clean_filename(filename):
    if not isinstance(filename, str):
        filename = "unknown_file"
    
    name = re.sub(r'[^a-zA-Z0-9_.]', '_', filename)
    return name.strip('_')[:60]

def escape_string(s):
    if isinstance(s, bytes):
        s = s.decode('utf-8', errors='replace')
    elif not isinstance(s, str):
        s = str(s)
    
    s = s.replace('\\', '\\\\')
    s = s.replace('"', '\\"')
    s = s.replace('\x00', '')
    s = s.replace('\n', '\\n')
    s = s.replace('\r', '\\r')
    return s

def validate_rule(rule_text, needed_imports):
    try:
        full_rule = "\n".join(sorted(list(needed_imports))) + "\n\n" + rule_text if needed_imports else rule_text
        yara.compile(source=full_rule)
        return True
    except yara.Error as e:
        sys.stderr.write(f"Invalid YARA rule: {e}\n")
        return False
    except Exception as e:
        sys.stderr.write(f"Error compiling YARA rule: {e}\n")
