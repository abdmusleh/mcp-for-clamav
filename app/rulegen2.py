# rulegen.py - YARA rule generator  
import hashlib
import re
import yara
import math

def create_yara_rules(features, filename):
    """Generate YARA rules based on file analysis features. """
    rules = []
    
    if not features or features.get("error"):
        
        return rules 
    
    
    file_hash = features.get("hash", hashlib.md5(filename.encode()).hexdigest())
    rule_id = file_hash[:8] 
    clean_name = clean_filename(filename) 

    
    
    
    if features.get("is_pe") and features.get("imports"):
        bad_apis = [
            "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
            "SetWindowsHookEx", "URLDownloadToFileA", "WinExec",
            "NtReadVirtualMemory", "NtWriteVirtualMemory", "LdrLoadDll" 
        ]
        
        
        imports_list = features.get("imports", [])
        if not isinstance(imports_list, list):
            imports_list = [] 

        
        found_apis = [api for api in imports_list if isinstance(api, str) and api in bad_apis]
        
        if found_apis:
            conditions = [f'pe.imports("{api}")' for api in found_apis[:10]] 
            
            import_rule = f'''
rule SuspiciousImports_{clean_name}_{rule_id}
{{
    meta:
        description = "Detects suspicious API imports in {filename}"
        author = "Auto-generated"
        rule_type = "API_Based"
        
    strings:
        // No strings defined here as pe.imports is used directly in condition
        
    condition:
        uint16(0) == 0x5A4D and ({" or ".join(conditions)})
}}'''
            if is_valid_yara(import_rule):
                rules.append(import_rule)
    
  
    if features.get("is_pe") and features.get("sections"):
        sections_list = features.get("sections", [])
        if not isinstance(sections_list, list):
            sections_list = [] 
            
        for section in sections_list:
            
            if isinstance(section, dict) and section.get("entropy", 0) > 7.5:
                section_name = escape_string(section.get("name", "unknown_section"))
                
                entropy_rule = f'''
rule HighEntropy_{clean_name}_{rule_id}
{{
    meta:
        description = "Detects high entropy section '{section.get("name", "unknown")}' in {filename}"
        author = "Auto-generated"
        rule_type = "Entropy_Based"
        
    strings:
        // No strings, condition uses math.entropy module
        
    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].name == "{section_name}" and
            math.entropy(pe.sections[i].offset, pe.sections[i].size) > 7.5
        )
}}'''
                if is_valid_yara(entropy_rule):
                    rules.append(entropy_rule)
                    break  
    
    
    if features.get("strings"):
        strings_list = features.get("strings", [])
        if not isinstance(strings_list, list):
            strings_list = [] 
            
        bad_strings = [
            "http://", "https://", ".exe", ".dll", "cmd.exe", "powershell.exe", 
            "rundll32.exe", "user32.dll", "kernel32.dll", "advapi32.dll", 
            "C:\\Windows\\", "ProgramData", "AppData", "Temp\\", 
            "malware", "virus", "trojan", "ransom", "backdoor", 
            "downloadfile", "urlmoniker", "createprocess", "regopenkey", 
            "shell", "inject", "encrypt", "decrypt", "hacker", "payload" 
        ]
        
       
        found_strings = []
        for bad_str in bad_strings:
            if any(isinstance(s, str) and bad_str.lower() in s.lower() for s in strings_list):
                found_strings.append(bad_str)
        
        
        if found_strings and len(found_strings) <= 20: 
            string_defs = []
            for i, s in enumerate(found_strings):
                escaped = escape_string(s)
                string_defs.append(f'$s{i} = "{escaped}" nocase')
            
            string_rule = f'''
rule SuspiciousStrings_{clean_name}_{rule_id}
{{
    meta:
        description = "Detects suspicious strings in {filename}"
        author = "Auto-generated"
        rule_type = "String_Based"
        
    strings:
        {chr(10).join(f"        {s}" for s in string_defs)}
        
    condition:
        any of them
}}'''
            if is_valid_yara(string_rule):
                rules.append(string_rule)
    
    return rules

def clean_filename(filename):
    """Clean filename for use in YARA rule names.
    Replaces non-alphanumeric characters with underscores and limits length.
    """
    if not isinstance(filename, str):
        filename = "unknown_file"
    name = re.sub(r'[^a-zA-Z0-9_]', '_', filename)
    return name.strip('_')[:30] 

def escape_string(s):
    """Escape string for safe inclusion in YARA rules.
    Handles backslashes, double quotes, and null bytes.
    """
    if isinstance(s, bytes):
        s = s.decode('utf-8', errors='replace')
    elif not isinstance(s, str):
        s = str(s) 

    s = s.replace('\\', '\\\\') 
    s = s.replace('"', '\\"')   
    s = s.replace('\x00', '')   
    return s

def is_valid_yara(rule_text):
    """Test if a generated YARA rule compiles correctly.
    Uses the yara-python library to validate syntax.
    """
    try:
        yara.compile(source=rule_text)
        return True
    except yara.Error as e:
        
        print(f"DEBUG: Invalid YARA rule generated:\n{rule_text}\nError: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"DEBUG: Unexpected error during YARA compilation check: {e}", file=sys.stderr)
        return False
