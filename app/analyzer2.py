# analyzer.py - Simple binary analysis tool
import lief
import hashlib
import os
import re
import math

def analyze_file(file_path):
    """Analyze a binary file and extract useful features"""
    try:
        binary = lief.parse(file_path)
        if not binary:
            return {"error": "Can't parse this file format"}
            
        # Basic file info
        result = {
            "hash": get_file_hash(file_path),
            "strings": find_strings(file_path),
            "sections": [],
            "imports": [],
            "entropy": 0.0,
            "is_pe": binary.format == lief.Binary.FORMATS.PE
        }
        
        # Get sections info
        if binary.sections:
            for section in binary.sections:
                section_data = {
                    "name": section.name,
                    "entropy": getattr(section, 'entropy', 0.0),
                    "size": section.size,
                    "virtual_address": section.virtual_address
                }
                result["sections"].append(section_data)
        
        # Get imports for PE files
        if result["is_pe"] and hasattr(binary, 'imports') and binary.imports:
            for lib in binary.imports:
                if hasattr(lib, 'entries') and lib.entries:
                    for entry in lib.entries:
                        if entry.is_ordinal:
                            result["imports"].append(f"#{entry.ordinal}")
                        else:
                            result["imports"].append(entry.name)
        
        # Calculate overall file entropy
        with open(file_path, "rb") as f:
            content = f.read()
            result["entropy"] = calculate_entropy(content)
            
        return result
        
    except lief.bad_file as e:
        return {"error": f"LIEF parsing failed: {str(e)}"}
    except FileNotFoundError:
        return {"error": f"File not found: {file_path}"}
    except Exception as e:
        return {"error": f"Analysis failed: {str(e)}"}

def find_strings(file_path):
    """Extract readable strings from file"""
    strings = []
    try:
        with open(file_path, "rb") as f:
            data = f.read(10 * 1024 * 1024)  # Read first 10MB
            
            # Find ASCII strings
            ascii_matches = re.findall(rb'[\x20-\x7E]{4,}', data)
            for match in ascii_matches:
                try:
                    strings.append(match.decode("utf-8", errors="strict"))
                except UnicodeDecodeError:
                    pass # Ignore strings that aren't valid UTF-8
            
            # Find Unicode strings (UTF-16 LE)
            # Ensure data length is even for UTF-16 processing
            if len(data) % 2 != 0:
                data_unicode = data[:-1]
            else:
                data_unicode = data
            unicode_matches = re.findall(rb'(?:[\x20-\x7E]\x00){4,}', data_unicode)
            for match in unicode_matches:
                try:
                    strings.append(match.decode("utf-16le", errors="strict"))
                except UnicodeDecodeError:
                    pass # Ignore strings that aren't valid UTF-16
                
    except Exception:
        pass # Ignore errors during string extraction
    
    # Limit number of strings to avoid excessive output
    return strings[:1000]

def get_file_hash(file_path):
    """Get MD5 hash of file"""
    try:
        md5_hash = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()
    except Exception:
        return None

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    
    # Count byte frequencies
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    
    # Calculate entropy
    entropy = 0
    length = len(data)
    for count in counts:
        if count > 0:
            p = float(count) / length
            entropy -= p * math.log(p, 2)
    
    return entropy
