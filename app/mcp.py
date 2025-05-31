import json
import sys
import os
import hashlib
import subprocess

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import rulegen2

CAPA_PATH = "/usr/local/bin/capa"
PEANALYZER_PATH = "/usr/local/bin/peanalyzer"

class MCPServer:
    def __init__(self):
        self.methods = {
            "malware/analyzeSample": self.analyze_sample,
            "yara/generateRulesFromFeatures": self.generate_rules_from_features
        }

    def read_request(self):
        try:
            line = sys.stdin.readline()
            if not line:
                return None
            return json.loads(line)
        except json.JSONDecodeError as e:
            self.send_error(None, -32700, f"Parse error: {e}")
            return None
        except Exception as e:
            self.send_error(None, -32000, f"Internal error: {e}")
            return None

    def send_response(self, response):
        sys.stdout.write(json.dumps(response) + '\n')
        sys.stdout.flush()

    def send_result(self, request_id, result):
        response = {
            "jsonrpc": "2.0",
            "result": result,
            "id": request_id
        }
        self.send_response(response)

    def send_error(self, request_id, code, message, data=None):
        error = {
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message,
                "data": data
            },
            "id": request_id
        }
        self.send_response(error)

    def analyze_sample(self, params, request_id):
        file_path = params.get("file_path")
        if not file_path or not os.path.exists(file_path):
            self.send_error(request_id, -32602, "Invalid params", "file_path required and must exist")
            return

        features = {
            "filename": os.path.basename(file_path),
            "size": os.path.getsize(file_path),
            "hash": hashlib.md5(open(file_path, 'rb').read()).hexdigest(),
            "is_pe": False,
            "imports": [],
            "sections": [],
            "strings": []
        }

        # Get strings from file
        try:
            strings_output = subprocess.check_output(['strings', '-n', '4', file_path], timeout=30).decode('utf-8', errors='ignore')
            features["strings"] = strings_output.splitlines()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            sys.stderr.write(f"Warning: strings command failed for {file_path}: {e}\n")
            features["strings"] = []

        # Check if PE file
        with open(file_path, 'rb') as f:
            magic_bytes = f.read(2)
            if magic_bytes == b'MZ':
                features["is_pe"] = True
            
        # Analyze PE structure if it's a PE file
        if features["is_pe"]:
            try:
                peanalyzer_cmd = [PEANALYZER_PATH, file_path]
                peanalyzer_output = subprocess.check_output(peanalyzer_cmd, timeout=60).decode('utf-8', errors='ignore')
                pe_analysis = json.loads(peanalyzer_output)

                if pe_analysis and isinstance(pe_analysis.get("imports"), list):
                    features["imports"] = [imp.get("name") for imp in pe_analysis["imports"] if imp.get("name")]
                
                if pe_analysis and isinstance(pe_analysis.get("sections"), list):
                    features["sections"] = pe_analysis["sections"]

            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                sys.stderr.write(f"Warning: peanalyzer failed for {file_path}: {e}\n")
                features["imports"] = []
                features["sections"] = []
            except json.JSONDecodeError as e:
                sys.stderr.write(f"Warning: peanalyzer output invalid JSON: {e}\n")
                features["imports"] = []
                features["sections"] = []
            except FileNotFoundError:
                sys.stderr.write(f"Error: peanalyzer not found at {PEANALYZER_PATH}\n")
                features["is_pe"] = False

        self.send_result(request_id, features)

    def generate_rules_from_features(self, params, request_id):
        features = params.get("features")
        filename = params.get("filename")

        if not features or not filename:
            self.send_error(request_id, -32602, "Invalid params", "features and filename required")
            return

        try:
            rules, imports = rulegen2.create_yara_rules(features, filename)
            self.send_result(request_id, {"rules": rules, "imports": list(imports)})
        except Exception as e:
            self.send_error(request_id, -32000, f"Error generating YARA rules: {e}", str(e))

    def run(self):
        sys.stderr.write("JSON-RPC server starting...\n")
        while True:
            request = self.read_request()
            if request is None:
                sys.stderr.write("Server shutting down\n")
                break

            method = request.get("method")
            params = request.get("params")
            request_id = request.get("id")

            if method in self.methods:
                try:
                    self.methods[method](params, request_id)
                except Exception as e:
                    self.send_error(request_id, -32000, f"Server error: {e}", str(e))
            else:
                self.send_error(request_id, -32601, "Method not found")

if __name__ == "__main__":
    server = MCPServer()
    server.run()
