# mcp_server.py - Manual JSON-RPC over Stdio Server

import sys
import json
import os
import traceback
import concurrent.futures
import time # Added import for time.ctime() for logging

# Import the analysis and rule generation logic
import analyzer2 
import rulegen2 

# --- START OF DEBUGGING ADDITION ---
# Define a log file for server errors
SERVER_LOG_FILE = "/tmp/mcp_server_error.log"

def log_error_to_file(message):
    """Writes error messages and tracebacks to a designated log file."""
    try:
        with open(SERVER_LOG_FILE, "a") as f:
            f.write(f"[{time.ctime()}] ERROR: {message}\n")
            traceback.print_exc(file=f)
            f.write("-" * 50 + "\n\n")
    except Exception as e:
        # Fallback to stderr if logging to file fails
        print(f"FATAL ERROR: Could not write to log file {SERVER_LOG_FILE}: {e}", file=sys.stderr)
        print(message, file=sys.stderr)
        traceback.print_exc(file=sys.stderr)

# --- END OF DEBUGGING ADDITION ---


def write_jsonrpc_response(response_id, result): 
    """Formats and writes a successful JSON-RPC response to stdout."""
    response = {
        "jsonrpc": "2.0",
        "id": response_id,
        "result": result
    }
    print(json.dumps(response), flush=True)

def write_jsonrpc_error(response_id, code, message, data=None):
    """Formats and writes a JSON-RPC error response to stdout."""
    error_obj = {"code": code, "message": message}
    if data:
        error_obj["data"] = data
    response = {
        "jsonrpc": "2.0",
        "id": response_id,
        "error": error_obj
    }
    print(json.dumps(response), flush=True)

def process_request(request_data):
    """Processes a single JSON-RPC request dictionary."""
    request_id = request_data.get("id")
    method = request_data.get("method")
    params = request_data.get("params")

    if not method or not isinstance(params, dict):
        write_jsonrpc_error(request_id, -32600, "Invalid Request: Missing method or params")
        return

    try:
        if method == "malware/analyzeSample":
            file_path = params.get("file_path")
            if not file_path or not isinstance(file_path, str):
                write_jsonrpc_error(request_id, -32602, "Invalid Params: Missing or invalid file_path")
                return
            
            # Ensure file exists before analyzing
            if not os.path.exists(file_path):
                write_jsonrpc_error(request_id, -32001, f"File not found: {file_path}")
                return
                
            try:
                # Using ProcessPoolExecutor to run analysis in a separate process with a timeout
                with concurrent.futures.ProcessPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(analyzer2.analyze_file, file_path)
                    result = future.result(timeout=60) # Set your desired timeout in seconds
                write_jsonrpc_response(request_id, result)
            except concurrent.futures.TimeoutError:
                write_jsonrpc_error(request_id, -32002, "Analysis timed out (exceeded 60 seconds).")
            except Exception as e:
                error_message = f"Analysis failed: {str(e)}"
                log_error_to_file(f"Error during analysis of {file_path} for request ID {request_id}: {error_message}") # Log to file
                write_jsonrpc_error(request_id, -32003, error_message)

        elif method == "yara/generateRulesFromFeatures":
            features = params.get("features")
            filename = params.get("filename")
            if not features or not isinstance(features, dict) or not filename or not isinstance(filename, str):
                write_jsonrpc_error(request_id, -32602, "Invalid Params: Missing or invalid features/filename")
                return
                
            if features.get("error"):
                write_jsonrpc_response(request_id, {"rules": []})
                return
                
            # --- START OF CHANGE: Add timeout for rulegen2.create_yara_rules ---
            try:
                # Using ThreadPoolExecutor for rule generation as it's CPU-bound Python code
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(rulegen2.create_yara_rules, features, filename)
                    result_rules = future.result(timeout=30) # 30 seconds timeout for rule generation
                write_jsonrpc_response(request_id, {"rules": result_rules})
            except concurrent.futures.TimeoutError:
                write_jsonrpc_error(request_id, -32004, "Rule generation timed out (exceeded 30 seconds).")
            except Exception as e:
                error_message = f"Rule generation failed: {str(e)}"
                log_error_to_file(f"Error during rule generation for {filename} (request ID {request_id}): {error_message}") # Log to file
                write_jsonrpc_error(request_id, -32005, error_message)
            # --- END OF CHANGE ---

        else:
            write_jsonrpc_error(request_id, -32601, f"Method not found: {method}")

    except Exception as e:
        # Catch-all for unexpected errors during processing
        error_message = f"Internal server error: {str(e)}"
        log_error_to_file(f"Error processing request ID {request_id}: {error_message}") # Log to file
        write_jsonrpc_error(request_id, -32603, error_message)

def main_loop():
    """Reads JSON-RPC requests from stdin and processes them."""
    print("Manual JSON-RPC server started. Listening on stdin...", file=sys.stderr, flush=True)
    # Ensure log file is clear at startup for a fresh run
    if os.path.exists(SERVER_LOG_FILE):
        try:
            os.remove(SERVER_LOG_FILE)
        except OSError as e:
            print(f"Warning: Could not remove old log file {SERVER_LOG_FILE}: {e}", file=sys.stderr, flush=True)
    
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
            
        # print(f"Received line: {line}", file=sys.stderr, flush=True) # Debug log - keep if useful, otherwise remove
        request_id = None
        try:
            request_data = json.loads(line)
            if not isinstance(request_data, dict):
                raise ValueError("Request must be a JSON object")
                    
            request_id = request_data.get("id")
            
            if request_data.get("jsonrpc") != "2.0":
                write_jsonrpc_error(request_id, -32600, "Invalid Request: Missing or invalid jsonrpc version")
                continue
                
            process_request(request_data)
            
        except json.JSONDecodeError:
            error_message = f"Failed to decode JSON: {line}"
            log_error_to_file(f"JSON Decode Error: {error_message}") # Log to file
            write_jsonrpc_error(request_id, -32700, error_message)
        except Exception as e:
            # Catch errors during the request processing setup (before process_request)
            error_message = f"Server error handling request: {str(e)}"
            log_error_to_file(f"General Server Error for line '{line}': {error_message}") # Log to file
            write_jsonrpc_error(request_id, -32603, error_message)
            
    print("Stdin closed. Server shutting down.", file=sys.stderr, flush=True)

if __name__ == "__main__":
    main_loop()
