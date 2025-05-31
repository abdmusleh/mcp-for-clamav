import argparse
import os
import json
import subprocess
import sys
import threading
import queue
import time

def start_server(script_path):
    process = subprocess.Popen(
        [sys.executable, script_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1
    )
    return process

def read_output(pipe, q):
    for line in iter(pipe.readline, b''):
        q.put(line)
    pipe.close()

def parse_args():
    parser = argparse.ArgumentParser(description="Generate YARA rules from malware samples")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--file', type=str, help='Path to a single sample file')
    group.add_argument('--batch', type=str, help='Path to file containing list of sample paths')
    
    parser.add_argument('--output-type', choices=['features', 'rules', 'both'], default='rules',
                        help='Output type: features (JSON), rules (YARA), or both')
    parser.add_argument('--output', type=str, help='Path to output file')
    parser.add_argument('--server-script', type=str, default=os.path.join(os.path.dirname(__file__), '../app/mcp.py'),
                        help='Path to MCP server script')
    parser.add_argument('--max-rules-per-file', type=int, default=500,
                        help='Max YARA rules per output file (0 for unlimited)')
    return parser.parse_args()

def main():
    args = parse_args()

    sample_files = []
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        sample_files.append(args.file)
    elif args.batch:
        if not os.path.exists(args.batch):
            print(f"Error: Batch file not found: {args.batch}", file=sys.stderr)
            sys.exit(1)
        with open(args.batch, 'r') as f:
            for line in f:
                file_path = line.strip()
                if file_path and not file_path.startswith("#"):
                    if os.path.exists(file_path):
                        sample_files.append(file_path)
                    else:
                        print(f"Warning: File not found, skipping: {file_path}", file=sys.stderr)

    server_script_path = os.path.abspath(args.server_script)
    if not os.path.exists(server_script_path):
        print(f"Error: Server script not found: {server_script_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Starting server: {server_script_path}...", file=sys.stderr)
    server_process = start_server(server_script_path)
    time.sleep(1.5)

    if server_process.poll() is not None:
        stderr_output = server_process.stderr.read().decode("utf-8", errors="ignore")
        print(f"ERROR: Server failed to start. Exit code: {server_process.poll()}", file=sys.stderr)
        print(f"Server stderr:\n{stderr_output}", file=sys.stderr)
        sys.exit(1)

    print("Server started successfully", file=sys.stderr)

    stdout_queue = queue.Queue()
    stderr_queue = queue.Queue()

    stdout_thread = threading.Thread(target=read_output, args=(server_process.stdout, stdout_queue))
    stderr_thread = threading.Thread(target=read_output, args=(server_process.stderr, stderr_queue))

    stdout_thread.daemon = True
    stderr_thread.daemon = True

    stdout_thread.start()
    stderr_thread.start()

    all_rules = set()
    all_imports = set()

    processed_count = 0
    success_count = 0
    
    if args.output and args.output_type == "rules":
        output_dir = os.path.dirname(os.path.abspath(args.output))
        os.makedirs(output_dir, exist_ok=True)

    try:
        for i, sample_file_path in enumerate(sample_files):
            processed_count += 1
            print(f"\nProcessing [{processed_count}/{len(sample_files)}]: {os.path.basename(sample_file_path)}", file=sys.stderr)

            # Analyze sample
            print(f"Analyzing {os.path.basename(sample_file_path)}...", file=sys.stderr)
            analyze_request = {
                "jsonrpc": "2.0",
                "method": "malware/analyzeSample",
                "params": {"file_path": sample_file_path},
                "id": i * 2
            }
            server_process.stdin.write(json.dumps(analyze_request).encode('utf-8') + b'\n')
            server_process.stdin.flush()

            analysis_response = None
            while True:
                try:
                    line = stdout_queue.get(timeout=10)
                    response = json.loads(line.decode('utf-8'))
                    if response.get("id") == analyze_request["id"]:
                        analysis_response = response
                        break
                    else:
                        stdout_queue.put(line)
                except queue.Empty:
                    print(f"ERROR: Timeout waiting for analysis response", file=sys.stderr)
                    analysis_response = {"error": {"message": "Client timeout"}}
                    break
                except json.JSONDecodeError:
                    print(f"ERROR: Invalid JSON response", file=sys.stderr)
                    analysis_response = {"error": {"message": "Invalid JSON"}}
                    break

            if analysis_response and analysis_response.get("error"):
                error_msg = analysis_response["error"].get("message", "Unknown error")
                print(f"ERROR: {error_msg}", file=sys.stderr)
                continue

            print(f"Analysis successful", file=sys.stderr)
            features = analysis_response.get("result")
            if not features:
                print(f"WARNING: No features returned", file=sys.stderr)
                continue

            # Generate rules
            print(f"Generating rules...", file=sys.stderr)
            generate_request = {
                "jsonrpc": "2.0",
                "method": "yara/generateRulesFromFeatures",
                "params": {"features": features, "filename": os.path.basename(sample_file_path)},
                "id": i * 2 + 1
            }
            server_process.stdin.write(json.dumps(generate_request).encode('utf-8') + b'\n')
            server_process.stdin.flush()

            generation_response = None
            while True:
                try:
                    line = stdout_queue.get(timeout=45)
                    response = json.loads(line.decode('utf-8'))
                    if response.get("id") == generate_request["id"]:
                        generation_response = response
                        break
                    else:
                        stdout_queue.put(line)
                except queue.Empty:
                    print(f"ERROR: Timeout waiting for rule generation", file=sys.stderr)
                    generation_response = {"error": {"message": "Client timeout"}}
                    break
                except json.JSONDecodeError:
                    print(f"ERROR: Invalid JSON response", file=sys.stderr)
                    generation_response = {"error": {"message": "Invalid JSON"}}
                    break

            if generation_response and generation_response.get("error"):
                error_msg = generation_response["error"].get("message", "Unknown error")
                print(f"ERROR: {error_msg}", file=sys.stderr)
                continue

            result = generation_response.get("result", {})
            rules = result.get("rules", [])
            imports = set(result.get("imports", []))

            all_rules.update(rules)
            all_imports.update(imports)

            success_count += 1
            print(f"Generated {len(rules)} rule(s)", file=sys.stderr)

    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
    finally:
        # Stop server
        if server_process and server_process.poll() is None:
            try:
                server_process.stdin.close()
            except Exception as e:
                print(f"Warning: Error closing server stdin: {e}", file=sys.stderr)
            
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("Terminating server...", file=sys.stderr)
                server_process.terminate()
                try:
                    server_process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    print("Killing server...", file=sys.stderr)
                    server_process.kill()

        print("\nClient finished", file=sys.stderr)
        print(f"Total files: {len(sample_files)}", file=sys.stderr)
        print(f"Successfully processed: {success_count}", file=sys.stderr)
        print(f"Unique rules generated: {len(all_rules)}", file=sys.stderr)

        # Write output files
        if args.output:
            base_output_path = args.output
            output_dir = os.path.dirname(base_output_path)
            output_filename_base = os.path.splitext(os.path.basename(base_output_path))[0]
            output_ext = os.path.splitext(os.path.basename(base_output_path))[1]

            sorted_rules = sorted(list(all_rules))
            num_rules = len(sorted_rules)
            
            # Split into multiple files if needed
            if args.max_rules_per_file > 0 and num_rules > args.max_rules_per_file:
                file_index = 0
                current_rules = 0
                output_file = None

                for rule_text in sorted_rules:
                    if output_file is None or current_rules >= args.max_rules_per_file:
                        if output_file:
                            output_file.close()
                            print(f"Output saved to: {output_file_path}", file=sys.stderr)

                        file_index += 1
                        output_file_path = os.path.join(output_dir, f"{output_filename_base}_part{file_index}{output_ext}")
                        output_file = open(output_file_path, 'w')
                        current_rules = 0

                        # Write imports at the top
                        for imp in sorted(list(all_imports)):
                            output_file.write(imp + "\n")
                        if all_imports:
                            output_file.write("\n")
                        
                        output_file.write(f"// Part {file_index} of {num_rules} rules\n\n")

                    output_file.write(rule_text + "\n\n")
                    current_rules += 1
                
                if output_file:
                    output_file.close()
                    print(f"Output saved to: {output_file_path}", file=sys.stderr)
                
                print(f"Split {num_rules} rules into {file_index} files", file=sys.stderr)

            else:
                # Write to single file
                with open(base_output_path, 'w') as f:
                    for imp in sorted(list(all_imports)):
                        f.write(imp + "\n")
                    if all_imports:
                        f.write("\n")
                    
                    for rule_text in sorted_rules:
                        f.write(rule_text + "\n\n")
                print(f"Output saved to: {base_output_path}", file=sys.stderr)

        else:
            print("No output file specified", file=sys.stderr)

if __name__ == "__main__":
    main()
