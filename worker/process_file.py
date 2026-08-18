import subprocess
from worker.processing_stats import FileStatus

def process_file(file_path, queue_process, filter_protocols, tshark_path):
    """Process a pcap file and send results via queue."""
    queue_process.put((file_path, FileStatus.ACTIVE, ''))
    
    command = [
        tshark_path,
        '-r', file_path,
        '-Y', filter_protocols,
        '-T', 'ek'
    ]
    
    process = None
    output_lines = []
    BATCH_SIZE = 100
    
    try:
        # Start subprocess
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',
            bufsize=1
        )

        try:
            # Read stdout line by line (non-blocking with bufsize=1)
            for line in process.stdout:
                line = line.strip()
                if line:
                    output_lines.append(line)
                
                # Send batch when threshold reached
                if len(output_lines) > BATCH_SIZE:
                    queue_process.put((file_path, FileStatus.DATA, output_lines))
                    output_lines = []
                    
        except Exception as e:
            # Handle any errors during reading
            raise RuntimeError(f"Error reading stdout: {e}") from e

        # Wait for process to complete with timeout
        return_code = process.wait(timeout=300)  # 5 minutes

        # Check if process failed
        if return_code != 0:
            stderr_output = process.stderr.read()
            error_msg = f"tshark failed (code {return_code}): {stderr_output}"
            raise ChildProcessError(error_msg)

        # Send any remaining data
        if output_lines:
            queue_process.put((file_path, FileStatus.DATA, output_lines))
            output_lines = []

        # Signal successful completion
        queue_process.put((file_path, FileStatus.DONE, ""))

    except subprocess.TimeoutExpired as e:
        # Handle timeout
        error_msg = f"Processing {file_path} timed out after 300 seconds"
        queue_process.put((file_path, FileStatus.ERROR, error_msg))
        if process and process.poll() is None:
            process.kill()
            process.wait()
        raise TimeoutError(error_msg) from e
        
    except Exception as e:
        error_msg = f"Unexpected error processing {file_path}: {str(e)}"
        queue_process.put((file_path, FileStatus.ERROR, error_msg))
    finally:
        # Clean up process resources
        if process is not None:
            try:
                if process.poll() is None:  # Still running
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                # Close pipes
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    process.stderr.close()
            except Exception as e:
                print(f"Warning: Process cleanup failed: {e}")