import subprocess

from parsers.kerberos_parser import *
from parsers.ntlm_parser import *
from parsers.pop_parser import *
from parsers.imap_parser import *
from parsers.smtp_parser import *
from parsers.http_parser import *
from parsers.ftp_parser import *
from worker.processing_stats import FileStatus

def process_file(file_path, queue_process, filter_protocols, tshark_path):
    queue_process.put((file_path, FileStatus.ACTIVE, ''))
    command = [
        tshark_path,
        '-r', file_path,
        '-Y', filter_protocols,
        '-T', 'ek'
    ]
    process = None
    packets = []
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Wait up to 300 seconds (5 minutes) with timeout
        try:
            output, errors = process.communicate(timeout=300)  # 5 minutes timeout
        except subprocess.TimeoutExpired:
            # Kill the process if it times out
            process.kill()
            process.wait()  # Wait for process to terminate
            raise TimeoutError(f"Processing {file_path} timed out after 5 minutes")
        if process.returncode == 0:
            text_output = output.decode('utf-8', errors='replace')
            queue_process.put((file_path, FileStatus.DONE, text_output))
        else:
            raise ChildProcessError(f"errors: {errors}, output thark: {output}")
    except Exception as e:
        queue_process.put((file_path, FileStatus.ERROR, e))
        raise e
    finally:
        try:
            if process is not None:
                process.wait(timeout=5)
                if process.poll() is not None:
                    process.stdout.close()
                    process.stderr.close()
                    process.terminate()
                process.kill()
        except Exception as e:
            raise