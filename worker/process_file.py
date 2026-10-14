import subprocess
from worker.processing_stats import FileStatus


SEP = '\x1f'
def _build_command(tshark_path, file_path, y_fields, e_fields):
    command = [
        tshark_path,
        '-n', '-N', 'n',        # без резолвинга имён
        '-l', '-q',             # line-buffered, без прогресс-бара
        '-r', file_path,
        '-Y', ' or '.join(y_fields),
        '-T', 'fields',
        '-E', f'separator={SEP}',
        '-E', 'occurrence=a',   # все вхождения поля, не только первое
        '-E', 'aggregator=|',   # как склеивать повторяющиеся поля
    ]
    for e_field in e_fields:
        command += ['-e', e_field]
    return command

def process_file(file_path, queue_process, y_fields, e_fields, tshark_path):
    """Process a pcap file and send results via queue."""
    queue_process.put((file_path, FileStatus.ACTIVE, ''))
    
    command = _build_command(tshark_path, file_path, y_fields, e_fields)
    
    process = None
    READ_SIZE = 32 * 1024

    try:
        # Start subprocess
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0
        )
        buffer = b''

        while True:
            chunk = process.stdout.read(READ_SIZE)
            if not chunk:
                break
            buffer += chunk
            last_nl = buffer.rfind(b'\n')
            if last_nl != -1:
                payload = buffer[:last_nl + 1]
                buffer = buffer[last_nl + 1:]
                if payload:
                    queue_process.put((file_path, FileStatus.DATA, payload))

        if buffer:
            queue_process.put((file_path, FileStatus.DATA, buffer))

        return_code = process.wait(timeout=300)

        if return_code != 0:
            stderr_output = process.stderr.read().decode('utf-8', errors='replace')
            error_msg = f"tshark failed (code {return_code}): {stderr_output}"
            raise ChildProcessError(error_msg)
        queue_process.put((file_path, FileStatus.DONE, ""))
    except subprocess.TimeoutExpired as e:
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
        if process is not None:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    process.stderr.close()
            except Exception as e:
                print(f"Warning: Process cleanup failed: {e}")