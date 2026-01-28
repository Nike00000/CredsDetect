import json
import subprocess

from parsers.kerberos_parser import *
from parsers.ntlm_parser import *
from parsers.pop_parser import *
from parsers.imap_parser import *
from parsers.smtp_parser import *
from parsers.http_parser import *
from parsers.ftp_parser import *
from dto.kerberos_data import AsreqKerberos, AsrepKerberos, TgsrepKerberos
from dto.net_ntlm_data import ChallengeNetNTLM, ResponseNetNTLM
from dto.user_pass_data import UserPassData
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
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, errors = process.communicate()
        if process.returncode == 0:
            text_output = output.decode('utf-8', errors='replace')
            queue_process.put((file_path, FileStatus.DONE, text_output))
    except Exception as e:
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