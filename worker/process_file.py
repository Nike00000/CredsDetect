import json
from datetime import datetime

import subprocess

from parsers.kerberos_parser import *
from parsers.ntlm_parser import *
from parsers.pop_parser import *
from parsers.imap_parser import *
from parsers.smtp_parser import *
from parsers.http_parser import *
from parsers.ftp_parser import *

unknown = 'unknown'
functions_list = [kerberos_packet,
                  ntlm_tcp_payload_parse,
                  http_authorization,
                  http_proxy_authorization,
                  http_proxy_authenticate,
                  pop_packet,
                  imap_packet,
                  smtp_packet,
                  ftp_parse]

def process_chunk(packets, filename):
    chunk_results = []
    for packet in packets:
        try:
            if 'layers' not in packet:
                continue
            parse_packet = dict()
            if 'timestamp' in packet:
                parse_packet['timestamp'] = int(packet['timestamp'])
            layers = packet['layers']
            if 'frame' in layers:
                parse_packet['time'] = datetime.fromisoformat(layers['frame']['frame_frame_time_utc'])
                parse_packet['number'] = layers['frame']['frame_frame_number']
            else:
                continue
            if 'eth' in layers:
                parse_packet['src_mac'] = layers['eth'].get('eth_eth_src', unknown)
                parse_packet['dst_mac'] = layers['eth'].get('eth_eth_dst', unknown)
            if 'ip' in layers:
                parse_packet['src_ip'] = layers['ip'].get('ip_ip_src', unknown)
                parse_packet['dst_ip'] = layers['ip'].get('ip_ip_dst', unknown)
                #Session
                session_id1 = min(parse_packet['src_ip'], parse_packet['dst_ip'])
                session_id2 = max(parse_packet['src_ip'], parse_packet['dst_ip'])
                parse_packet['session_id'] = '-'.join([session_id1, session_id2])
            else:
                continue
            if 'tcp' in layers:
                parse_packet['src_port'] = layers['tcp'].get('tcp_tcp_srcport', unknown)
                parse_packet['dst_port'] = layers['tcp'].get('tcp_tcp_dstport', unknown)
            if 'udp' in layers:
                parse_packet['src_port'] = layers['udp'].get('udp_udp_srcport', unknown)
                parse_packet['dst_port'] = layers['udp'].get('udp_udp_dstport', unknown)

            for func_parse in functions_list:
                protocol, auth, data_type, data = func_parse(layers)
                if not data_type is None and not data is None:
                    parse_packet['protocol'] = protocol
                    parse_packet['auth'] = auth
                    parse_packet['type'] = data_type
                    parse_packet['data'] = data
                    chunk_results.append(parse_packet)
                    break
        except Exception as e:
            continue
    return chunk_results

def process_file(file_path, queue_process, filter_protocols, tshark_path):
    queue_process.put((file_path, 'Started', ''))
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
            for line in text_output.splitlines():
                try:
                    packet = json.loads(line)
                    packets.append(packet)
                except Exception as e:
                    continue
            results = process_chunk(packets, file_path)
            queue_process.put((file_path, 'Done', results))
        else:
            process.terminate()
    except Exception as e:
        raise e
    finally:
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            except Exception as e:
                raise
        queue_process.put((file_path, "Done", ''))