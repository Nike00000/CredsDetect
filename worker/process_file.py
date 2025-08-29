import pyshark

from parsers.kerberos_parser import *
from parsers.ntlm_parser import *
from parsers.pop_parser import *
from parsers.imap_parser import *
from parsers.smtp_parser import *
from parsers.http_parser import *
from parsers.ftp_parser import *

def process_chunk(packets, filename):
    chunk_results = []

    functions_list = [kerberos_packet,
                      ntlm_tcp_payload_parse,
                      http_authorization,
                      http_proxy_authorization,
                      http_proxy_authenticate,
                      pop_packet,
                      imap_packet,
                      smtp_packet,
                      ftp_parse]
    for packet in packets:
        try:
            parse_packet = dict()
            parse_packet['filename'] = filename
            parse_packet['src_mac'] = packet.eth.src
            parse_packet['dst_mac'] = packet.eth.dst

            parse_packet['src_ip'] = packet.ip.src
            parse_packet['dst_ip'] = packet.ip.dst
            session_id1 = min(parse_packet['src_ip'], parse_packet['dst_ip'])
            session_id2 = max(parse_packet['src_ip'], parse_packet['dst_ip'])
            parse_packet['session_id'] = '-'.join([session_id1, session_id2])
            parse_packet['time'] = packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S.%f")
            parse_packet['number'] = packet.number
            if 'tcp' in packet:
                parse_packet['src_port'] = packet.tcp.srcport
                parse_packet['dst_port'] = packet.tcp.dstport
            if 'udp' in packet:
                parse_packet['src_port'] = packet.udp.srcport
                parse_packet['dst_port'] = packet.udp.dstport
            for func_parse in functions_list:
                protocol, auth, data_type, data = func_parse(packet)
                if not data_type is None and not data is None:
                    parse_packet['protocol'] = protocol
                    parse_packet['auth'] = auth
                    parse_packet['type'] = data_type
                    parse_packet['data'] = data
                    chunk_results.append(parse_packet)
                    break
        except:
            continue
    return chunk_results



def process_file(file_path, queue_process, filter_protocols, tshark_path):
    queue_process.put((file_path, 'Started'))
    chunk_packets = []
    packet_chunk_size = 1000

    capture_args = {
        'input_file': file_path,
        'display_filter': filter_protocols,
        'use_json': True
    }
    if tshark_path is not None:
        capture_args['tshark_path'] = tshark_path
    capture = None
    try:
        capture = pyshark.FileCapture(**capture_args)
        for packet in capture:
            chunk_packets.append(packet)
            if len(chunk_packets) >= packet_chunk_size:
                chunk_results = process_chunk(chunk_packets, file_path)
                queue_process.put((file_path, chunk_results))
                chunk_packets = []
    except Exception as e:
        raise
    finally:
        if capture is not None:
            capture.close()
        if chunk_packets:
            chunk_results = process_chunk(chunk_packets, file_path)
            queue_process.put((file_path, chunk_results))
        queue_process.put((file_path, "Done"))
    return