
import pyshark

from parsers.kerberos_parser import *
from parsers.ntlm_parser import *
from parsers.pop_parser import *
from parsers.imap_parser import *
from parsers.smtp_parser import *
from parsers.http_parse import *
from parsers.ftp_parser import *
from worker.results_manager import *

def process_chunk(packets, fileId):
    chunk_results = dict_results()
    for packet in packets:
        if 'kerberos' in packet:
            try:
                kerberos_layer = packet.kerberos
                if 'as_req_element' in kerberos_layer.field_names:
                    as_req = asreq_packet(kerberos_layer)
                    if not as_req is None:
                        chunk_results['asreq'].append(as_req)
                    continue
                if 'as_rep_element' in kerberos_layer.field_names:
                    as_rep = asrep_packet(kerberos_layer)
                    if not as_rep is None:
                        chunk_results['asrep'].append(as_rep)
                    continue
                if 'tgs_rep_element' in kerberos_layer.field_names:
                    tgs_rep = tgsrep_packet(kerberos_layer)
                    if not tgs_rep is None:
                        chunk_results['tgsrep'].append(tgs_rep)
                    continue
            except:
                pass
            continue
        if 'pop' in packet:
            try:
                pop_cred = pop_packet(packet)
                tcpId = f"{fileId}_{pop_cred['stream']}"

                if tcpId in chunk_results['pop3']:
                    chunk_results['pop3'][tcpId].append(pop_cred)
                else:
                    chunk_results['pop3'][tcpId] = [pop_cred]
            except:
                pass
            continue
        if 'imap' in packet:
            try:
                creds = imap_packet(packet)
                if not creds is None:
                    chunk_results['imap'].append(creds)
            except:
                pass
            continue
        if 'smtp' in packet:
            try:
                creds = smtp_packet(packet)
                if not creds is None:
                    tcpId = f"{fileId}_{creds['stream']}"

                    if tcpId in chunk_results['smtp']:
                        chunk_results['smtp'][tcpId].append(creds)
                    else:
                        chunk_results['smtp'][tcpId] = [creds]
            except:
                pass
            continue
        if 'ftp' in packet:
            ftp_creds = ftp_parse(packet)
            if not ftp_creds is None:
                tcpId = f"{fileId}_{ftp_creds['stream']}"
                if tcpId in chunk_results['ftp']:
                    chunk_results['ftp'][tcpId].append(ftp_creds)
                else:
                    chunk_results['ftp'][tcpId] = [ftp_creds]
            continue
        if 'http' in packet:
            try:
                http_basic = http_auth_basic(packet)
                if not http_basic is None:
                    chunk_results['http_authbasic'].append(http_basic)
            except:
                pass
        try:
            ntlm_cred = ntlm_parse(packet)
            tcpId = f"{fileId}_{ntlm_cred['stream']}"
            if tcpId in chunk_results['netntlmv2']:
                chunk_results['netntlmv2'][tcpId].append(ntlm_cred)
            else:
                chunk_results['netntlmv2'][tcpId] = [ntlm_cred]
            continue
        except:
            pass

    return chunk_results



def process_file(file_path, queue_process, filter_protocols, tshark_path):
    packets = []
    packet_chunk_size = 1000

    try:
        if tshark_path is None:
            capture = pyshark.FileCapture(file_path, display_filter=filter_protocols, use_json=True)
        else:
            capture = pyshark.FileCapture(file_path, display_filter=filter_protocols, use_json=True, tshark_path=tshark_path)
        for packet in capture:
            packets.append(packet)
            if len(packets) >= packet_chunk_size:
                chunk_results = process_chunk(packets, file_path)
                queue_process.put((file_path, chunk_results))
                packets = []
        capture.close()
    except Exception as inst:
        print(f"Error in file: {file_path}.\n")    # the exception type
        print(inst)
    finally:
        if packets:
            chunk_results = process_chunk(packets, file_path)
            queue_process.put((file_path, chunk_results))
        queue_process.put((file_path, "Done"))
    return