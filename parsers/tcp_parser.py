def tcp_parse(packet):
    try:
        tcp_dict = {'src': f"{packet.ip.src}:{packet.tcp.srcport}",
                    'dst': f"{packet.ip.dst}:{packet.tcp.dstport}",
                    'stream': packet.tcp.stream,
                    'pnum': int(packet.tcp.pnum)}
        return tcp_dict
    except:
        return None