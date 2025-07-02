from parsers.tcp_parser import tcp_parse

def pop_packet(packet):
    try:
        pop_creds = tcp_parse(packet)

        pop_layer = packet.pop
        command = str(pop_layer.request_tree.command).lower()
        list_commands = ['user', 'pass']
        if command not in list_commands:
            return None
        pop_creds['command'] = command
        pop_creds['parameter'] = str(pop_layer.request_tree.parameter)
        return pop_creds
    except:
        return None