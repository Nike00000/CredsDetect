from parsers.tcp_parser import tcp_parse

def sort_pop_creds(pop_creds):
    creds_result = []
    for pop_cred in pop_creds:

        for find_cred in creds_result:
            if find_cred['channel'] == pop_cred['channel']:
                if not pop_cred['user'] is None:
                    find_cred['user'] += pop_cred['user']
                if not pop_cred['pass'] is None:
                    find_cred['pass'] += pop_cred['pass']
                break
        else:
            new_creds = {'user': [],
                         'pass': [],
                         'channel': pop_cred['channel']}
            if not pop_cred['user'] is None:
                new_creds['user'] += pop_cred['user']
            if not pop_cred['pass'] is None:
                new_creds['pass'] += pop_cred['pass']
            creds_result.append(new_creds)
    return creds_result


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