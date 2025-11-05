def pop_packet(packet):
    try:
        data = dict()
        command = packet['pop']['pop_pop_request_command'].lower()
        list_commands = ['user', 'pass']
        if command not in list_commands:
            return None, None, None, None
        data[command] = packet['pop']['pop_pop_request_parameter']
        return 'POP', 'ClearText', command, data
    except:
        return None, None, None, None