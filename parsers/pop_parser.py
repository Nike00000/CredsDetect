def pop_packet(packet):
    try:
        data = dict()

        pop_layer = packet.pop
        command = str(pop_layer.request_tree.command).lower()
        list_commands = ['user', 'pass']
        if command not in list_commands:
            return None, None, None, None
        data[command] = str(pop_layer.request_tree.parameter)
        return 'POP', 'ClearText', command, data
    except:
        return None, None, None, None