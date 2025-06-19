def dict_results():
    dict_pattern = {
        'asreq':[],
        'asrep': [],
        'tgsrep': [],
        'pop3': {},
        'netntlmv2': {},
        'imap': [],
        'smtp': {}
    }
    return dict_pattern



def merge_dict_results(results, chunk):
    # Добавление в общий словарь
    for key in chunk.keys():
        if isinstance(chunk[key], dict):
            merge_dict_results(results[key], chunk[key])
        if isinstance(chunk[key], list):
            if not  key in results:
                results[key] = list()
            results[key] += chunk[key]
    pass