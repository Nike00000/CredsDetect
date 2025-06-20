def extract_http_auth_basic(http_results: list, unique):
    results = []
    for http_one in http_results:
        src_ip = http_one['src'].split(':')[0]
        dst_ip = http_one['dst'].split(':')[0]
        results.append([src_ip, dst_ip, http_one['user'], http_one['pass'], http_one['uri']])
    if unique:
        unique_results = []
        for one in results:
            has = False
            for unique_one in unique_results:
                if one[2] == unique_one[2] and one[3] == unique_one[3]:
                    if one[1] == unique_one[1]:
                        has = True
            if not has:
                unique_results.append(one)
        return unique_results
    return results