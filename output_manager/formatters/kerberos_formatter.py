def get_kerberos_data_str(packet:dict):
    if 'asreq' in packet['type']:
        func = asreq_format
    elif 'asrep' in packet['type']:
        func = asrep_format
    elif 'tgsrep' in packet['type']:
        func = tgsrep_format
    else:
        return 'unknown', 'unknown'
    return func(packet['data'])

def sort_kerberos_type(packets:list, unique, machine, hash_type):
    results = list()
    hash_id_list = list()
    packets_by_time = sorted(packets, key=lambda x: x['time'], reverse=True)
    for packet in packets_by_time:
        if not machine and '$' in packet['data']['cname']:
            continue
        if not packet['type'] == hash_type:
            continue
        hash_id, hash_data = get_kerberos_data_str(packet)
        if unique:
            if hash_id in hash_id_list:
                continue
            hash_id_list.append(hash_id)
        results.append(packet)

    return results

def asreq_format(data:dict):
    #$krb5pa$23$user$realm$salt$4e751db65422b2117f7eac7b721932dc8aa0d9966785ecd958f971f622bf5c42dc0c70b532363138363631363132333238383835
    #$krb5pa$17$hashcat$HASHCATDOMAIN.COM$a17776abe5383236c58582f515843e029ecbff43706d177651b7b6cdb2713b17597ddb35b1c9c470c281589fd1d51cca125414d19e40e333
    #$krb5pa$18$hashcat$HASHCATDOMAIN.COM$96c289009b05181bfd32062962740b1b1ce5f74eb12e0266cde74e81094661addab08c0c1a178882c91a0ed89ae4e0e68d2820b9cce69770
    cname_lower = str(data['cname']).lower().split('@')[0]
    realm_upper = str(data['realm']).upper()
    if data['etype'] == 23:
        hash_data = f"$krb5pa${data['etype']}${cname_lower}${data['realm']}${data['cipher'][:24]}${data['cipher'][24:]}"
    else:
        hash_data = f"$krb5pa${data['etype']}${cname_lower}${realm_upper}${data['cipher']}"
    hash_id = f"$krb5pa${data['etype']}${cname_lower}${realm_upper.split('.')[0]}"
    return hash_id.lower(), hash_data

def asrep_format(data:dict):
    #$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac
    #$krb5asrep$17$user$EXAMPLE.COM$a419c4030e555734b06c2629$c09a1421f96eb126c757a4b87830381f142477d9a85b2beb3093dbfd44f38ddb6016a479537fb7b36e046315869fe79187217971ff6a12c1e0a2df3f68045e03814b21f756d8981f781803d65e8572823c88979581d93cf7d768f2efced16f3719b8d1004d9e73d798de255383476bced47d1982f16be77d0feb55a1f44f58bd013fa4caee58ac614caf0f1cf9101ec9623c5b8c2a1491b73f134f074790088fdb360b5ebce0d32a8145ed00a81ddf77188e150b92d8e8ddd0285d27f1514253e5546e6bba864b362bb1e6483b26d08fa4cc268bfbefe0f690039bcc524b774599df3680c1c3431d891bfa99514a877f964e
    #$krb5asrep$18$user$EXAMPLE.COM$aa4c494f520b27873a4de8f7$ebc9976a77f62e8ccca02d43d68bafcc66a81fcbb44a336b00ce401982f32975a5f9bcdc752643252185866685b0a30aaf50e449e392a5994e6979f23aba25f7704c90b2efa03b703c3c2f9e3617cc588ed226d0417e7742d45407878fd946d046b4a9732b9a203cb857811714b009c195b7c96b9bccb7e48832b11a4e92ecf24c49e54de8d0d5d5351445b5126db90bb7eebc7861db1e61de1175824b0a45023a6fa06c2a9d3035fdcf863bea922648e3dc28b48e39b1dec0869e7fe4de399cb52dfcf2596599da54a4bb0169c72d9496de2e137a4594e0e8a69082fc558ac9ace65d32eae5e260a65ca3f2f5871aaeee7a3b090b50f39321d120c144421e0abe7d
    cname_lower = str(data['cname']).lower()
    realm_upper = str(data['realm']).upper()
    if data['etype'] == 23:
        hash_data = f"$krb5asrep${data['etype']}${cname_lower}@{realm_upper}:{data['cipher']}"
    else:
        hash_data = f"$krb5asrep${data['etype']}${cname_lower}${realm_upper}${data['cipher'][-24:]}${data['cipher'][:-24]}"
    hash_id = f"$krb5asrep${data['etype']}${cname_lower}@{realm_upper.split('.')[0]}"
    return hash_id.lower(), hash_data

def tgsrep_format(data:dict):
    #$krb5tgs$23$*user$realm$test/spn*$63386d22d359fe42230300d56852c9eb$891ad31d09ab89c6b3b8c5e5de6c06a7f49fd559d7a9a3c32576c8fedf705376cea582ab5938f7fc8bc741acf05c5990741b36ef4311fe3562a41b70a4ec6ecba849905f2385bb3799d92499909658c7287c49160276bca0006c350b0db4fd387adc27c01e9e9ad0c20ed53a7e6356dee2452e35eca2a6a1d1432796fc5c19d068978df74d3d0baf35c77de12456bf1144b6a750d11f55805f5a16ece2975246e2d026dce997fba34ac8757312e9e4e6272de35e20d52fb668c5ed
    #$krb5tgs$17$user$realm$ae8434177efd09be5bc2eff8$90b4ce5b266821adc26c64f71958a475cf9348fce65096190be04f8430c4e0d554c86dd7ad29c275f9e8f15d2dab4565a3d6e21e449dc2f88e52ea0402c7170ba74f4af037c5d7f8db6d53018a564ab590fc23aa1134788bcc4a55f69ec13c0a083291a96b41bffb978f5a160b7edc828382d11aacd89b5a1bfa710b0e591b190bff9062eace4d26187777db358e70efd26df9c9312dbeef20b1ee0d823d4e71b8f1d00d91ea017459c27c32dc20e451ea6278be63cdd512ce656357c942b95438228e
    #$krb5tgs$18$user$realm$8efd91bb01cc69dd07e46009$7352410d6aafd72c64972a66058b02aa1c28ac580ba41137d5a170467f06f17faf5dfb3f95ecf4fad74821fdc7e63a3195573f45f962f86942cb24255e544ad8d05178d560f683a3f59ce94e82c8e724a3af0160be549b472dd83e6b80733ad349973885e9082617294c6cbbea92349671883eaf068d7f5dcfc0405d97fda27435082b82b24f3be27f06c19354bf32066933312c770424eb6143674756243c1bde78ee3294792dcc49008a1b54f32ec5d5695f899946d42a67ce2fb1c227cb1d2004c0
    hash_id = f"$krb5tgs${data['etype']}$*{data['sname']}${data['realm'].split('.')[0]}"
    realm_upper = str(data['realm']).upper()
    if data['etype'] == 23:
        hash_data = f"$krb5tgs${data['etype']}$*some_domain_user${realm_upper}${data['sname']}*${data['cipher'][:32]}${data['cipher'][32:]}"
    else:
        hash_data = f"$krb5tgs${data['etype']}${data['sname']}${realm_upper}${data['cipher'][-24:]}${data['cipher'][:-24]}"
    return hash_id.lower(), hash_data
