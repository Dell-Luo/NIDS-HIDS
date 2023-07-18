array_ip={}
while True:
    IP_src = input("IP_src:")
    if  IP_src not in array_ip:
        array_ip[IP_src] = 1
    else:
        array_ip[IP_src] += 1
    print(array_ip)