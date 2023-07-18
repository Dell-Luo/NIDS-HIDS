# -*- coding: utf-8 -*-
# @Time : 2023/3/24 22:07
# @Author : Freeman
# @Email : 925322821@qq.com
# @File : scapy_web_detect.py
# @Project : PycharmProjects
# @脚本说明 :

# 该脚本会监听网络流量，当检测到TCP数据包中包含HTTP请求数据，并且该数据包的目的端口为80时，会检查HTTP请求数据是否包含SQL注入语句。如果检测到SQL注入，则打印相关信息。
# 该脚本使用正则表达式进行SQL注入语句的匹配，可以根据需要进行修改和优化。同时，该脚本只是一个简单的示例，实际使用中还需要考虑其他方面的安全问题。
# 联系TEST3 文档内容进行开发。
from detective_func import *
from scapy.all import *
from regex_json import *
import re, datetime,time
import urllib.parse
import sendmsg

def check_network_injection(packet):
    time_now = str(datetime.datetime.now())
    threat_level = ""
    IP_src = ""
    payload = ""
    # array_ip={}              #存储访问次数的元祖

    # 检查是否为HTTP请求
    '''
    Scapy库中的haslayer方法是用来判断数据包是否包含指定的协议层的。
    它的用法是在Scapy的数据包对象上,调用haslayer方法,并传入想要判断的协议层的类型，
    如果该数据包包含这一层,那么返回True,否则返回False。
    '''
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].dport == 80 :
        # 获取HTTP请求数据
        http_data = str(packet[Raw].load)
        # print(http_data)
        http_data1 = urllib.parse.unquote(http_data)  # 防止URL编码绕过
        http_data2 = http_data1.lower()  # 防止大小写绕过
        IP_src = packet[IP].src  #提取源IP
        IP_dst = packet[IP].dst  #提取目的 IP



        # 检查是否为SQL注入等基于字段检测就能发现的攻击
        result=re.search(rf"{regex_sql}", http_data2)
        if result:
          try:  
            match = re.search(r"match=(.*)>", str(result))
            payload = match.group(1)
            threat_level = '7'
            print("[+] !!!!!!Possible SQL intrution detected!!!!!!:")
            time_now, IP_src, payload, threat_level,IP_dst=display(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
            # print(f'测试：传递值成功,时间:{time_now},源IP:{IP_src},目的IP:{IP_dst},payload:{payload},threat_levet:{threat_level}')
            sendmsg.WebINnfo(IP_src,payload,time_now,threat_level)
            msg=(f"""检测到攻击行为\n时间:{time_now}\n源IP:{IP_src}\npayload:{payload}\nthreat_levet:{threat_level}\n若需处理请查看:http://114.132.214.155/web/nids/detail.html""")
            sendmsg.send(msg)
            # make_choice(IP_src)
          except Exception as e:
            pass
            
        # 检查是否为xss注入等基于字段检测就能发现的攻击
        result_xss = re.search(rf"{regex_xss}", http_data2)
        if result_xss:
          try:
            print(result_xss)
            match = re.search(r"match=(.*)>", str(result_xss))
            payload = match.group(1)
            threat_level = '7'
            print("[+] !!!!!!Possible XSS intrution detected!!!!!!:")
            display(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
            sendmsg.WebINnfo(IP_src,payload,time_now,threat_level)
            msg=(f"""检测到攻击行为\n时间:{time_now}\n源IP:{IP_src}\npayload:{payload}\nthreat_levet:{threat_level}\n若需处理请查看:http://114.132.214.155/web/nids/detail.html""")
            sendmsg.send(msg)
            # make_choice(IP_src)
          except Exception as e:
            pass
            

        # 检查是否被恶意扫描.PS:!doctype.+!entity检查XXE实体注入，../检查目录穿越.
        result_scanner = re.search(rf"{regex_scan}", http_data2)
        if result_scanner: 
          try:
            # print(result)
            match = re.search(r"match=(.*)>", str(result_scanner))
            payload = match.group(1)
            threat_level = '6'
            print("[+] !!!!!!suspected to be maliciously scanned!!!!!!:")
            display(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
            sendmsg.WebINnfo(IP_src,payload,time_now,threat_level)
            msg=(f"""检测到攻击行为\n时间:{time_now}\n源IP:{IP_src}\npayload:{payload}\nthreat_levet:{threat_level}\n若需处理请查看:http://114.132.214.155/web/nids/detail.html""")
            sendmsg.send(msg)
            # make_choice(IP_src)
          except Exception as e:
            pass
            

        # 检查是否为反序列化攻击   
        if re.search(rf"{regex_unser}", http_data2):
          try:
            # result = re.search(r".*%22S%22%3A1.*|.*%3A%7Bs%3A1.*|.*\"S\":.*|.*:\{s.*|content-length:.+(o:.*\";\})'", http_data2)
            # print(result)
            match = re.search(r"content-length:.+(o:.*\";\})'", http_data2)   
            # match = re.search(r"match='(.*)'", str(result))
            payload = match.group(1)
            threat_level = '8'
            print("[+] !!!!!!Possible unserialize intrution detected!!!!!!:")
            display(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
            sendmsg.WebINnfo(IP_src,payload,time_now,threat_level)
            msg=(f"""检测到攻击行为\n时间:{time_now}\n源IP:{IP_src}\npayload:{payload}\nthreat_levet:{threat_level}\n若需处理请查看:http://114.132.214.155/web/nids/detail.html""")
            sendmsg.send(msg)
            # make_choice(IP_src)
          except Exception as e:
            pass         


        # 检查是否为CSRF等需要进行校验才能发现的攻击,目前该规则在正常访问时容易报错。
        match = re.search(rf"{regex_unser}", http_data)
        if match:
          try:
            # match2 = re.search(r"Referer: http://(\d+\.\d+\.\d+\.\d+/\S+)\\r\\nCookie", http_data)
            threat_level = '7'
            local_ip = match.group(1)
            payload = "CSRF link chain"
            if local_ip != '114.132.214.155':
                print('[+] !!!!!!A CSRF link has been clicked already!!!!!!:')
                display(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
                sendmsg.WebINnfo(IP_src,payload,time_now,threat_level)
                msg=(f"""检测到攻击行为\n时间:{time_now}\n源IP:{IP_src}\npayload:{payload}\nthreat_levet:{threat_level}\n若需处理请查看:http://114.132.214.155/web/nids/detail.html""")
                sendmsg.send(msg)
                # make_choice(IP_src)
          except Exception as e:
            pass                
                

        # 检查上传文件的内容是否存在危险：
        if 'multipart/form-data' in http_data:
          try:
            match = re.search(r"filename=\"(.+\.\S+)\"", http_data)
            filename = match.group(1)
            if re.search(rf"{regex_uoload}", http_data2):
                threat_level = "9"
                payload = filename
                print('[+] !!!!!!The uploaded file was considered to a invasion !!!!!!:')
                display(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
                sendmsg.WebINnfo(IP_src,payload,time_now,threat_level)
                msg=(f"""检测到攻击行为\n时间:{time_now}\n源IP:{IP_src}\npayload:{payload}\nthreat_levet:{threat_level}\n若需处理请查看:http://114.132.214.155/web/nids/detail.html""")
                sendmsg.send(msg)
                # make_choice(IP_src)
          except Exception as e:
            pass                
            

        #蚁剑检测
        if re.search(rf"{regex_ant}",http_data):
            get_shell_ant(time_now,IP_src,threat_level,http_data2,payload,IP_dst) 
        #冰蝎检测
        if re.search(rf"{regex_behinder}",http_data):
            get_shell_behinder(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
        #哥斯拉检测
        if re.search(rf"{regex_godzila}", http_data):
            get_shell_Godzila(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
        #菜刀检测
        if re.search(rf"{regex_chopper}",http_data):
            get_shell_chopper(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
            
            
        # 检查是否存在基于Linux系统的命令注入
        result_cmd = re.search(rf"{regex_cmd}", http_data2)
        if result_cmd:
          try:
            print(result_cmd)
            match = re.search(r"match=(.*)>", str(result_cmd))
            payload = match.group(1)
            threat_level = '8'
            print("[+] !!!!!!Possible command intrution detected!!!!!!:")
            display(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
            sendmsg.WebINnfo(IP_src,payload,time_now,threat_level)
            msg=(f"""检测到攻击行为\n时间:{time_now}\n源IP:{IP_src}\npayload:{payload}\nthreat_levet:{threat_level}\n若需处理请查看:http://114.132.214.155/web/nids/detail.html""")
            sendmsg.send(msg)
            # make_choice(IP_src)
          except Exception as e:
            pass
          
        #检测web爆破攻击  username=.*password=.* 两种方法
        if re.search(rf"{regex_web_b}",http_data2):
            payload = "Web Brute force alert!"
            threat_level="6"
            with open('access_count.txt', 'r') as fp:
                num = fp.read()
                num = int(num)
                num += 1  
            with open('access_count.txt', 'w') as fp:            
                fp.write(str(num))   
                fp.close()            
            time_limited(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
        
        # if re.search(r"username=.*password=.*",http_data2):
        #   try:  
        #     print('a')
        #     payload = "Brute force alert!"
        #     threat_level="3"
        #     if  IP_src not in array_ip:
        #         array_ip[IP_src] = 1
        #     else:
        #         array_ip[IP_src] += 1
                
        #         if array_ip[IP_src] >= 5:    
        #             display(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
        #     print(array_ip)
        #   except Exception as e:
        #     print(e)   
          
    if  packet[TCP].dport == 3467 and packet.haslayer(Raw) and packet[IP].src == '114.132.214.155' and packet[IP].src == '127.0.0.1':
    # 获取mysql协议数据
        # print(1)
        content = str(packet[Raw].load)
        # print(payload)
    # 判断是否是密码验证数据包
        if f'n{regex_mysql_b}' in content:
            IP_src = packet[IP].src  #提取源IP
            IP_dst = packet[IP].dst  #提取目的 IP
        # 记录源IP地址和密码
            payload = "Mysql Brute force alert!"
            threat_level="6"
            http_data2=content
            with open('mysql_count.txt', 'r') as fp:
                num = fp.read()
                num = int(num)
                num += 1  
            with open('mysql_count.txt', 'w') as fp:            
                fp.write(str(num))   
                fp.close()            
            time_limited_mysql(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
      
    if  packet.haslayer(TCP) and packet[IP].src == '114.132.214.155' and packet[IP].src == '127.0.0.1' :
    # 判断是TCP协议
        IP_src = packet[IP].src  #提取源IP
        IP_dst = packet[IP].dst  #提取目的 IP
    # 记录源IP地址和密码
        payload = "TCP flood!"
        threat_level="6"
        http_data2=""
        with open('tcp_count.txt', 'r') as fp:
            num = fp.read()
            num = int(num)
            num += 1  
        with open('tcp_count.txt', 'w') as fp:            
            fp.write(str(num))   
            fp.close()            
        time_limited_tcp(time_now,IP_src,threat_level,http_data2,payload,IP_dst) 
        

def main():
    sniff(filter="tcp", prn=check_network_injection)


if __name__ == '__main__':
        main()









