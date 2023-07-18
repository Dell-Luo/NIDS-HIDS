import time,os ,json
import sendmsg
from regex_json import *




#暴破计时器,web        
def time_limited(time_now,IP_src,threat_level,http_data2,payload,IP_dst):

    try:
        time.sleep(1)  # 让程序等待1秒
        with open('access_count.txt', 'r') as fp:
            num = fp.read()
            # print(num)
            if int(num) >= access_frequency_web :
                print("触发web暴破预警,可疑IP地址为:")
                display(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
                sendmsg.WebINnfo(IP_src,payload,time_now,threat_level)
                msg=(f"""检测到攻击行为\n时间:{time_now}\n源IP:{IP_src}\npayload:{payload}\n threat_levet:{threat_level}\n 若需处理请查看:http://114.132.214.155/web/nids/detail.html""")
                sendmsg.send(msg)
            # fp.close()
                with open('access_count.txt', 'w') as fp:            
                    fp.write('0')   
                    fp.close() 
    except Exception as e:
        print(e) 

#暴破计时器,mysql
def time_limited_mysql(time_now,IP_src,threat_level,http_data2,payload,IP_dst):
    try:
        time.sleep(1)  # 让程序等待1秒
        with open('mysql_count.txt', 'r') as fp:
            num = fp.read()
            # print(num)
            if int(num) >= access_frequency_mysql :
                print("触发web暴破预警,可疑IP地址为:")
                display(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
                sendmsg.WebINnfo(IP_src,payload,time_now,threat_level)
                msg=(f"""检测到攻击行为\n时间:{time_now}\n源IP:{IP_src}\npayload:{payload}\n threat_levet:{threat_level}\n 若需处理请查看:http://114.132.214.155/web/nids/detail.html""")
                sendmsg.send(msg)
            # fp.close()
                with open('mysql_count.txt', 'w') as fp:            
                    fp.write('0')   
                    fp.close() 
    except Exception as e:
        print(e) 

#暴破计时器,tcp
def time_limited_tcp(time_now,IP_src,threat_level,http_data2,payload,IP_dst):
    try:
        # time.sleep(1)  # 让程序等待1秒
        with open('tcp_count.txt', 'r') as fp:
            num = fp.read()
            num = int(num)
            if int(num) >= access_frequency_tcp :
                print("触发TCP-FLOOD预警,可疑IP地址为:")
                display(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
                sendmsg.WebINnfo(IP_src,payload,time_now,threat_level)
                msg=(f"""检测到攻击行为\n时间:{time_now}\n源IP:{IP_src}\npayload:{payload}\n threat_levet:{threat_level}\n 若需处理请查看:http://114.132.214.155/web/nids/detail.html""")
                sendmsg.send(msg)
            # fp.close()
                with open('tcp_count.txt', 'w') as fp:            
                    fp.write('0')   
                    fp.close() 
    except Exception as e:
        print(e) 
        
#间歇性清空文档，一分钟清一次。用Linux的crontab更好实现。crontab -e :* * * * * echo "0" > /opt/lampp/htdocs/NIDS/access_count.txt
# def delete_file():
#     while True:
#         time.sleep(30)
#         with open("access_count.txt", "w") as fp:
#           fp.write("0")

# #在开始时间内进行计算次数的操作
# def count_add2(num,time_now,IP_src,threat_level,http_data2,payload,IP_dst):
#     # print("阶段访问次数：",num)
#     if num >= '5':
#         # print("触发暴破预警,可疑IP地址为:",IP_src)
#         display_burst(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
#         sendmsg.WebINnfo(IP_src,payload,time_now,threat_level)
#         sendmsg.send(msg)
#         # make_choice(IP_src)

 
#打印出报告信息
def display(time_now,IP_src,threat_level,http_data2,payload,IP_dst):
    print('\r')
    print("↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓")
    print("time: " + time_now)
    print("Source IP: " + IP_src)
    print("Destination IP: " + IP_dst)
    print("threat_level: " + threat_level)
    print("payload: " + payload)
    print("↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑")
    print('\r') 
    # print(http_data2)
    print('\r')
    return time_now, IP_src, payload, threat_level,IP_dst

# def display_burst(time_now,IP_src,threat_level,http_data2,payload,IP_dst):
#     return time_now, IP_src, payload, threat_level,IP_dst
    


#封禁IP,采用插入队首的方式。
def IP_block(IP_src):
    os.system(f"iptables -I INPUT -s {IP_src} -j DROP")
    print(f'现在，{IP_src}已被封禁。')

#封禁选择
def make_choice(IP_src):
    print("****press 1 to block IP****")
    print("****press 2 to ignore  ****")
    try:
        choice = input("press:")
        if choice == '1':
            IP_block(IP_src)
        else :
            pass
    except Exception as e:
        pass


#Shell工具检查
def get_shell_ant(time_now,IP_src,threat_level,http_data2,payload,IP_dst):
    payload = "AntSword(shell_tool) flow detected"
    threat_level = "9"
    print("[+] !!!!!!Your System Has Been Get-shell!!!!!!:")
    display(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
    sendmsg.WebINnfo(IP_src,payload,time_now,threat_level)
    msg=(f"""检测到攻击行为\n时间:{time_now}\n源IP:{IP_src}\npayload:{payload}\n threat_levet:{threat_level}\n 若需处理请查看:http://114.132.214.155/web/nids/detail.html""")
    sendmsg.send(msg)
    # make_choice(IP_src) 
    
def get_shell_behinder(time_now,IP_src,threat_level,http_data2,payload,IP_dst):
    payload = "Behinder(shell_tool) flow detected"
    threat_level = "9"
    print("[+] !!!!!!Your System Has Been Get-shell!!!!!!:")
    display(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
    sendmsg.WebINnfo(IP_src,payload,time_now,threat_level)
    msg=(f"""检测到攻击行为\n时间:{time_now}\n源IP:{IP_src}\npayload:{payload}\n threat_levet:{threat_level}\n 若需处理请查看:http://114.132.214.155/web/nids/detail.html""")
    sendmsg.send(msg)
    # make_choice(IP_src) 

def get_shell_Godzila(time_now,IP_src,threat_level,http_data2,payload,IP_dst):
    payload = "Godzila(shell_tool) flow detected"
    threat_level = "9"
    print("[+] !!!!!!Your System Has Been Get-shell!!!!!!:")
    display(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
    sendmsg.WebINnfo(IP_src,payload,time_now,threat_level)
    msg=(f"""检测到攻击行为\n时间:{time_now}\n源IP:{IP_src}\npayload:{payload}\n threat_levet:{threat_level}\n 若需处理请查看:http://114.132.214.155/web/nids/detail.html""")
    sendmsg.send(msg)    
    # make_choice(IP_src) 
    
def get_shell_chopper(time_now,IP_src,threat_level,http_data2,payload,IP_dst):
    payload = "ChineseCaiDao(shell_tool) flow detected"
    threat_level = "9"
    print("[+] !!!!!!Your System Has Been Get-shell!!!!!!:")
    display(time_now,IP_src,threat_level,http_data2,payload,IP_dst)
    sendmsg.WebINnfo(IP_src,payload,time_now,threat_level)
    msg=(f"""检测到攻击行为\n时间:{time_now}\n源IP:{IP_src}\npayload:{payload}\n threat_levet:{threat_level}\n 若需处理请查看:http://114.132.214.155/web/nids/detail.html""")
    sendmsg.send(msg)    
    # make_choice(IP_src) 
    
