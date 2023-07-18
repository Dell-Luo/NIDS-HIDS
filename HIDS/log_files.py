#  _log_file_chack 
# -*- coding: utf-8 -*-
# @脚本说明 :通过对suricata的实时监控，来进行防火墙Action（需要放到eve.json目录下）
import time,json,os
from sendmsg import *



#数据库爆破
#远程爆破日志查询     #放入计划任务执行。  3/5秒一次     #需要在主函数进行创建计划任务和黑名单   blacknames.txt
def SSH_log_blast():
    cmd = "cat /var/log/secure | grep Failed | awk '{print $3,$(NF-3)}' | awk -F ':' '{print $1,$2,$3}' "
    with open('./blacknames.txt','r') as fp:    #取出黑名单
        black = fp.readlines()
    res = os.popen(cmd).readlines()
    for info in res:
        info = info.strip().split()
        # print(info)
        if int(info[0]) > 5 and info[3]+'\n' not in black: #判断登录失败次数 > 5 ，再查看是否时存在黑名单里得IP，如果是的话代表已经封禁，进行忽略
            with open('./blacknames.txt','a') as fp2:
                fp2.write(info[3]+'\n')
                # print(f'{info[3]}疑似在爆破SSH,已经记录到黑名单！ blacknames.txt')           #接口   情况 ip time 处置
                now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
                msgs = f'''正在遭受ssh登录爆破！\n攻击主机IP地址:"  {info[3]}\n时间:  {now}\n威胁等级: 7\n已收录黑名单！\n处理访问    http://114.132.214.155/web/nids/detail.html'''
                WebINnfo(info[3],'ssh登录爆破',now,'7')
                send(msgs)
            break

#MYSQl爆破
def MySQL_log_blast():
    cmd = "cat /opt/lampp/logs/mysql_log | grep Connect | grep denied | awk '{print $7}' | awk -F '@' '{print $1,$2}' | uniq -c| sort -n -r"
    with open('./blacknames.txt','r') as fp:
        black = fp.readlines()
    res = os.popen(cmd).readlines()
    for inf in res:
        info = inf.replace('\'','').strip().split()
        # print(info)
        if int(info[0]) > 3 and info[2]+'\n' not in black: #判断登录失败次数 > 3 ，再查看是否时存在黑名单里得IP，如果是的话代表已经封禁，进行忽略
            with open('./blacknames.txt','a') as fp2:
                fp2.write(info[2]+'\n')
                # print(f'{info[2]}疑似在爆破MySQL,已经记录到黑名单！ blacknames.txt')           #接口   情况 ip time 处置
                now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
                msgs = f'''MySQL数据库正在被爆破！\n用户名:  {info[1]}\n攻击主机IP地址:"  {info[2]}\n时间:  {now}\n威胁等级: 7\n已收录黑名单！\n处理访问    http://114.132.214.155/web/nids/detail.html'''
                WebINnfo(info[2],'MySQL数据库正在被爆破',now,7)
                send(msgs)
            break


#进程检查  mpstat | head -4 | tail -1  取出cpu的空闲率
def cpu_chack():
    cmd = "mpstat 1 1 | head -4 | tail -1 | awk '{print $13}'" #巡检cpu的空闲率
    res = os.popen(cmd).read().strip()
    if float(res) < 60:   #  cpu空闲率低于60
        cmd = "ps -aux | awk '{print $3,$2,$11}' | sort -r | head -4 | tail -3"  #在进程的前3项中找到对应的高使用率进程
        info = os.popen(cmd).readlines()
        for sys in info:
            sys = sys.split()
            if float(sys[0]) > 40:        #并且找出可以进程        #接口   >
                # print('发送')
                now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
                msgs = f'''该进程CPU占用率过高！\nPID:  {sys[1]}\n进程名称:"  {sys[2]}\n%CPU使用率:  {sys[0]}\n时间:  {now}\n威胁等级: 5\n已收录黑名单！\n处理访问    http://114.132.214.155/web/hids/fileinfo.html'''
                FileINfo(now,f"CPU占用率过高！\nPID:  {sys[1]}\n进程名称: {sys[2]}\n%CPU使用率:  {sys[0]}",'None','5','None')
                send(msgs)



# if __name__ == '__main__':
# MySQL_log_blast()
# SSH_log_blast()
# cpu_chack()
# MySQL_log_blast()



