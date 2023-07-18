# -*- coding: utf-8 -*-
#针对一些原有的配置用户，内容进行配置
import os

#cmd
def cmd_lis(cmd):
    res = os.popen(cmd).readlines()      #获取结果按行读取
    return res


#可登录账户,以及空密码检测
def shadow_weak_pass():
    print("[+][+][+]————————————账户安全排查——————————————[+][+][+]")
    res  =  cmd_lis('cat /etc/shadow')      ##查看shadow文件    
    res2 =  cmd_lis("cat /etc/passwd | grep /bin/bash | awk -F : '{print $1}'")      #查看可以登录的用户
    print("可登录系统的账户列表：")
    for i in res2:
        print(i.strip())
    print()
    for r in res:
        ls = r.split(':')
        if (ls[1]=="!!" and ls[0]+"\n" in res2) or (ls[1]==''):
            print(f'[---]用户 {ls[0]} 的密码是空密码!建议及时修改！' )
            print("")


#高权限用户检测
def group_chack():
    print("[+][+][+]————————————高权限用户检测——————————————[+][+][+]")      
    ls = cmd_lis("awk -F : '$3==0{print $1}' /etc/passwd") #查看UID=0的用户（高权限用户）
    su_root_users= cmd_lis("cat /etc/passwd | grep /bin/bash | awk -F : '{print $1}' && groupmems -g wheel -l")  #能够登录的用户和可以su到root的用户
    res = ls + su_root_users
    new = []
    for i in res:
        ta = i.strip()
        if ta not in new:
            new.append(ta)
    if len(new) > 0:
        print("[---]存在除root外的高权限账户：")
        print("[+]建议：命令提示:[gpasswd -d [user] [group]] 将user移出用户组")
        for j in new:
            if j != "root":
                print(j)
                os.system(f"id {j}")
    

#弱密码检查
# shadow_weak_pass()
#高权限用户排查
# group_chack()







