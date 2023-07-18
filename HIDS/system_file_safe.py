import os

#cmd
def cmd_lis(cmd):
    res = os.popen(cmd)      #获取结果按行读取
    return res

#系统安全配置排查
def system_safe():
    print("[+][+][+]———————————系统安全配置排查——————————————[+][+][+]")
    #su配置文件
    res = cmd_lis("cat /etc/pam.d/su | grep required | awk -F ' ' '{print $1,$2,$3}'").read()
    a = res.split(' ')
    if '#' in a[0]:
        print(f"[---]该安全配置项存在风险:{res.strip()}  [所有用户都可以su到root]")
        print("请修改该配置项：[vi /etc/pam.d/su]")
        print("[+]建议：修改为 auth    required    pam_wheel.so user_id\n")

    #ssh配置文件
    res = cmd_lis("cat /etc/ssh/sshd_config | grep Port | awk '{print $1,$2}'").readlines()
    for i in res:
        if "#Port 22" in  i.strip() or "Port 22" in i.strip():
            print("[---]该安全配置项存在风险:",i.strip()," [默认ssh端口22号]")
            print('请修改该配置项：[vim /etc/ssh/sshd_config]')
            print("[+]建议：修改为其他端口或者使用密钥登录！\n")

    #ssh配置禁止root远程登录
    res = cmd_lis("cat /etc/ssh/sshd_config | grep PermitRootLogin").readlines()
    for j in res:
        j=j.strip()
        if "#PermitRootLogin" in j or "PermitRootLogin yes" == j:
            print(f"[---]该安全配置项存在风险:{j} [root用户直接远程登录]")
            print('请修改该配置项：[vim /etc/ssh/sshd_config]')
            print("[+]建议：修改为 PermitRootLogin no 并且在下面添加允许远程登录的用户 Allowusers [username]\n")

    #配置密码复杂度要求
    res = cmd_lis("cat /etc/login.defs | grep ^PASS")
    for j in res:
        j=j.strip().split()
        if j[0] == "PASS_MAX_DAYS" and j[1] == '99999':
            print(f"[---]该安全配置项存在风险:{j[0]}  {j[1]}")
            print('请修改该配置项：[vim /etc/login.defs] [用户密码策略配置]')
            print("[+]建议：配置PASS_MAX_DAYS [有效时长/天]\n")
        if j[0] == "PASS_MIN_LEN" and int(j[1]) < 8:
            print(f"[---]该安全配置项存在风险:{j[0]}  {j[1]}")
            print('请修改该配置项：[vim /etc/login.defs] [用户密码策略配置]')
            print("[+]建议：配置PASS_MIN_LEN [最小密码长度]\n")
    
        
    #用户认证失败锁定配置  cat /etc/pam.d/system-auth | grep pam.tally.so
    res = cmd_lis("cat /etc/pam.d/system-auth | grep unlock_time")
    if res != "":
        print(f"[---]该安全配置项存在风险:")
        print('请修改该配置项：[vim /etc/pam.d/system-auth] [登录失败锁定策略]')
        print("[+]建议：配置登录认证失败锁定策略：")
        print(   "auth        required      pam.tally.so enerr=fail deny=[用户登录失败次数] unlock_time=[普通用户锁定时长/s] even_deny_root root_unlock_time=[root用户锁定时长/s]")


# if __name__ == '__main__':
#     system_safe()