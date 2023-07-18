import os
import requests
import json
import time
from sendmsg import *

# 对可以文件上传到微步进行分析。并且获取情报
#  https://x.threatbook.com/v5/myApi  #微步接口文档
#  https://s.threatbook.com/report/file/{sha256}"/  #查看web版本报告信息
#  提交可疑文件
def send_to_wb(dirs,name):
    url = 'https://api.threatbook.cn/v3/file/upload'
    fields = {
        'apikey': 'dc16217274fd436ba70bb55200e76d92f21bb736f34f42bbb2e43b2737f7df2f',
        'sandbox_type': 'centos_7_x64',
        'run_time': 60
    }
    file_dir = dirs
    file_name = name
    files = {
    'file' : (file_name, open(os.path.join(file_dir, file_name), 'rb'))
    }
    response = requests.post(url, data=fields, files=files)
    data = response.json()
    return data


def get_info(SHA256):
    url = 'https://api.threatbook.cn/v3/file/report'
    params = {
        'apikey': 'dc16217274fd436ba70bb55200e76d92f21bb736f34f42bbb2e43b2737f7df2f',
        'sandbox_type': 'centos_7_x64',
        'sha256': SHA256
    }
    response = requests.get(url, params=params)
    data = response.json()
    return data


def results(fil_path,fil_name):
    data_dict = send_to_wb(fil_path,fil_name)
    print(data_dict['data']['sha256'])
    time.sleep(180)
    get_infos=get_info(data_dict['data']['sha256'])   #获取文件的密钥，然后查看检测的数据情报
    print(fil_name,'检测完毕！')
    #接口
    if get_infos['data']['summary']['threat_level'] != "clean":
        #威胁等级分为malicious（恶意）、suspicious（可疑）、clean（安全)
        threat_le=get_infos['data']['summary']['threat_level']
        ##病毒类型定位     ['Backdoor', 'Chopper']
        bingdu_type= get_infos['data']['summary']['tag']['x']
        ##反病毒扫描引擎检出率
        enging = get_infos['data']['summary']['multi_engines']
        now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        msg=f'''时间：{now}\n文件名称{fil_name}\n文件路径：{fil_path}{"/",fil_name}\n威胁等级：{get_infos['data']['summary']['threat_level']}\n威胁等级: 10\n病毒类型：{get_infos['data']['summary']['tag']['x']}\n反病毒扫描引擎检出率：{get_infos['data']['summary']['multi_engines']}\n处理访问    http://114.132.214.155/web/hids/fileinfo.html '''
        send(msg)
        fil_path = fil_path+'/'+fil_name
        info = f'\n威胁等级：{threat_le}\n病毒类型：{bingdu_type[0]}——{bingdu_type[1]}\n反病毒扫描引擎检出率：{enging}\n'
        FileINfo(now,info,'None','10',fil_path)


        
