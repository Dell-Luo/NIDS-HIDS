import pymysql,json,time,hmac,hashlib,base64,urllib.parse,requests




def send(msg):
    headers = {'Content-Type': 'application/json', "Charset": "UTF-8"}
    prefix = 'https://oapi.dingtalk.com/robot/send?access_token=b60feb7e9d75c865644f73c56c2299bc5ed583ec80a8cf1b604db767d2e936a7'# 这里替换为复制的完整 webhook 地址,从飞书群里生成机器人的时候复制
    timestamp = str(round(time.time() * 1000))#生成时间戳
# 这里替换为自己复制过来的加签秘钥
    secret = 'SEC2483647edd8910f64aacfd3f131f11cd860cdb9a38c28794a39f474aad58961d'
    secret_enc = secret.encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()#加密
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    url = f'{prefix}&timestamp={timestamp}&sign={sign}'
# 钉钉消息格式，其中 msg 就是我们要发送的具体内容
    data = {
        "at": {
            "isAtAll": False
        },
        "text": {
            "content": msg
        },
        "msgtype": "text"
    }

    return requests.post(url=url, data=json.dumps(data), headers=headers).text






"""(ip,payload,time,level):"""

def WebINnfo(ip,payload,time,level):
    consql=pymysql.connect(host='114.132.214.155',user='root',password='Luoyi08030627',port=3467,database='opt')
    cursor=consql.cursor()
    sql=f"""INSERT INTO webinfo (`ip`,`payload`,`time`,`level`,`ar`) VALUE("{ip}","{payload}",'{time}','{level}','no');"""
    try:
        cursor.execute(sql)
        consql.commit() #DQL需要作提交
        cursor.close()
        consql.close()
    except:
        print(sql)
         



"""(time,stat,ip,level,path)"""

def FileINfo(time,stat,ip,level,path):
    consql=pymysql.connect(host='114.132.214.155',user='root',password='Luoyi08030627',port=3467,database='opt')
    cursor=consql.cursor()
    sql=f"INSERT INTO fileinfo (`time`,`stat`,`ip`,`level`,`path`,`ar`) VALUE('{time}','{stat}','{ip}','{level}','{path}','no');"
    # print(sql)
    cursor.execute(sql)
    consql.commit() #DQL需要作提交
    cursor.close()
    consql.close()



