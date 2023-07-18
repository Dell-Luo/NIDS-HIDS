import pyinotify
import os
import requests
import threading,time,json
from sendmsg import *
from send_wb import *
# from send_wb import *
# 实现在线监控文件和目录的变化。
#  https://x.threatbook.com/v5/myApi  #微步接口文档


wm = pyinotify.WatchManager()

class MyEventHandler(pyinotify.ProcessEvent):
    #检测敏感文件
    def process_IN_ACCESS(self,event):           #只可以检测本地系统里的
        print(event.name)
        if event.path == "/etc/passwd":
            print(f"{event.path}敏感文件被访问。 ")
        if event.path == "/etc/shadow":
            print(f"{event.path}敏感文件被访问。 ")
            
    def process_IN_CREATE(self,event):
        print("该文件目录下有新文件生成！请及时查看")
        print("路径",event.path)
        print("文件名称",event.name)
        
    #用来检测文件上传
    def process_IN_MOVED_TO(self,event):       
        print("检测到文件上传！",event.name)
        print("路径",event.path)
        print("文件名称",event.name)
        threading.Thread(target=results,args=(event.path,event.name),name=str(event.name)).start()

 

def ontime_file():
    path = json.load(open("./rules_of_json/files.json"))#这个位置主函数      #获取需要配置的目录  
    handler = MyEventHandler()
    notifier = pyinotify.Notifier(wm,handler)
    mask = pyinotify.IN_ACCESS | pyinotify.IN_CREATE | pyinotify.IN_MOVED_TO 
    for files,path in path['filepath'].items():
        p = path      #去除所有配置好的文件路径
        wm.add_watch(p,mask)
        print("对",path,"进行实时监控！")
    notifier.loop()
ontime_file()


    