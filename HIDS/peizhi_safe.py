import json
import re,os
#规则库为                    safe_rules.json         #配置文件“空格”分割 和  “=”分割  安全项提示。

#代码实现：  通过指定rule.json里的配置文件以及安全配置的规则
#来针对配置文件格式为 “=” 号的配置文件进行安全配置
def fix_file1(file_info,data):          #配置文件为 = 号分隔符    
    file_name = file_info[0]
    filepath = file_info[1]
    with open(filepath) as files:
        line_list =files.readlines()
    separator = data[file_name]['separator']
    commentor = data[file_name]['commentor']
    print(f"[+][+][+]————————————{filepath}安全配置方案——————————————[+][+][+]")
    print(f"需要检查的安全配置项有{len(data[file_name]['scitems'])}个!")
    print("建议修改的配置项如下：")
    print("↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓")
    report_dict=data[file_name]['scitems']
    pat = f"^(?!{data[file_name]['commentor']}).*"                    #匹配不以 ; 注释符开头的
    lisof_scitems=list(data[file_name]['scitems'].keys())            #把需要修改的项目先存到一个列表方便判断
    for line in line_list:
        if data[file_name]["separator"] in line and re.match(pat,line):     #取出来的所有值只匹配  包含等号  的,并且不以 ; 注释符开头的
            line = line.split("=")                                         #匹配出来的项放到列表里
            line[0]=line[0].strip()
            if line[0] in lisof_scitems:                   #把等号左边的匹配项取出来和我们规则库做对比，查看是否再里面，就可以省去一次循环
                line[1] = line[1].replace("\n", '').strip()   # 切割出来的列表结构里等号右边会有‘\n'，把它进行替换，
                if line[1]  != data[file_name]['scitems'][line[0]]:  # 然后进行比较，如果不是我们设置的值则进行修改
                    print(f"[{line[0]} ={line[1]}] 不安全，建议修改为： [{line[0]} =  {data[file_name]['scitems'][line[0]]}]  ")
                lisof_scitems.pop(lisof_scitems.index(line[0]))  # 把已经修改的匹配项删除，筛选出没有源文件不存在的安全选项
    if len(lisof_scitems) != 0 :
        print("[+][+]被注释或者没有匹配到的安全配置：", lisof_scitems)    # 被注释或者没有匹配到的安全配置
    for item in lisof_scitems:
        print(f"建议添加：{item} = {data[file_name]['scitems'][item]}")
    print("↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑")



#针对配置文件格式为空格符 “ ” 号的配置文件进行安全配置
def fix_file2(file_info,data):
    file_name = file_info[0]
    filepath = file_info[1]
    with open(filepath) as file:
        line_list =file.readlines()
    separator = data[file_name]['separator']
    commentor = data[file_name]['commentor']
    print(f"[+][+][+]————————————{filepath}安全配置方案——————————————[+][+][+]")
    print(f"需要检查的安全配置项有{len(data[file_name]['scitems'])}个!")
    print("建议修改的配置项如下：")
    print("↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓")
    report_dict = data[file_name]['scitems']
    pat = f"^(?!{data[file_name]['commentor']}).*"   # 匹配不以 ; 注释符开头的
    lisof_scitems = list(data[file_name]['scitems'].keys())  # 把需要修改的项目先存到一个列表方便判断
    # print(lisof_scitems)
    for line in line_list:
        line = line.strip()   #去除开头的空白符号以免误判
        if data[file_name]["separator"] in line and re.match(pat, line):  # 取出来的所有值只匹配  包含等号  的,并且不以 ; 注释符开头的
            line = line.split()  # 匹配出来的通过空格分割项放到列表里
            line[1] = " ".join(line[1:])     #应为空格分割，会把后面的带空格的配置项做分割，对后面被分割个配置进行重新赋值。如：Require all denied
            if line[0] in lisof_scitems:  # 把等号左边的匹配项取出来和我们规则库做对比，查看是否再里面，就可以省去一次循环
                line[1] = line[1].replace("\n", '').strip()  # 切割出来的列表结构里等号右边会有‘\n'，把它进行替换，
                if line[1] != data[file_name]['scitems'][line[0]]:  # 然后进行比较，如果不是我们设置的值则进行修改
                    print(f"[{line[0]}   {line[1]}] 不安全。建议修改为[{line[0]}  {data[file_name]['scitems'][line[0]]}]  ")
                lisof_scitems.pop(lisof_scitems.index(line[0]))  # 把已经修改的匹配项删除，筛选出没有源文件不存在的安全选项
    if len(lisof_scitems) != 0 :
        print("被注释或者没有匹配到的安全配置：", lisof_scitems)  # 被注释或者没有匹配到的安全配置
    for item in lisof_scitems:
        print(f"建议添加：{item}    {data[file_name]['scitems'][item]}")
    print("↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑")



#用户交互
def user_input():
    up = 0
    result = []
    file_name = input("请输入您想加固的配置文件名称[q退出]：")
    cmd = f"find / -name {file_name}"
    res = os.popen(cmd).readlines()
    if len(res) != 0 and file_name != 'q':
        print("该文件对应的文件路径为：")
        for paths in res:
            print(paths)
        file_path = input("请确认文件路径：")
    elif file_name == 'q':
        pass
    else:
        print("文件名错误或该配置文件不存在！",file_name)
        user_input()
    result.append(file_name)
    result.append(file_path)      
    res = json.load(open('./HIDS/rules_of_json/safe_rules.json'))

    #通过配置文件中的分隔符来判断是要调用上面的哪一种方法去进行配置。
    for key in res.keys():
        # print(key)
        if res[key]['separator'] == '=' and key.strip() == file_name:
            up = 1
            fix_file1(result,res)
            break
        elif res[key]['separator'] == " " and key.strip() == file_name:
            p = 1
            fix_file2(result,res)
            break 
        
    if up == 0: 
        cmd = "find / -name safe_rules.json"    
        res = os.popen(cmd).read().strip() 
        print(f"[+]该配置文件规则暂未编写！请将规则添加到{res}文件中。")



# if __name__ == '__main__':
#     #文件安全配置项目
#     user_input()




