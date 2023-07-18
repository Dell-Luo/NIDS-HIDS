import json

data=json.load(open('regex.json'))


# print(data['regex_sql'])
# print(data['regex_xss'])
# print(data['regex_scan'])
# print(data['regex_unser'])
# print(data['regex_csrf'])
# print(data['regex_uoload'])
# print(data['regex_cmd'])
# print(data['regex_ant'])
# print(data['regex_behinder'])
# print(data['regex_godzila'])
# print(data['regex_chopper'])
# print(data['regex_web_b'])
# print(data['regex_mysql_b'])


regex_sql =data['regex_sql']
regex_xss =data['regex_xss']
regex_scan =data['regex_scan']
regex_unser =data['regex_unser']
regex_csrf =data['regex_csrf']
regex_uoload = data['regex_uoload']
regex_cmd =data['regex_cmd']
regex_ant =data['regex_ant']
regex_behinder =data['regex_behinder']
regex_godzila =data['regex_godzila']
regex_chopper =data['regex_chopper']
regex_web_b = data['regex_web_b']
regex_mysql_b = data['regex_mysql_b']

access_frequency_web = data['access_frequency_web']
access_frequency_mysql = data['access_frequency_mysql']
access_frequency_tcp = data['access_frequency_tcp']
