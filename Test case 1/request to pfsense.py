import requests
try:
	s=requests.Session()
	#s.verify ='E:/EV/PSS/cet'
	#r = requests
	url='https://192.168.1.100/api/v1/system/arp'
	headers={'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Mobile Safari/537.36'
	, 'upgrade-insecure-requests': '1'
	}
	payload ={'usernamefld':'admin','passwordfld':'pfsense'}
	r=s.get(url,headers=headers,data=payload,verify=False)
	print(r.content)
	#print(r.headers['content-type'],'/n')
	#print(r.status_code,'/n')
except Exception as e:
	print(e)
else:
	pass
finally:
	pass


