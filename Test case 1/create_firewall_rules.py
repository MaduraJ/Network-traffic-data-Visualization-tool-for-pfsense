import requests
import json


link="https://192.168.1.100/api/v1/firewall/rule"
headers={'Content-Type': 'application/json'}
stringIP="242.65.25.14"
#data='{"client-id":"admin","client-token":"pfsense","type": "block","interface": "wan","ipprotocol":"inet","protocol":"tcp/udp","src":"172.16.209.138","srcport":"any","dst": "172.16.209.138","dstport": 443,"descr": "This is a test rule added via API"}'
data2={"client-id":"admin","client-token":"pfsense","type": "block","interface": "wan","ipprotocol":"inet","protocol":"tcp/udp","src":"","srcport":"any","dst":"","dstport": "any","descr": "Automated api rule test"}
data2['src']=stringIP
data2['dst']=stringIP
data3=json.dumps(data2)
pemCert='pfsense1.localdomain.pem'
chkStatus= "https://192.168.1.100/api/v1/firewall/states"
auth='{"client-id":"admin","client-token":"pfsense"}'
try:
	#response=requests.post(link,verify=pemCert,data=data3,headers=headers)
	response=requests.get(chkStatus,verify=pemCert,data=auth)
	print(response.content)
	responseDict=json.loads(response.content)
	print(f"{responseDict} \n\n\n")
	jsonStr=json.dumps(responseDict,indent=3)
	print(jsonStr)
	#print(type(data2))
	#print(data2)
	#print(data3)
	#print(response.url)
	#print(response)
	#dataobj=json.loads(response.content)
	#dataobj['code']=404
	#print(dataobj)
	#print()
	#print(type(dataobj))
except Exception as e:
	print(e)
else:
	pass
