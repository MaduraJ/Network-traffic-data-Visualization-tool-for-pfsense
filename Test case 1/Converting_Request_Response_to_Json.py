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
try:
	response=requests.post(link,verify=pemCert,data=data3,headers=headers)

	#print(type(data2))
	#print(data2)
	#print(data3)
	#print(response.url)
	#print(response)
	ConvertedToPytohnDictionary=json.loads(response.content)
	ConvertedToPytohnDictionary['code']=404
	#print(dataobj)
	#print(type(dataobj))
	ConvertedToJsonString=json.dumps(ConvertedToPytohnDictionary,indent=4)
	print(ConvertedToJsonString)
	print(type(ConvertedToJsonString))
except Exception as e:
	print(e)
else:
	pass
