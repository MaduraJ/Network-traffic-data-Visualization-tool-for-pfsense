import requests
import json


link="https://192.168.1.100/api/v1/system/arp"
headers={'Content-Type': 'application/json'}
google="https://google.com"
data='{"client-id": "admin", "client-token": "pfsense"}'
pemCert='pfsense1.localdomain.pem'
try:
	response=requests.get(link,verify=pemCert,data=data,headers=headers)
	print(response.url)
	print(response)
	#print(json.dumps(response.content))
	print(response.content)
	response.close()
	#help(response)
except Exception as e:
	print(e)
else:
	pass

