import requests
import json 

link="https://192.168.1.100/api/v1/system/arp"
headers={'Content-Type': 'application/json'}
google="https://google.com"
data='{"client-id": "admin", "client-token": "pfsense"}'
pemCert='C:/Users/Madura1/Desktop/Python/Pfsense API/pfsense1.localdomain.pem'

diognosticLink="https://192.168.1.100/api/v1/diagnostics/command_prompt"
diagnosticsData='{"shell_cmd": "echo Test command"}'
try:
	response=requests.get(link,verify=pemCert,data=data,headers=headers)
	print(response)
	print(response.content)
	#response.post(link,data=diagnosticsData)
	#print(response.url)
	#print(response.head(url=link))
	#print(response.head(url=diagnosticsData))
	#help(response)
	#print(response.get(url=link))
	#print(response.get(url=diagnosticsData))

	#print(json.dumps(response.content))
	#print(response.content)
	#help(response)
	#response.close()
	
except Exception as e:
	print(e)
else:
	pass

