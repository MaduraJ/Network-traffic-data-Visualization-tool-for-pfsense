import requests
import json


link=""
headers={'Content-Type': 'application/json'}
google="https://google.com"
data='{"client-id": "admin", "client-token": "pfsense"}'
pemCert='pfsense1.localdomain.pem'
try:
	response=requests.get(link)
	print(response.url)
	response(type(response))
	print(response.status_code)
	#print(json.dumps(response.content))
	print(response.content)
	response.close()
	#help(response)
except Exception as e:
	print(e)
else:
	pass



