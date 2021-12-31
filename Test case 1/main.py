import Access_token

def __init__(self):
	pass



headers={'Content-Type': 'application/json'}
data='{"client-id": "admin", "client-token": "pfsense"}'
pemCert='C:/Users/Madura1/Desktop/Python/Pfsense API/pfsense1.localdomain.pem'
link="https://192.168.1.100/api/v1/system/arp"
diognosticLink="https://192.168.1.100/api/v1/diagnostics/command_prompt"
diagnosticsData='{"shell_cmd": "echo Test command"}'

box1=Access_token.PfsenseRequest(link,headers,data,pemCert)
box1.pfsnseVerify()
