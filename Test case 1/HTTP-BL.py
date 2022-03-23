import httpbl
import json
ip_address='134.119.216.167'
#100.200.159.162

bl = httpbl.HttpBL('')
response = bl.query(ip_address)
print(response)
print(type(response))
jsonString=json.dumps(response,indent=1)
print(type(jsonString),"\n",response)
#print(response.items())

#print("Threat-Score: {} \nDays-since-last-activity: {}\nVisitor-Type-Number: {}".format(response['threat_score'],response['days_since_last_activity'],response['type']))
#print("Visitor-Type: {} ".format(', '.join([httpbl.DESCRIPTIONS[t] for t in response['type']])))
#print('Visitor type: {}').format(', '.join([httpbl.DESCRIPTIONS[t] for t in response['type']]))