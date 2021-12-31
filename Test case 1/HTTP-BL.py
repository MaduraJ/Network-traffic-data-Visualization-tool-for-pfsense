import httpbl
ip_address='123.231.84.218'

bl = httpbl.HttpBL('apikey')
response = bl.query(ip_address)
#print(type(response))
#print(response.items())

print("Threat-Score: {} \nDays-since-last-activity: {}\nVisitor-Type-Number: {}".format(response['threat_score'],response['days_since_last_activity'],response['type']))
print("Visitor-Type: {} ".format(', '.join([httpbl.DESCRIPTIONS[t] for t in response['type']])))
#print('Visitor type: {}').format(', '.join([httpbl.DESCRIPTIONS[t] for t in response['type']]))