import httpbl
ip_address='93.185.65.187'

bl = httpbl.HttpBL('apikey')
response = bl.query(ip_address)

print(response)
#print('IP Address: {}').format(ip_address)
#print('Threat Score: {}').format(response['threat_score'])
#print('Days since last activity: {}').foramt(response['days_since_last_activity'])
#print('Visitor type: {}').format(', '.join([httpbl.DESCRIPTIONS[t] for t in response['type']]))