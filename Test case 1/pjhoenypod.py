import httpbl

ip_address = '103.232.201.15'

bl = httpbl.HttpBL('')
response = bl.query(ip_address)

print(response['threat_score'])
print(response['type'])
print(response['days_since_last_activity'])
print(response['name'])



		
		
		
		
		
		
		
		
