import bigdatacloudapi

apiKey = 'key' 

client = bigdatacloudapi.Client(apiKey)

resultObject,httpResponseCode = client.getIpGeolocationFull({"ip":"8.8.8.8"})

print('HTTP Response Code: ',httpResponseCode)
print('Lookup IP: ',resultObject['ip'])
for items in resultObject:
	print(f'{items} \n')