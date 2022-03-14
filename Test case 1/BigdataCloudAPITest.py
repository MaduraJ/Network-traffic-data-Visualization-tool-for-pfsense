import bigdatacloudapi

apiKey = '0fb0868823be4b3c9f4a7632d1a3eb0f' 

client = bigdatacloudapi.Client(apiKey)

resultObject,httpResponseCode = client.getIpGeolocationFull({"ip":"8.8.8.8"})

print('HTTP Response Code: ',httpResponseCode)
print('Lookup IP: ',resultObject['ip'])
print('Security Threat Status: ',resultObject['securityThreat'])
print('Locality Language Requested: ',resultObject['localityLanguageRequested'])
print('Is Reachable Globally: ',resultObject['isReachableGlobally'])
print('Country: ',resultObject['country'])
print("Location: ",resultObject['location'])
print("LastUpdated: ",resultObject['lastUpdated'])
print("Network: ",resultObject['network'])
print("Confidence: ",resultObject['confidence'])
print("Confidence Area: ",resultObject['confidenceArea'])
print("Hazard Report: ",resultObject['hazardReport'])
for items in resultObject:
	print(f'{items}')