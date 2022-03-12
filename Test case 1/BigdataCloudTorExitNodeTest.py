import requests
apiKey = 'apiKey'
batchSize="100"
offset="0"
sort="ip"
order="asc"
localityLanguage="en"
link=f"https://api.bigdatacloud.net/data/tor-exit-nodes-list?batchSize={batchSize}&offset={offset}&sort=+{sort}&localityLanguage={localityLanguage}&key={apiKey}"
headers={'Content-Type': 'application/json'}
#payload='{"batchSize":"100","offset":"0","sort":"ip","order":"asc","localityLanguage":"en","key":""}'


def getTorExitNodes():
	try:
		response=requests.get(link,headers=headers)
		print(response.url)
		print(response.content)
	except Exception as e:
		raise
	else:
		pass
	finally:
		pass

if __name__ == '__main__':
	getTorExitNodes()