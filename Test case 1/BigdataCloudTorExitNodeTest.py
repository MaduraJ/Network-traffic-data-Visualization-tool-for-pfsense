import requests
import json
import datetime
apiKey = '0fb0868823be4b3c9f4a7632d1a3eb0f'
batchSize="10"
offset="0"
sort="ip"
order="asc"
localityLanguage="en"
link=f"https://api.bigdatacloud.net/data/tor-exit-nodes-list?batchSize={batchSize}&offset={offset}&sort={sort}&order={order}&localityLanguage={localityLanguage}&key={apiKey}"
headers={'Content-Type': 'application/json'}
#payload='{"batchSize":"100","offset":"0","sort":"ip","order":"asc","localityLanguage":"en","key":""}'


def getTorExitNodes():
	try:
		response=requests.get(link,headers=headers)
		print(response.content)
		dictResponse=json.loads(response.content)
		jsonString=json.dumps(dictResponse,indent=3)
		print(jsonString)
		cDateTime=datetime.datetime.now()
		print(type(dictResponse))
		print(dictResponse["nodes"][9])
		print(dictResponse["nodes"][0]["ip"],type(dictResponse['nodes'][0]))
		print(dictResponse["total"])
		print(dictResponse['nodes'][9]['carriers'][0]['rank'],type(dictResponse['nodes'][0]['carriers'][0]))
		strCData=str(cDateTime)
		fStrCdata=strCData.replace(":",".")
		#out_file=open(f"{fStrCdata}.json","w")
		#json.dump(dictResponse,out_file,indent=3)
		#out_file.close()
	except Exception as e:
		raise
	else:
		pass
	finally:
		pass

if __name__ == '__main__':
	getTorExitNodes()