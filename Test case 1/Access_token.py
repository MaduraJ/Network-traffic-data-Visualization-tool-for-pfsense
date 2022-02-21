import requests
import json
import ast


class PfsenseRequest(object):
	"""docstring for ClassName"""
	def __init__(self,Link,Headers,Data,pemCert):
		self.link=Link
		self.headers=Headers
		self.data=Data
		self.pemCert=pemCert

	def pfsnseVerify(self):
		try:
			response=requests.get(self.link,verify=self.pemCert,data=self.data,headers=self.headers)
			
			str_res=response._content.decode("UTF-8")
			dict_str_res=ast.literal_eval(str_res)
			print(dict.keys(dict_str_res))
			print("Status: {0}\nCode: {1}\nReturn: {2}\nMessage: {3}\n".format(dict_str_res['status'],str(dict_str_res['code']),str(dict_str_res['return']),dict_str_res['message']))
			for data in dict_str_res['data']:
				print(data)
			#=str(response._content)
			#print("Status: {}".format(_stringResponse_['status']))
			#response.post(link,data=diagnosticsData)
			#print(response.url)
			#print(response.head(url=link))
			#print(response.head(url=diagnosticsData))
			#print(response.get(url=link))
			#help(response)
			#print(response.get(url=diagnosticsData))
			#print(json.dumps(response.content))
			#print(response.content)
			#help(response)
			#response.close()
		except Exception as e:
			print(e)
		else:
			pass




