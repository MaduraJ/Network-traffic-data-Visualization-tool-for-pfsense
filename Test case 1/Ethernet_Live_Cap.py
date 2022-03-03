import pyshark
import httpbl
import json
from json import JSONEncoder
import asyncio
import time
import subprocess
import requests
from get_nic import getnic 

class IP:
	""" """
	def __init__(self):
		self.srcIPList=set()
		self.dstIPList=set()
		self.srcdstList=set()
		self.threatList=set()
	def SourceIPs(self,srcIP):
		self.srcIPList.add(srcIP)
		self.srcdstList=self.srcIPList.copy()

	def DestinationIPs(self,dstIP):
		self.dstIPList.add(dstIP)
		self.srcdstLis=self.dstIPList.copy()

	def getSourceIPs(self):
		#for x in self.srcIPList:
			#print(x)
		#print(len(self.srcIPList))
		return self.srcIPList

	def getDestinationIPs(self):
		#for x in self.dstIPList:
			#print(x)
		return self.dstIPList

	def checkBlackListStatus(self):
		#print(self.srcdstList)
		bl = httpbl.HttpBL('vwmjfxvftsrb')
		#print(self.srcdstList)
		self.link="https://192.168.1.100/api/v1/firewall/rule"
		self.headers={'Content-Type': 'application/json'}
		self.pemCert='pfsense1.localdomain.pem'
		#while(len(self.srcdstList)<100)
		for ips in self.srcdstList:
			response = bl.query(ips)
			time.sleep(.500)
			print("threat_score {0}".format(response['threat_score']),ips)
			#time.sleep(1)
			if(response['threat_score']>10):
				try:
					if(ips in self.threatList):
						continue
					else:
						print("THREAT DETECTED")
						self.sringIP=str(ips)
						self.threatList.add(ips)
						self.paraM={"client-id":"admin","client-token":"pfsense","type": "block","interface": "wan","ipprotocol":"inet","protocol":"tcp/udp","src":"","srcport":"any","dst":"","dstport": "any","descr": "Automated api rule test"}
						self.paraM['src']=ips
						self.paraM['dst']=ips
						self.data=json.dumps(self.paraM)
						response=requests.post(self.link,verify=self.pemCert,data=self.data,headers=self.headers)
						#print(response.url)
						print(response)
						#print(json.dumps(response.content))
						print(response.content)
						response.close()
						#help(response)
				except Exception as e:
					print(e)
				finally:
					pass
			else:
				print("NETWORK MONITORING ACTIVE")
				#print(response['threat_score'])
				#print(response['type'])
				#print(response['days_since_last_activity'])
				#print(response['name'])
		


		

class TrafficCapture:
	def __init__(self, sysInterface):
		self.sysInterface = sysInterface

	def __CheckNetInterfaces(self):
		avlSysInterfaces=getnic.interfaces()

		self.netInterface=self.sysInterface
		return self.netInterface

	global _stopCapture_
	_stopCapture_=True
	def __stopCapture(self):
		_stopCapture_=False

	def Capture(self):
		"""
		Capture()
		Capture is the function that is used to capture network traffic.
		Instances of TrafficCapture class need a arugment System Interface (sysInterface)
		sysInterfacee tells the program which interface to capture network traffic from. 
		Ex: on windows sysInterface should be--> Ethernet, Wi-Fi
			on linux  eth0, eth1, wlan0
		"""
		try:
			#output_file='tempNetTraffic.pcapng',
			capture = pyshark.LiveCapture(interface=self.__CheckNetInterfaces(),display_filter=None)
			#capture.set_debug()
			eth=True
			ip=True
			tcp=True
			udp=True
			tls=True
			ipList=IP()
			sourceIPset=set()
			destinationIPset=set()
			while  _stopCapture_:
				for packets in capture.sniff_continuously():
					#dir(capture.my_layer)
					if ('IP' in packets):#'IP' in capture
						#sourceIPset.add(packets['IP'].src)
						#destinationIPset.add(packets['IP'].dst)
						ipList.SourceIPs(packets['IP'].src)
						ipList.DestinationIPs(packets['IP'].dst)
						#print(ipList.getSourceIPs())
						ipList.checkBlackListStatus()
						#print(ipList.getSourceIPs(),ipList.getDestinationIPs())
					else:
						continue
					#print(packets['IP'].src,packets['IP'].dst)
					#print(packets['IP'].src,packets['IP'].dst)
					#for x in packets:
						#print(x)
					#with open("tempNetTraffic.json","w") as netTraffic:
					#json.dump(packets,netTraffic,indent=5)
					#jsonString=json.dump(packets,indent=4)
					#jsonFile.write(jsonString)


		except EOFError as e:
			print(e)
		except Exception as e:
			print(e)
		except KeyboardInterrupt:
			#type(capture)
			print("Press Ctrl-C to terminate while statement")
		else:
			pass
		finally:
			pass




test1=TrafficCapture("Ethernet")
test1.Capture()


			


 