import pyshark, httpbl, json, threading, collections, gc
from json import JSONEncoder
from get_nic import getnic 
import time
import requests

class IP:
	""" """
	def __init__(self):
		self.srcIPList=set()
		self.dstIPList=set()
		#self.srcdstList=set()
		self.srcdstList = collections.deque()
		self.Mutex_lock=threading.Lock()
		self.threatList=set()
		self.checkedIPset=set()
	def SourceIPs(self,srcIP):
		self.srcIPList.add(srcIP)
		for itmes in self.srcIPList:
			if not self.srcIPList:
				continue
			if itmes in self.srcdstList:
				continue
			else:
				self.Mutex_lock.acquire()
				self.srcdstList.append(itmes)
				self.Mutex_lock.release()

		#self.srcdstList=self.srcIPList.copy()

	def DestinationIPs(self,dstIP):
		self.dstIPList.add(dstIP)
		for itmes in self.dstIPList:
			if not self.dstIPList:
				continue
			if itmes in self.srcdstList:
				continue
			else:
				self.Mutex_lock.acquire()
				self.srcdstList.append(itmes)
				self.Mutex_lock.release()
		#self.srcdstLis=self.dstIPList.copy()

	def getSourceIPs(self):
		#for x in self.srcIPList:
			#print(x)
		#print(len(self.srcIPList))
		#return self.srcIPList
		return self.srcdstList

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
		for ips in self.srcdstList: #Loop through Source and destination IPs
			try:
				if not self.srcdstList:
					continue
				if (ips in self.checkedIPset):
					print(f'{ips} has already cheked against the HttpBL')
					continue
					

				else:
					response = bl.query(ips)
					if(response['threat_score']>10):
						print(f'{ips} THREAT DETECTED WITH {0}',response['threat_score'])
						if ips in self.threatList:
							continue
						self.threatList.add(ips)
						self.sringIP=str(ips)
						self.threatList.add(ips)
						self.paraM={"client-id":"admin","client-token":"pfsense","type": "block","interface": "wan","ipprotocol":"inet","protocol":"tcp/udp","src":"","srcport":"any","dst":"","dstport": "any","descr": "Automated api rule test"}
						self.paraM['src']=ips
						self.paraM['dst']=ips
						self.data=json.dumps(self.paraM)
						response=requests.post(self.link,verify=self.pemCert,data=self.data,headers=self.headers)
						print(f'{response} \n')
						print(f'{response.content} \n')
						

					self.checkedIPset.add(ips)
					#if((len(self.srcdstList))<=2):

						#continue
					#else:
						#print("MONITORING ACTIVEcl")
						#self.srcdstList.pop()
			except Exception as e:
				print(e)
			except RuntimeError:
				print("MONITORING ACTIVE")
			else:
				pass
			finally:
				pass
			
			
			#print("threat_score {0}".format(),ips)
			#time.sleep(1)
				#try:
					#if(ips in self.threatList):
						#continue
					#else:
						#print("")
						
						#print(response.url)
						
						#print(json.dumps(response.content))
						
						#response.close()
						#help(response)
				#except Exception as e:
					#print(e)
				#finally:
					#pass
			#else:
				#print("NETWORK MONITORING ACTIVE")
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
						addSrcIPList=threading.Thread(target=ipList.SourceIPs(packets['IP'].src))
						addSrcIPList.start()
						addSrcIPList.join()
						
						addDstIPList=threading.Thread(target=ipList.DestinationIPs(packets['IP'].dst))
						addDstIPList.start()
						addDstIPList.join()
						#print(ipList.getSourceIPs())
						
						IPblacklistThread=threading.Thread(target=ipList.checkBlackListStatus)
						IPblacklistThread.start()
						IPblacklistThread.join()
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
		except RuntimeError:
				print("MONITORING ACTIVE")
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
TestThread=threading.Thread(target=test1.Capture)
gc.enable()
TestThread.start()
TestThread.join()



			


 