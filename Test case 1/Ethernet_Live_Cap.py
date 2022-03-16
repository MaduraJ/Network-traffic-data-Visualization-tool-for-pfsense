import pyshark, httpbl, json, threading #threading non-functional 
import collections, gc
from json import JSONEncoder
from get_nic import getnic 
import time
import requests
import bigdatacloudapi


class IP:
	""" """
	def __init__(self):
		self.srcIPList=set()
		self.dstIPList=set()
		#self.srcdstList=set()
		self.checkedIPset=set()
		self.srcdstList = collections.deque()

		self.Mutex_lock=threading.Lock()
		self.threatList=set()
		self.dequeLenth=None

		self.monitoringOnly=False
		self.networkMonitoringEnable=None
		self.TorExitBlockEnable=None
		self.httpBlHeaders=None
		self.isFirewallUP=False
		self.httpBLKey='vwmjfxvftsrb'
		self.pemCert='pfsense1.localdomain.pem'
		self.maximumAllowedThreatScore=10
		self.headers={'Content-Type': 'application/json'}
		
		
		self.hostName="192.168.1.100"
		self.client_ID='admin'
		self.clien_Token='pfsense'
		self.rule_Type='block'
		self.rule_Interface='wan'


		self.unableToReachMSG='Unable to Reach Firewall Check if the Network, Firewall is UP and Running'
		self.continueTimeOutMSG='Connection Timeout: Check if the Network, Firewall is UP and Running'
		self.tooManyRedirectsMSG='Too Many Redirects: Bad URL'
		self.requestLibraryErrorMSG='Request Library Error'
		self.firewallWorkingMsg=f'(OK): {self.hostName} is UP and Running'
		self.okResponseMSG200="is UP network monitoring has started"
		self.badRequestMSG400="(Bad Request) : An error was found within your requested parameters"
		self.unauthorizedMSG401="(Unauthorized) : API client has not completed authentication or authorization successfully "


	def HostStatusCheck(self):
		statusCheckURL=f"https://{self.hostName}/api/v1/firewall/states"
		statesAuth={"client-id": "", "client-token": ""}
		statesAuth["client-id"]=self.client_ID
		statesAuth["client-token"]=self.clien_Token
		self.statusAuthdata=json.dumps(statesAuth)
		try:
			firewallStatus=requests.get(statusCheckURL,verify=self.pemCert,data=self.statusAuthdata)
			if (firewallStatus.status_code==200):
				self.isFirewallUP=True
				print(f'(OK) :{self.hostName} {self.okResponseMSG200}')
				#return self.isFirewallUP
			elif(firewallStatus.status_code==400):
				self.isFirewallUP=False
				print(f'{self.hostName} {self.badRequestMSG400}')
				return self.isFirewallUP
			elif(firewallStatus.status_code==401):
				self.isFirewallUP=False
				print(f'{self.hostName} {self.unauthorizedMSG401}')
				return self.isFirewallUP
			elif(firewallStatus.status_code==403):
				self.isFirewallUP=False
				print(f'{self.hostName}  (Forbidden) : The API endpoint has refused your call. Commonly due to your access settings found in System > API ')
				return self.isFirewallUP
			elif(firewallStatus.status_code==404):
				self.isFirewallUP=False
				print(f'{self.hostName} (Not found) : Either the API endpoint or requested data was not found ')
				return self.isFirewallUP
			elif(firewallStatus.status_code==500):
				self.isFirewallUP=False
				print(f'{self.hostName} (Server error) : The API endpoint encountered an unexpected error processing your API request ')
				return self.isFirewallUP
			else:
				self.isFirewallUP=False
				print(f'{self.hostName} (ERROR) : Contact admin ')
				return self.isFirewallUP

		except requests.exceptions.RequestException as e:
			print(f"{self.unableToReachMSG}")
		except requests.exceptions.Timeout as e:
			print(f"{self.continueTimeOutMSG}")
		except requests.exceptions.TooManyRedirects:
			print(f"{self.tooManyRedirectsMSG}")
		except requests.exceptions.RequestException as e:
			print(f"{self.requestLibraryErrorMSG}")
		except Exception as e:
			raise
		else:
			pass
		finally:
			pass
		


	def SourceIPs(self,srcIP):
		self.srcIPList.add(srcIP)
		for itmes in self.srcIPList:
			if (itmes==" " or ""):
				continue
			if not self.srcIPList: #check empty status
				continue
			if itmes in self.srcdstList:
				continue
			else:
				self.Mutex_lock.acquire()
				self.srcdstList.append(" ".join(itmes.split()))
				self.Mutex_lock.release()

		#self.srcdstList=self.srcIPList.copy()

	def DestinationIPs(self,dstIP):
		self.dstIPList.add(dstIP)
		for itmes in self.dstIPList:
			if (itmes==" "or""):#check empty status
				continue
			if not self.dstIPList:
				continue
			if itmes in self.srcdstList:
				continue
			else:
				self.Mutex_lock.acquire()
				self.srcdstList.append(" ".join(itmes.split()))
				self.Mutex_lock.release()
		#self.srcdstLis=self.dstIPList.copy()

	def getSourceIPs(self):
		#for x in self.srcdstList:
			#print(x)
		#print(len(self.srcIPList))
		return self.srcdstList
		#return self.dstIPList

	def getDestinationIPs(self):
		#for x in self.dstIPList:
			#print(x)
		return self.dstIPList

	def getSrcDstQueueLen(self):
		self.dequeLenth=len(self.srcdstList)
		return self.dequeLenth

	def checkBlackListStatus(self):
		#print(self.srcdstList)
		bl = httpbl.HttpBL(self.httpBLKey)
		#print(self.srcdstList)
		self.ruleCreationlink=f"https://{self.hostName}/api/v1/firewall/rule"
		#while(len(self.srcdstList)<100)
		#Loop through Source and destination IPs
		for ips in self.srcdstList: 
			try:
				if (self.getSrcDstQueueLen()<=0):
					continue
				if (ips==None):
					print(f"{ips} None IP DETECTED")
					continue
				if(ips==""):
					print(f"{ips} No space quotes DETECTED")
					continue
				if(ips==" "):
					print(f"{ips} quotes with space DETECTED")
					continue
				if not self.srcdstList:
					continue
				if (ips in self.checkedIPset):
					#print(f'{ips} has already cheked against the HttpBL')
					continue
				if (ips == '162.159.200.1'):
					continue
				else:
					print(f"{ips} this is else print")
					response = bl.query(ips)
					if(response['threat_score']>self.maximumAllowedThreatScore):
						print(f'{ips} THREAT DETECTED WITH {0}',response['threat_score'])
						if ips in self.threatList:
							continue
						self.threatList.add(ips)
						#self.sringIP=str(ips)
						#self.threatList.add(ips)

						#need to create way to modify the rule

						self.paraM={"client-id":"","client-token":"pfsense","type": "","interface": "","ipprotocol":"inet","protocol":"tcp/udp","src":"","srcport":"any","dst":"","dstport": "any","descr": "Automated api rule test"}
						
						self.paraM['client-id']=self.client_ID
						self.paraM['client-token']=self.clien_Token
						self.paraM['type']=self.rule_Type
						self.paraM['dst']=ips
						self.paraM['src']=ips
						self.paraM['interface']=self.rule_Interface
						self.data=json.dumps(self.paraM)
						

						try:
							response=requests.post(self.ruleCreationlink,verify=self.pemCert,data=self.data,headers=self.headers)
							#if(response.status_code==200):
							print(f'API Call Succeeded Firewall Rule Has Been Created')
							print(f'{response} \n')
							print(f'{response.content} \n')
							#if(response.status_code==500):
								#print(f'{response.status_code} (Server error) : The API endpoint encountered an unexpected error processing your API request')
						except IndexError:
							print(self.srcdstList[-1:-5])
							exit()
						except requests.exceptions.RequestException as e:
							print(f"{self.unableToReachMSG}")
							continue
						except requests.exceptions.Timeout as e:
							print(f"{self.continueTimeOutMSG}")
							continue
						except requests.exceptions.TooManyRedirects:
							print(f"{self.tooManyRedirectsMSG}")
							continue
						except requests.exceptions.RequestException as e:
							print(f"{self.requestLibraryErrorMSG}")
							continue
						except Exception as e:
							raise
						else:
							pass
						finally:
							pass
					self.checkedIPset.add(ips)
					#if((len(self.srcdstList))<=2):

						#continue
					#else:
						#print("MONITORING ACTIVEcl")
						#self.srcdstList.pop()
			except Exception as e:
				raise
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
			
			
			
			#dir(capture.my_layer)#'IP' in capture
			while  _stopCapture_:
				print(f'Checking Host:{ipList.hostName} status')
				firewallStatusCheck=threading.Timer(10,ipList.HostStatusCheck)
				firewallStatusCheck.start()
				firewallStatusCheck.join()
				if(ipList.isFirewallUP):
					print(f'{ipList.hostName} {ipList.okResponseMSG200}')
				else:
					continue
				for packets in capture.sniff_continuously():
					if ('IP' in packets):
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
						#ipList.getDestinationIPs()
						
						#print(ipList.getSourceIPs())
						#print(ipList.getSourceIPs(),ipList.getDestinationIPs())
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



			


 