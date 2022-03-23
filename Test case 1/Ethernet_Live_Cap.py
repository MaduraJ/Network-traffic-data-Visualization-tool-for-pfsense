import pyshark, httpbl, json, threading #threading non-functional 
import collections, gc ,re
from json import JSONEncoder
from get_nic import getnic 
import time
import requests
import bigdatacloudapi
import datetime ,smtplib



global __enableCapture__
__enableCapture__=True
global __StartLogging__
__StartLogging__=False


		
class Firewall:
	""" """
	def __init__(self):
		self.srcIPList=set()
		self.dstIPList=set()
		#self.srcdstList=set()
		self.checkedIPset=set()
		self.srcdstList = collections.deque()
		self.blockedIPs={}

		self.Mutex_lock=threading.Lock()
		
		self.threatList=set()
		self.twoTimeRepeat=set()
		self.threeTimeRepeat=set()
		self.firstUblockTimer=None
		self.secondUnblockTimer=None

		self.ruleTrackerId=set()
		self.ruleCreationResponseToDict=[]
		self.fwRcRConvertedToPytohnDictionary=None#Firewall Rule Creation Response content in dictionary format
		self.firewallRuleCrInResponseJsonSringFormat=None
		self.logHttpblResponse=None
		self.httpblResponse=None
		self.strHttpblResponse=None
		self.firewallRuleCreationResponse=None
		self.httpBLKey=''
		self.pemCert='pfsense1.localdomain.pem'
		self.maximumAllowedThreatScore=10
		self.headers={'Content-Type': 'application/json'}
		
		self.senderEmailAddress="pfsenseauomatedmail@gmail.com"
		self.senderEmailPwd=""
		self.receiverMail=""

		self.dequeLenth=None
		self.skipIPlist=['162.159.200.1',"162.159.200.123"]

		self.hostName="192.168.1.100"
		self.monitoringOnly=False
		self.networkMonitoringEnable=None
		self.TorExitBlockEnable=None
		self.httpBlHeaders=None
		self.isFirewallUP=False
		
		
		self.client_ID='admin'
		self.clien_Token='pfsense'
		self.rule_Type='block'
		self.rule_Interface='wan'


		self.unableToReachMSG='\n\nUnable to Reach Firewall Check if the Network, Firewall is UP and Running\n\n'
		self.continueTimeOutMSG='\n\nConnection Timeout: Check if the Network, Firewall is UP and Running\n\n'
		self.tooManyRedirectsMSG='\n\nToo Many Redirects: Bad URL\n\n'
		self.requestLibraryErrorMSG='\n\nRequest Library Error\n\n'
		self.firewallWorkingMsg=f'\n\n(OK): {self.hostName} is UP and Running\n\n'
		self.okResponseMSG200="is UP network monitoring has started"
		self.firewallRuleCreatedMSG="\n\nAPI Call (OK): Succeeded Firewall Rule Has Been Created\n\n"
		self.badRequestMSG400="\n\n(Bad Request) : An error was found within your requested parameters\n\n"
		self.unauthorizedMSG401="\n\n(Unauthorized) : API client has not completed authentication or authorization successfully\n\n"
		self.forbiddenMSG403="(Forbidden) : The API endpoint has refused your call. Commonly due to your access settings found in System > API"
		self.notFoundMSG404="(Not found) : Either the API endpoint or requested data was not found"
		self.serverErrorMSG500="(Server error) : The API endpoint encountered an unexpected error processing your API request"
		self.generalErrorMSG="(ERROR) : Contact admin"
		self.tlsErrorMSG="(TLS Error) : Could not find a suitable TLS CA certificate bundle"

	def HostStatusCheck(self):
		statusCheckURL=f"https://{self.hostName}/api/v1/firewall/states"
		statesAuth={"client-id": "", "client-token": ""}
		statesAuth["client-id"]=self.client_ID
		statesAuth["client-token"]=self.clien_Token
		self.statusAuthdata=json.dumps(statesAuth)
		try:
			firewallStatus=requests.get(statusCheckURL,verify=self.pemCert,data=self.statusAuthdata)
			firewallStatusDict=json.loads(firewallStatus.content)
			StatusCodeCheck=threading.Thread(target=self.FirewallStatusCheckMsg,args=(firewallStatusDict['code'],))
			StatusCodeCheck.start()
			StatusCodeCheck.join()
			print(firewallStatusDict['code'])
			firewallStatus=None
		except TimeoutError:
			self.isFirewallUP=False
			print(f"\n\n{self.unableToReachMSG}\n\n")
		except requests.exceptions.RequestException as e:
			self.isFirewallUP=False
			print(f"\n\n{self.unableToReachMSG}\n\n")
		except requests.exceptions.Timeout as e:
			self.isFirewallUP=False
			print(f"\n\n{self.continueTimeOutMSG}\n\n")
		except requests.exceptions.TooManyRedirects:
			self.isFirewallUP=False
			print(f"\n\n{self.tooManyRedirectsMSG}\n\n")
		except requests.exceptions.RequestException as e:
			self.isFirewallUP=False
			print(f"\n\n{self.requestLibraryErrorMSG}\n\n")
		except Exception as e:
			self.isFirewallUP=False
			raise
		except OSError:
			print(f"{self.tlsErrorMSG}")
		else:
			pass
		finally:
			pass

	def FirewallStatusCheckMsg(self,StatusCode):
		self.firewallStatus=StatusCode
		if (self.firewallStatus==200):
			self.isFirewallUP=True
			print(f'(OK) :{self.hostName} {self.okResponseMSG200}')
		elif(self.firewallStatus==400):
			self.isFirewallUP=False
			print(f'{self.hostName} {self.badRequestMSG400}')
		elif(self.firewallStatus==401):
			self.isFirewallUP=False
			print(f'{self.hostName} {self.unauthorizedMSG401}')
		elif(self.firewallStatus==403):
			self.isFirewallUP=False
			print(f'{self.hostName} {self.forbiddenMSG403}')
		elif(self.firewallStatus==404):
			self.isFirewallUP=False
			print(f'{self.hostName} {self.notFoundMSG404}')
		elif(self.firewallStatus==500):
			self.isFirewallUP=False
			print(f'{self.hostName} {self.serverErrorMSG500}')
		else:
			self.isFirewallUP=False
			print(f'Unreachable : {self.hostName} | Status check fail {self.generalErrorMSG}')

	def FirewallRuleCreationMsg(self,StatusCode,response_content):
		RuleCreationStatusCode=StatusCode
		try:
			if (RuleCreationStatusCode==200):
				print(f'{self.hostName} (OK) : {self.firewallRuleCreatedMSG}\n\n\n{self.firewallRuleCrInResponseJsonSringFormat}\n\n\n')
			elif(self.RuleCreationStatusCode==400):
				print(f'{self.hostName} {self.badRequestMSG400}\n{self.firewallRuleCrInResponseJsonSringFormat}')
			elif(self.RuleCreationStatusCode==401):
				print(f'{self.hostName} {self.unauthorizedMSG401}\n{self.firewallRuleCrInResponseJsonSringFormat}')
			elif(self.RuleCreationStatusCode==403):
				print(f'{self.hostName} {self.forbiddenMSG403}\n{self.firewallRuleCrInResponseJsonSringFormat}')
			elif(self.RuleCreationStatusCode==404):
				print(f'{self.hostName} {self.notFoundMSG404}\n{self.firewallRuleCrInResponseJsonSringFormat}')
			elif(self.RuleCreationStatusCode==500):
				print(f'{self.hostName} {self.serverErrorMSG500}\n{self.firewallRuleCrInResponseJsonSringFormat}')
			else:
				print(f'Unreachable : {self.hostName} | Firewall Rule Creation Fail {self.generalErrorMSG}\n{self.firewallRuleCrInResponseJsonSringFormat}')
		except Exception as e:
			raise
		else:
			pass
		finally:
			pass

	def sendEmailNotification(self):
		try:
			if self.senderEmailAddress==None or self.senderEmailPwd==None or self.receiverMail==None:
				print(f'Please proveide details to send notification')
			if (self.isFirewallUP==False):
				smtpSession = smtplib.SMTP('smtp.gmail.com', 587)
				smtpSession.starttls()
				smtpSession.login(self.senderEmailAddress,self.senderEmailPwd)
				report=f"Subject:Unable to Reach Firewall\nThreat detected but Unable to create firewall rule\n Firewall Rule details \n{self.firewallRuleCrInResponseJsonSringFormat}\n Threat details \n{self.strHttpblResponse}"
				smtpSession.sendmail(self.senderEmailAddress,self.receiverMail,report)
				smtpSession.quit()
				print("\n\nEmail Notification sent successfully!\n\n\n") 
			else:
				 smtpSession = smtplib.SMTP('smtp.gmail.com', 587)
				 smtpSession.starttls()
				 smtpSession.login(self.senderEmailAddress,self.senderEmailPwd)
				 report=f"Subject:Auomated Firewall Rule\nFirewall Rule details \n{self.firewallRuleCrInResponseJsonSringFormat}\n Threat details \n{self.strHttpblResponse}"
				 smtpSession.sendmail(self.senderEmailAddress,self.receiverMail,report)
				 smtpSession.quit()
				 print("\n\nEmail Notification sent successfully!\n\n") 
		except smtplib.SMTPServerDisconnected as e:
			smtpSession.quit()
			print("Server  unexpectedly disconnect")
		except smtplib.SMTPResponseException as e:
			print(f"SMTP server error | {smtpSession.smtp_code}\n{smtpSession.smtp_error}")
		except smtplib.SMTPSenderRefused as e:
			print("Sender address refused")
		except smtplib.SMTPAuthenticationError as e:
			smtpSession.quit()
			print("SMTP Authentication Error : Please check Sender email and password\nSecure Implementaion working progress")
		except smtplib.SMTPDataError as e:
			print("The SMTP server refused to accept the message data")
		except smtplib.SMTPConnectError as e:
			print("Error occurred during establishment of a connection with the server")
		except Exception as e:
			smtpSession.quit()
			raise
		else:
			pass
		finally:
			pass

	def fillJsonStrDict(self,response_content,httpbl_response):
		blackListResponse=httpbl_response
		try:
			if not response_content:
				pass
			else:
				self.fwRcRConvertedToPytohnDictionary=json.loads(response_content)
				#print(type(self.fwRcRConvertedToPytohnDictionary))
				self.strHttpblResponse=json.dumps(blackListResponse)
				print(self.strHttpblResponse,type(self.strHttpblResponse))
				self.firewallRuleCrInResponseJsonSringFormat=json.dumps(self.fwRcRConvertedToPytohnDictionary,indent=4)
		except Exception as e:
			raise
		else:
			pass
		finally:
			pass
		

	def LogRule(self,response_content,httpbl_response):
		cTime=str(datetime.datetime.now())
		formatedCTime=cTime.replace(":",".")	
		self.logHttpblResponse=httpbl_response
		self.fwRcRConvertedToPytohnDictionary=json.loads(response_content)
		try:
			out_file=open(f"Firewall_Rule_{formatedCTime}.json","w")
			json.dump(self.fwRcRConvertedToPytohnDictionary,out_file,indent=4)
			out_file.close()
			print(f'\n\n\n {formatedCTime} Log Created \n\n\n')
		except EOFError as e:
			print(e)
			out_file.close()
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
				self.srcdstList.append(itmes)
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
				self.srcdstList.append(itmes)
				self.Mutex_lock.release()
		#self.srcdstLis=self.dstIPList.copy()

	def getSourceIPs(self):
		#for x in self.srcdstList:
			#print(x)
		#print(len(self.srcIPList))
		#return self.srcdstList
		print(self.srcdstList)

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
				if(ips in self.threatList):
					continue
				else:
					#HttpBLChkThread=Threading(target=)
					
					self.httpblResponse = bl.query(ips)
					print(self.httpblResponse['threat_score'],ips)
					if (self.httpblResponse['threat_score']==None):
						continue
					if(self.httpblResponse['threat_score']>self.maximumAllowedThreatScore):
						print(f'\n\n\nTHREAT DETECTED: {ips} WITH THREAT SCORE OF',self.httpblResponse ['threat_score'],"\n\n\n")
						if ips in self.threatList:
							continue
						else:
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
							self.firewallRuleCreationResponse=requests.post(self.ruleCreationlink,verify=self.pemCert,data=self.data,headers=self.headers)

							fillJsonStrDictThread=threading.Thread(target=self.fillJsonStrDict, args=(self.firewallRuleCreationResponse.content,self.httpblResponse,))
							fillJsonStrDictThread.start()
							fillJsonStrDictThread.join()

							ruleCreationStatusCodeThread=threading.Thread(target=self.FirewallRuleCreationMsg,args=(self.firewallRuleCreationResponse.status_code,self.firewallRuleCreationResponse.content,))
							ruleCreationStatusCodeThread.start()
							ruleCreationStatusCodeThread.join()
							LogRuleThread=threading.Thread(target=self.LogRule, args=(self.firewallRuleCreationResponse.content,self.httpblResponse,))
							if __StartLogging__:
								LogRuleThread.start()
							
							emailThread=threading.Thread(target=self.sendEmailNotification)
							emailThread.start()
							emailThread.join()
						except TimeoutError:
							try:
								possibleFirewallDown=threading.Thread(target=self.HostStatusCheck)
								possibleFirewallDown.start()
								possibleFirewallDown.join()
								if(self.isFirewallUP==False):
									firewallDownNotification=threading.Thread(target=self.sendEmailNotification)
									firewallDownNotification.start()
									firewallDownNotification.join()
							except Exception as e:
								raise
							else:
								pass
							finally:
								pass
						except IndexError:
							print(self.srcdstList[-1:-5])
							exit()
						except requests.exceptions.Timeout as e:
							print(f"{self.continueTimeOutMSG}")
							try:
								possibleFirewallDown=threading.Thread(target=self.HostStatusCheck)
								possibleFirewallDown.start()
								possibleFirewallDown.join()
								if(self.isFirewallUP==False):
									firewallDownNotification=threading.Thread(target=self.sendEmailNotification)
									firewallDownNotification.start()
									firewallDownNotification.join()
							except Exception as e:
								raise
							else:
								pass
							finally:
								pass
							continue
						except requests.exceptions.TooManyRedirects:
							print(f"{self.tooManyRedirectsMSG}")
							try:
								possibleFirewallDown=threading.Thread(target=self.HostStatusCheck)
								possibleFirewallDown.start()
								possibleFirewallDown.join()
								if(self.isFirewallUP==False):
									firewallDownNotification=threading.Thread(target=self.sendEmailNotification)
									firewallDownNotification.start()
									firewallDownNotification.join()
							except Exception as e:
								raise
							else:
								pass
							finally:
								pass
							continue
						except requests.exceptions.RequestException as e:
							print(f"{self.requestLibraryErrorMSG}")
							try:
								possibleFirewallDown=threading.Thread(target=self.HostStatusCheck)
								possibleFirewallDown.start()
								possibleFirewallDown.join()
								if(self.isFirewallUP==False):
									firewallDownNotification=threading.Thread(target=self.sendEmailNotification)
									firewallDownNotification.start()
									firewallDownNotification.join()
							except Exception as e:
								raise
							else:
								pass
							finally:
								pass
						except Exception as e:
							raise
						except OSError:
							print(f"{self.tlsErrorMSG}")
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
		self.netAdapter=sysInterface
	def __CheckNetInterfaces(self):
		avlSysInterfaces=getnic.interfaces()

		self.netInterface=self.sysInterface
		return self.netInterface

	def __enableCapture(self):
		__enableCapture__=False

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
			ipList=Firewall()
			sourceIPset=set()
			destinationIPset=set()
			
			
			
			#dir(capture.my_layer)#'IP' in capture
			while  __enableCapture__:
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
						addSrcIPList=threading.Thread(target=ipList.SourceIPs, args=(packets['IP'].src,))
						addSrcIPList.start()
						addSrcIPList.join()
						
						addDstIPList=threading.Thread(target=ipList.DestinationIPs, args=(packets['IP'].dst,))
						addDstIPList.start()
						addDstIPList.join()
						#print(ipList.getSourceIPs())

						#getAllAddresses=threading.Thread(ipList.getSourceIPs)
						#getAllAddresses.start()
						

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



			


 