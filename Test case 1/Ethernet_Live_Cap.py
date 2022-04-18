import pyshark, httpbl, json, threading #threading non-functional 
import collections, gc ,re
from json import JSONEncoder
from get_nic import getnic 
import time
import requests
import bigdatacloudapi
import datetime ,smtplib, multiprocessing
from multiprocessing import Queue


global __enableCapture__
__enableCapture__=True
global __StartLogging__
__StartLogging__=False
global __EnableTorBlocking__
__EnableTorBlocking__=False
global __EnableAutomaticUnblock__
__EnableAutomaticUnblock__=True
global srcdstList 
srcdstList = collections.deque()
global __EnableEmailNotification__
__EnableEmailNotification__=False

global __UnblockHours__
global __UnblockMinutes__
global __UnblockSeconds__
__UnblockHours__=0
__UnblockMinutes__=0
__UnblockSeconds__=60
global FWRuleInfo
FWRuleInfo=collections.deque()

class TimeLaps:
	"""docstring for TimeLaps"""

	def __init__(self,Item):
		self.BlockedItem=Item
		self.endtime=datetime.timedelta(0,00,00)

	def countdown(self,h=__UnblockHours__, m=__UnblockMinutes__, s=__UnblockSeconds__):
		if __UnblockHours__ == 0 and __UnblockMinutes__== 0 and __UnblockSeconds__==0:
			print(f'Invalid Time format | Hours, Minutes, Seconds cannot all be zero Auto Unblock Disabled \n\n\n')
			__EnableAutomaticUnblock__=False
		else:
			total_seconds = __UnblockHours__ * 3600 +  __UnblockMinutes__ * 60 + __UnblockSeconds__
			timer = datetime.timedelta(seconds = total_seconds)
			while timer>=self.endtime:
				timer = datetime.timedelta(seconds = total_seconds)
				time.sleep(1)
				total_seconds -= 1
				#print(f"item from time {self.BlockedItem} {timer} \n")
				if timer==self.endtime:
					FWRuleInfo[FWRuleInfo.index(self.BlockedItem)]['Timer']='expired'
					#print(f" {FWRuleInfo} Timer hit zero returing Ip\n\n\n")
					
					#print(f"\n\n global IP {globalIP['ip']}")
					#if self.BlockedItem['ip'] in globalIP['ip']:
					#IPindex=globalIPTracker.index(globalIP)
					#globalIPTracker[IPindex]['Timer']=='expired'


class Firewall:
	""" """
	def __init__(self):
		self.pemCert='pfsense1.localdomain.pem'
		self.hostName="192.168.1.100"


		self.srcIPList=set()
		self.dstIPList=set()
		#self.srcdstList=set()
		self.checkedIPset=set()
		self.TorcheckedIPset=set()
		

		self.Mutex_lock=threading.Lock()
		
		self.threatList=set()
		self.torThreatList=set()

		
		self.ipTimerObj={'ip':''}
		
		self.twoTimeRepeat=set()
		self.threeTimeRepeat=set()
		self.firstUblockTimer=None
		self.secondUnblockTimer=None

		
		self.ruleCreationResponseToDict=[]
		self.fwRcRConvertedToPytohnDictionary=None#Firewall Rule Creation Response content in dictionary format
		self.firewallRuleCrInResponseJsonStrFormat=None
		self.logHttpblResponse=None
		self.httpblResponse=None
		self.strHttpblResponse=None
		self.firewallRuleCreationResponse=None
		
		

		self.httpBLKey=''
		self.maximumAllowedThreatScore=10
		
		
		self.senderEmailAddress=""
		self.senderEmailPwd=""
		self.receiverMail=""

		self.dequeLenth=None
		self.skipIPlist=['162.159.200.1',"162.159.200.123"]

		self.monitoringOnly=False
		self.networkMonitoringEnable=None
		self.httpBlHeaders=None
		self.isFirewallUP=False
		
		
		self.client_ID='admin'
		self.clien_Token='pfsense'
		self.rule_Type='block'
		self.rule_Interface='wan'
		self.headers={'Content-Type': 'application/json'}

	
		self.bigdataCloudApiKey=""
		self.bigdataCloudBatchSize=50
		self.TorExitNodeSet={'nodes':[]}
		self.iterrableTorSet=[]
		self.BDCDictResponse=None
		self.bigdataCloudOffset="0"
		self.bigdataCloudSortBy="ip"
		self.bigdataCloudOrder="asc"
		self.bigdataCloudLocalityLanguage="en"
		self.bigdataCloudAbilableIps=None
		self.TorFWResponseConToPytohnDict=None
		self.TorWFRuleCrInResponseStrFormat=None
		self.TorNodeinndexLocation=None
		self.TorNodDetailsEmail=None
		self.bigdataCloudApiKeyError="\n\nAPI key Error : Please check if the Big data cloud API key is correct or valid\n\n"


		self.unableToReachMSG='\n\nUnable to Reach Firewall Check whether the Network, Firewall is UP and Running\n\n'
		self.continueTimeOutMSG='\n\nConnection Timeout: Check whether the Network, Firewall is UP and Running\n\n'
		self.tooManyRedirectsMSG='\n\nToo Many Redirects: Bad URL\n\n'
		self.requestLibraryErrorMSG='\n\nRequest Library Error\n\n'
		self.firewallWorkingMsg=f'\n\n(OK): {self.hostName} is UP and Running\n\n'
		self.okResponseMSG200="is UP network monitoring has started"
		self.firewallRuleCreatedMSG="\n\nAPI Call (OK): Succeeded Firewall Rule Has Been Created\n\n"
		self.badRequestMSG400="\n\n(Bad Request) : An error was found within your requested parameters\n\n"
		self.unauthorizedMSG401="\n\n(Unauthorized) : API client has not completed authentication or authorization successfully\n\n"
		self.forbiddenMSG403="\n\n(Forbidden) : The API endpoint has refused your call. Commonly due to your access settings found in System > API\n\n"
		self.notFoundMSG404="\n\n(Not found) : Either the API endpoint or requested data was not found\n\n"
		self.serverErrorMSG500="\n\n(Server error) : The API endpoint encountered an unexpected error processing your API request\n\n"
		self.generalErrorMSG="\n\n(ERROR) : Contact admin\n\n"
		self.tlsErrorMSG="\n\n(TLS Error) : Could not find a suitable TLS CA certificate bundle\n\n"
		
	def addRuleDetails(self,ip='',trackerId=''):
		IPandTrackerId={'ip':' ','RuleTrackerID':' ','Timer':''}
		if not ip or not trackerId:
			pass
		elif ip==' '=='' or trackerId==' '=='':
			pass
		else:
			try:
				IPandTrackerId['ip']=ip
				IPandTrackerId['RuleTrackerID']=trackerId
				IPandTrackerId['Timer']='active'
				FWRuleInfo.append(IPandTrackerId)
				#print(f"Bloacked ip List {type(IPandTrackerId)},{FWRuleInfo} \n\n\n")
			except Exception as e:
				raise
			else:
				pass
			finally:
				pass
	def unblockTimer(self):
		for ips in FWRuleInfo:
			if ips['Timer']=='active':
				self.ipTimerObj['ip']=TimeLaps(ips)
				threading.Thread(target=self.ipTimerObj['ip'].countdown).start()
		#if globalIPTracker==None:
		#self.FWRuleInfo.remove(item)
		#print(f'IP timer Obj {self.ipTimerObj}')s

	def UnblockIP(self):
		pass
	def getTotalBigDataCloudBatchSize(self):
		endpoint=f"https://api.bigdatacloud.net/data/tor-exit-nodes-list?batchSize={str(self.bigdataCloudBatchSize)}&offset={self.bigdataCloudOffset}&sort={self.bigdataCloudSortBy}&order={self.bigdataCloudOrder}&localityLanguage={self.bigdataCloudLocalityLanguage}&key={self.bigdataCloudApiKey}"
		headers={'Content-Type': 'application/json'}
		try:
			bigdatacloudResponse=requests.get(endpoint,headers=headers)
			self.BDCDictResponse=json.loads(bigdatacloudResponse.content)
			self.bigdataCloudAbilableIps=self.BDCDictResponse['total']
		except Exception as e:
			raise
		except KeyError as e:
			print(f"{bigdataCloudApiKeyError}")
		else:
			pass
		finally:
			pass

	def CreateTorBlacklistList(self):
		endpoint=f"https://api.bigdatacloud.net/data/tor-exit-nodes-list?batchSize={self.bigdataCloudBatchSize}&offset={self.bigdataCloudOffset}&sort={self.bigdataCloudSortBy}&order={self.bigdataCloudOrder}&localityLanguage={self.bigdataCloudLocalityLanguage}&key={self.bigdataCloudApiKey}"
		headers={'Content-Type': 'application/json'}
		added=0
		
		if(self.bigdataCloudBatchSize==None):
			print(f"\n\n\nPlease proveide Big Data Cloud batch size \n\n\n")
		else:
			try:
				bigdatacloudResponse=requests.get(endpoint,headers=headers)
				self.BDCDictResponse=json.loads(bigdatacloudResponse.content)
				self.bigdataCloudAbilableIps=self.BDCDictResponse['total']
				
				while(added<self.bigdataCloudBatchSize):
					try:
						ipandrank={'ip':'','rank':''}
						#print(self.BDCDictResponse['nodes'][added]['ip'], self.BDCDictResponse['nodes'][added]['carriers'][0]['rank'])
						ipandrank['ip']=self.BDCDictResponse['nodes'][added]['ip']
						ipandrank['rank']=self.BDCDictResponse['nodes'][added]['carriers'][0]['rank']
						self.TorExitNodeSet['nodes'].append(ipandrank)
						self.iterrableTorSet.append(self.BDCDictResponse['nodes'][added]['ip'])
						added=added+1
					except IndexError as e:
						continue
					except Exception as e:
						raise e
			except Exception as e:
				raise
			else:
				pass
			finally:
				print(self.iterrableTorSet)
				pass

	def blackListTorNodes(self):
		
		self.ruleCreationlink=f"https://{self.hostName}/api/v1/firewall/rule"
		self.rule_Type='block'
		for ips in srcdstList:
			#print(f'from TorNodeBlacklistThread {srcdstList}')
			try:
				#print(srcdstList)
				if(ips in self.torThreatList):
					continue
				if(ips in self.TorcheckedIPset):
					continue
				else:
					print(f"[Tor] {ips}  ")
					if(ips in self.iterrableTorSet):
						try:
							self.TorNodeinndexLocation=self.iterrableTorSet.index(ips)
						except Exception as e:
							raise e
						print(f'\n\n\nTHREAT DETECTED: {ips} WITH RANK OF',self.TorExitNodeSet['nodes'][self.TorNodeinndexLocation]["rank"],"\n\n\n")
						self.TorNodDetailsEmail=self.BDCDictResponse['nodes'][self.TorNodeinndexLocation]	
						self.torThreatList.add(ips)

						self.paraM={"client-id":"","client-token":"pfsense","type": "","interface": "","ipprotocol":"inet","protocol":"tcp/udp","src":"","srcport":"any","dst":"","dstport": "any","descr": "Automated api rule test"}
						self.paraM['client-id']=self.client_ID
						self.paraM['client-token']=self.clien_Token
						self.paraM['type']=self.rule_Type
						self.paraM['dst']=ips
						self.paraM['src']=ips
						self.paraM['interface']=self.rule_Interface
						self.data=json.dumps(self.paraM)
						try:
							self.TorBlacklisFWResponse=requests.post(self.ruleCreationlink,verify=self.pemCert,data=self.data,headers=self.headers)
							TorJsonStrDictThread=threading.Thread(target=self.torFillJsonStrDict, args=(self.TorBlacklisFWResponse.content,))
							TorJsonStrDictThread.start()
							TorJsonStrDictThread.join()

							ruleDetailsThread=threading.Thread(target=self.addRuleDetails,args=(ips,self.TorFWResponseConToPytohnDict['data']['tracker']))
							ruleDetailsThread.start()
							ruleDetailsThread.join()
							if __EnableAutomaticUnblock__:
								unblockTimerThread=threading.Thread(target=self.unblockTimer)
								unblockTimerThread.start()
							try:
								TorRuleCreationStatusCodeThread=threading.Thread(target=self.FirewallRuleCreationMsg,args=(self.TorBlacklisFWResponse.status_code,self.TorBlacklisFWResponse.content,True,))
								TorRuleCreationStatusCodeThread.start()
								TorRuleCreationStatusCodeThread.join()


								LogRuleThread=threading.Thread(target=self.LogRule, args=(self.TorBlacklisFWResponse.content,' ',True,))
								LogThreatWhenDownThread=threading.Thread(target=self.LogThreatWhenDown, args=('',True,))
								if __StartLogging__:
									LogRuleThread.start()
									LogThreatWhenDownThread.start()
									LogThreatWhenDownThread.join()
								if __EnableEmailNotification__:
									emailThread=threading.Thread(target=self.sendEmailNotification,args=(True,))
									emailThread.start()
									emailThread.join()
							except TimeoutError:
								try:
									possibleFirewallDown=threading.Thread(target=self.HostStatusCheck)
									possibleFirewallDown.start()
									possibleFirewallDown.join()
									if(self.isFirewallUP==False):
										firewallDownNotification=threading.Thread(target=self.sendEmailNotification,args=(True,))
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
							else:
								pass
							finally:
								pass
						except IndexError:
							print(srcdstList[-1:-5])
							exit()
						except requests.exceptions.Timeout as e:
							print(f"{self.continueTimeOutMSG}")
							try:
								possibleFirewallDown=threading.Thread(target=self.HostStatusCheck)
								possibleFirewallDown.start()
								possibleFirewallDown.join()
								if(self.isFirewallUP==False):
									firewallDownNotification=threading.Thread(target=self.sendEmailNotification,args=(True,))
									firewallDownNotification.start()
									firewallDownNotification.join()
							except Exception as e:
								raise
							else:
								pass
							finally:
								pass
						except requests.exceptions.TooManyRedirects:
							print(f"{self.tooManyRedirectsMSG}")
							try:
								possibleFirewallDown=threading.Thread(target=self.HostStatusCheck)
								possibleFirewallDown.start()
								possibleFirewallDown.join()
								if(self.isFirewallUP==False):
									firewallDownNotification=threading.Thread(target=self.sendEmailNotification,args=(True,))
									firewallDownNotification.start()
									firewallDownNotification.join()
							except Exception as e:
								raise
							else:
								pass
							finally:
								pass
						except requests.exceptions.RequestException as e:
							print(f"{self.requestLibraryErrorMSG}")
							try:
								possibleFirewallDown=threading.Thread(target=self.HostStatusCheck)
								possibleFirewallDown.start()
								possibleFirewallDown.join()
								if(self.isFirewallUP==False):
									firewallDownNotification=threading.Thread(target=self.sendEmailNotification,args=(True,))
									firewallDownNotification.start()
									firewallDownNotification.join()
							except Exception as e:
								raise
							else:
								pass
							finally:
								pass
						except OSError:
							print(f"{self.tlsErrorMSG}")
						except Exception as e:
							raise
						else:
							pass
						finally:
							pass
					else:
						self.TorcheckedIPset.add(ips)
			except Exception as e:
				raise
			except RuntimeError as RunErr:
				print(f"Runtime Error {RunErr}")
			except KeyboardInterrupt:
				exit()
				print("Press Ctrl-C to terminate while statement")
			else:
				pass
			finally:
				pass

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

	'''Firewall Status Check Message == FirewallStatusCheckMsg is used to check whether firewall is in a up or down state. '''
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

	def FirewallRuleCreationMsg(self,StatusCode,response_content,tor=False):
		try:
			if (StatusCode==200):
				print(f'{self.hostName}(OK):{self.firewallRuleCreatedMSG}\n\n\n{self.firewallRuleCrInResponseJsonStrFormat}\n\n\n')
			elif(StatusCode==200 and tor==True):
				print(f'{self.hostName}(OK):{self.firewallRuleCreatedMSG}\n\n\n')
			elif(StatusCode==400):
				print(f'{self.hostName} {self.badRequestMSG400}\n{self.firewallRuleCrInResponseJsonStrFormat}')
			elif(StatusCode==400 and tor==True):
				print(f'{self.hostName}(OK):{self.badRequestMSG400}\n\n\n')
			elif(StatusCode==401):
				print(f'{self.hostName} {self.unauthorizedMSG401}\n{self.firewallRuleCrInResponseJsonStrFormat}')
			elif(StatusCode==401 and tor==True):
				print(f'{self.hostName}(OK):{self.unauthorizedMSG401}\n\n\n')
			elif(StatusCode==403):
				print(f'{self.hostName} {self.forbiddenMSG403}\n{self.firewallRuleCrInResponseJsonStrFormat}')
			elif(StatusCode==403 and tor==True):
				print(f'{self.hostName}(OK):{self.forbiddenMSG403}\n\n\n')
			elif(StatusCode==404):
				print(f'{self.hostName} {self.notFoundMSG404}\n{self.firewallRuleCrInResponseJsonStrFormat}')
			elif(StatusCode==404 and tor==True):
				print(f'{self.hostName}(OK):{self.notFoundMSG404}\n\n\n')
			elif(StatusCode==500):
				print(f'{self.hostName} {self.serverErrorMSG500}\n{self.firewallRuleCrInResponseJsonStrFormat}')
			elif(StatusCode==500 and tor==True):
				print(f'{self.hostName}(OK):{self.serverErrorMSG500}\n\n\n')
			else:
				print(f'Unreachable : {self.hostName} | Firewall Rule Creation Fail {self.generalErrorMSG}\n{self.firewallRuleCrInResponseJsonStrFormat}')
		except Exception as e:
			raise
		else:
			pass
		finally:
			pass

	def sendEmailNotification(self,tor=False):
		try:
			if self.senderEmailAddress==None or self.senderEmailPwd==None or self.receiverMail==None:
				print(f'Please proveide details to send notification')
			elif (self.isFirewallUP==False):
				smtpSession = smtplib.SMTP('smtp.gmail.com', 587)
				smtpSession.starttls()
				smtpSession.login(self.senderEmailAddress,self.senderEmailPwd)
				if tor==False:
					report=f"Subject:Unable to Reach Firewall\nThreat detected but Unable to create firewall rule\n Firewall Rule details \n{self.firewallRuleCrInResponseJsonStrFormat}\n Threat details \n{self.mailsStrHttpblResponse}"
					smtpSession.sendmail(self.senderEmailAddress,self.receiverMail,report)
					self.firewallRuleCrInResponseJsonStrFormat=None
					smtpSession.quit()
				else:
					self.TorNodDetailsEmailStr=json.dumps(self.TorNodDetailsEmail,indent=4)
					report=f"Subject:Unable to Reach Firewall\nTor Node detected but Unable to create firewall rule\n Firewall Rule details \n{self.TorWFRuleCrInResponseStrFormat}\n Node details \n{self.TorNodDetailsEmailStr}"		
					smtpSession.sendmail(self.senderEmailAddress,self.receiverMail,report)
					self.TorNodDetailsEmail=None
					self.TorWFRuleCrInResponseStrFormat=None
					smtpSession.quit()
				print("\n\nEmail Notification sent successfully!\n\n\n") 
			else:
				smtpSession = smtplib.SMTP('smtp.gmail.com', 587)
				smtpSession.starttls()
				smtpSession.login(self.senderEmailAddress,self.senderEmailPwd)
				if tor==False:
					report=f"Subject:Auomated Firewall Rule\nFirewall Rule details \n{self.firewallRuleCrInResponseJsonStrFormat}\n Threat details \n{self.mailsStrHttpblResponse}"
					smtpSession.sendmail(self.senderEmailAddress,self.receiverMail,report)
					self.firewallRuleCrInResponseJsonStrFormat=None
					smtpSession.quit()
				else:
					self.TorNodDetailsEmailStr=json.dumps(self.TorNodDetailsEmail,indent=4)
					report=f"Subject:Auomated Firewall Rule\nTor Node detected \n Firewall Rule details \n{self.TorWFRuleCrInResponseStrFormat}\n Node details \n{self.TorNodDetailsEmailStr}"
					smtpSession.sendmail(self.senderEmailAddress,self.receiverMail,report)
					self.TorNodDetailsEmail=None
					self.TorWFRuleCrInResponseStrFormat=None
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
				self.strHttpblResponse=json.dumps(blackListResponse,indent=4)
				print(f'{self.strHttpblResponse}\n\n\n')
				self.mailsStrHttpblResponse=self.strHttpblResponse
				self.firewallRuleCrInResponseJsonStrFormat=json.dumps(self.fwRcRConvertedToPytohnDictionary,indent=4)
		except Exception as e:
			raise
		else:
			pass
		finally:
			pass
	def torFillJsonStrDict(self,response_content):
		try:
			if not response_content:
				pass
			else:
				self.TorFWResponseConToPytohnDict=json.loads(response_content)
				self.TorWFRuleCrInResponseStrFormat=json.dumps(self.TorFWResponseConToPytohnDict,indent=4)
				print(f"{self.TorWFRuleCrInResponseStrFormat}")
		except Exception as e:
			raise
		else:
			pass
		finally:
			pass
		

	def LogRule(self,response_content,httpbl_response,tor=False):
		cTime=str(datetime.datetime.now())#current Time
		formatedCTime=cTime.replace(":",".")#windows save 
		self.logHttpblResponse=httpbl_response
		self.fwRcRConvertedToPytohnDictionary=json.loads(response_content)
		if(tor==False):
			try:
				out_file=open(f"Firewall_Rule_{formatedCTime}.json","w")
				json.dump(self.fwRcRConvertedToPytohnDictionary,out_file,indent=4)
				out_file.close()
				print(f'\n\n\n {formatedCTime} Log Created \n\n\n')
			except EOFError as e:
				print(e)
				out_file.close()
			except Exception as e:
				out_file.close()
				raise
			else:
				pass
			finally:
				pass
		else:
			try:
				out_file=open(f"Firewall_Rule_Tor_Node_{formatedCTime}.json","w")
				json.dump(self.TorFWResponseConToPytohnDict,out_file,indent=4)
				out_file.close()
				print(f'\n\n\n {formatedCTime} Log Created \n\n\n')
			except EOFError as e:
				print(e)
				out_file.close()
			except Exception as e:
				out_file.close()
				raise
			else:
				pass
			finally:
				pass

	def LogThreatWhenDown(self,response='',tor=False):
		cTime=str(datetime.datetime.now())#current Time
		formatedCTime=cTime.replace(":",".")#windows save 	
		if(tor==False):
			try:
				self.logHttpblResponse=response
				out_file=open(f"HttpBL_Threat_Details_{formatedCTime}.json","w")
				json.dump(self.logHttpblResponse,out_file,indent=4)
				out_file.close()
				print(f'\n\n\n {formatedCTime} HttpBL Threat Details Log Created \n\n\n')
			except EOFError as e:
				print(e)
				out_file.close()
			except Exception as e:
				out_file.close()
				raise
			else:
				pass
			finally:
				pass
		else:
			try:
				out_file=open(f"Tor_Node_Details_{formatedCTime}.json","w")
				json.dump(self.TorNodDetailsEmail,out_file,indent=4)
				out_file.close()
				self.TorNodDetailsEmailStr=None
				print(f'\n\n\n {formatedCTime} Tor Node Details Log Created \n\n\n')
			except EOFError as e:
				print(e)
				out_file.close()
			except Exception as e:
				out_file.close()
				raise
			else:
				pass
			finally:
				pass

		

	def SourceIPs(self,srcIP):
		#self.srcIPList.add(srcIP)
		#for itmes in self.srcIPList:
		if (srcIP==" " or ""):
			pass
		elif(srcIP in srcdstList):
			pass
		else:
			self.Mutex_lock.acquire(blocking=False)
			srcdstList.append(srcIP)
			self.Mutex_lock.release()
			
			#print(f"from Source list {srcdstList}")
			#self.Mutex_lock.release()

			
			
		#if not self.srcIPList: #check empty status
			#continue
		

		#srcdstList=self.srcIPList.copy()

	def DestinationIPs(self,dstIP):
		#self.dstIPList.add(dstIP)
		#for itmes in self.dstIPList:
		if (dstIP==" "or""):#check empty status
			pass
		elif(dstIP in srcdstList):
			pass
		else:
			self.Mutex_lock.acquire(blocking=False)
			srcdstList.append(dstIP)
			self.Mutex_lock.release()

			
			#print(f"from DestinationIPs list {srcdstList}")
			#self.Mutex_lock.release()
			
			
		#self.srcdstLis=self.dstIPList.copy()
		#if not self.dstIPList:
			#pass
		
		

	def getSourceIPs(self):
		#for x in srcdstList:
			#print(x)
		#print(len(self.srcIPList))
		#return srcdstList
		print(srcdstList)

	def getDestinationIPs(self):
		#for x in self.dstIPList:
			#print(x)
		return self.dstIPList

	def getSrcDstQueueLen(self):
		self.dequeLenth=len(srcdstList)
		return self.dequeLenth
	

	def checkBlackListStatus(self):
		#print(srcdstList)
		bl = httpbl.HttpBL(self.httpBLKey)
		#print(srcdstList)
		self.ruleCreationlink=f"https://{self.hostName}/api/v1/firewall/rule"
		self.rule_Type='block'

		#while(len(srcdstList)<100)
		#Loop through Source and destination IPs
		
		for ips in srcdstList: 
			try:
				if(self.isFirewallUP==False):
					checkWFstatusThread=threading.Thread(target=self.HostStatusCheck)
					checkWFstatusThread.start()
					checkWFstatusThread.join()
					continue
				if(ips in self.threatList):
					continue
				else:
					#HttpBLChkThread=Threading(target=)
					if ips in self.checkedIPset:
						continue
					self.httpblResponse = bl.query(ips)
					print(self.httpblResponse['threat_score'],ips)
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

							ruleDetailsThread=threading.Thread(target=self.addRuleDetails,args=(ips,self.fwRcRConvertedToPytohnDictionary['data']['tracker']))
							ruleDetailsThread.start()
							ruleDetailsThread.join()
							if __EnableAutomaticUnblock__:
								unblockTimerThread=threading.Thread(target=self.unblockTimer)
								unblockTimerThread.start()

							LogRuleThread=threading.Thread(target=self.LogRule, args=(self.firewallRuleCreationResponse.content,self.httpblResponse,))
							LogThreatWhenDownThread=threading.Thread(target=self.LogThreatWhenDown, args=(self.httpblResponse,False,))
							if __StartLogging__:
								LogRuleThread.start()
								LogThreatWhenDownThread.start()
								LogThreatWhenDownThread.join()
							if __EnableEmailNotification__:
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
							print(srcdstList[-1:-5])
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
						except KeyboardInterrupt:
							exit()
							print("Press Ctrl-C to terminate while statement")
						except OSError:
							print(f"{self.tlsErrorMSG}")
						else:
							pass
						finally:
							pass
					else:
						self.checkedIPset.add(ips)
					#if((len(srcdstList))<=2):

						#continue
					#else:
						#print("MONITORING ACTIVEcl")
						#self.srcdstList.pop()
			except Exception as e:
				raise
			except RuntimeError as RunErr:
				print(f"Runtime Error {RunErr}")
			except KeyboardInterrupt:
				exit()
				print("Press Ctrl-C to terminate while statement")
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
			pfSenseFW=Firewall()
			sourceIPset=set()
			destinationIPset=set()
			
			
			
			#dir(capture.my_layer)#'IP' in capture
			while  __enableCapture__:
				print(f'Checking Host:{pfSenseFW.hostName} status')
				firewallStatusCheck=threading.Timer(10,pfSenseFW.HostStatusCheck)
				firewallStatusCheck.start()
				firewallStatusCheck.join()
				if(pfSenseFW.isFirewallUP):
					print(f'{pfSenseFW.hostName} {pfSenseFW.okResponseMSG200}')
				else:
					continue
				if(__EnableTorBlocking__ and pfSenseFW.isFirewallUP):
					TorNodeBlacklistThread=threading.Thread(target=pfSenseFW.getTotalBigDataCloudBatchSize)
					TorNodeBlacklistThread.start()
					TorNodeBlacklistThread.join()

					print("\n\n\n Creating Big Data Cloud List\n\n\n")
					CreateTorIpSet=threading.Thread(target=pfSenseFW.CreateTorBlacklistList)
					#print(type(pfSenseFW.bigdataCloudAbilableIps))
					#print(pfSenseFW.bigdataCloudAbilableIps)
					CreateTorIpSet.start()
					CreateTorIpSet.join()
				
				for packets in capture.sniff_continuously():
					if ('IP' in packets):
						#sourceIPset.add(packets['IP'].src)
						#destinationIPset.add(packets['IP'].dst)
						addSrcIPList=threading.Thread(target=pfSenseFW.SourceIPs, args=(packets['IP'].src,))
						addSrcIPList.start()					
						
						addDstIPList=threading.Thread(target=pfSenseFW.DestinationIPs, args=(packets['IP'].dst,))
						addDstIPList.start()
						#print(pfSenseFW.getSourceIPs())

						#getAllAddresses=threading.Thread(pfSenseFW.getSourceIPs)
						#getAllAddresses.start()

						IPblacklistThread=threading.Thread(target=pfSenseFW.checkBlackListStatus)
						IPblacklistThread.start()
						IPblacklistThread.join()

						if(__EnableTorBlocking__ and pfSenseFW.isFirewallUP):
							blackListTorNodesThread=threading.Thread(target=pfSenseFW.blackListTorNodes)
							blackListTorNodesThread.start()
							blackListTorNodesThread.join()

						

						#print(pfSenseFW.iterrableTorSet)
						#print(pfSenseFW.getDestinationIPs())
						
						#print(pfSenseFW.getSourceIPs())
						#print(pfSenseFW.getSourceIPs(),pfSenseFW.getDestinationIPs())
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
		except RuntimeError as RunErr:
				print(f"Runtime Error {RunErr}")
		except Exception as e:
			print(e)
		except KeyboardInterrupt:
			#type(capture)
			exit()
			print("Press Ctrl-C to terminate while statement")
		else:
			pass
		finally:
			pass



if __name__ == '__main__':
	test1=TrafficCapture("Ethernet")
	TestThread=threading.Thread(target=test1.Capture)
	gc.enable()
	TestThread.start()
	TestThread.join()
	


			

