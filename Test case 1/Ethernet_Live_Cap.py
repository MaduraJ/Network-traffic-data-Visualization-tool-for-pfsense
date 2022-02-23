import pyshark
import json
from json import JSONEncoder
import asyncio
import time
import subprocess
import platform
from get_nic import getnic 

class _IP:
	""" """
	def __init__(self):
		pass
	def GetSourceIPs(self,srcIP=set()):
		self.sourceIPList=set()
		self.sourceIPList.add(srcIp)
		print(sourceIPList)
	def GetDestinationIPs(self,dstIP=set()):
		self.destinationIPList=set()
		self.destinationIPList.add(dstIP)
		print(destinationIPList)
		
class TrafficCapture:
	
	def __init__(self, sysInterface):
		self.sysInterface = sysInterface

	def __CheckNetInterfaces(self):
		avlSysInterfaces=getnic.interfaces()

		self.netInterface=self.sysInterface
		return self.netInterface

	ipList=_IP()

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
			sourceIPset=set()
			destinationIPset=set()
			while  _stopCapture_:
				for packets in capture.sniff_continuously():
					#dir(capture.my_layer)
					if ('IP' in packets):#'IP' in capture
						sourceIPset.add(packets['IP'].src)
						destinationIPset.add(packets['IP'].dst)
						for x in sourceIPset,destinationIPset:
							print(x)
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


			


 