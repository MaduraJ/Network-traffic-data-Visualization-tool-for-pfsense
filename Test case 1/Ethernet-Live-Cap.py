import pyshark
import json
from json import JSONEncoder
import asyncio
import time
import subprocess
import platform
from get_nic import getnic 

class TrafficCapture:
	def __init__(self, sysInterface):
		self.sysInterface = sysInterface


	def __CheckNetInterfaces(self):
		avlSysInterfaces=getnic.interfaces()

		self.netInterface=self.sysInterface
		return self.netInterface

	def Capture(self):
		try:
			capture = pyshark.LiveCapture(interface=self.__CheckNetInterfaces(),output_file='tempNetTraffic.pcapng')
			while True:
				capture.sniff(timeout=0)
				for packet in capture.sniff_continuously():
					print(packet['eth'].field_names)
					#with open("tempNetTraffic.json","w") as netTraffic:
					#json.dump(packet,netTraffic,indent=5)
					#jsonString=json.dump(packet,indent=4)
					#jsonFile.write(jsonString)

		except EOFError as e:
			print(e)
		except Exception as e:
			print(e)
		except KeyboardInterrupt:
			type(capture)
			time.sleep(1)
			print("Press Ctrl-C to terminate while statement")
		else:
			pass
		finally:
			pass



test1=TrafficCapture("Wi-Fi")
test1.Capture()

			


 