import pyshark
import json
from json import JSONEncoder



try:
	capture = pyshark.LiveCapture(interface='Ethernet',output_file='tempNetTraffic.pcapng')
	while True:
		capture.sniff(timeout=0)
		for packet in capture.sniff_continuously():
			print(packet)
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
	print("Press Ctrl-C to terminate while statement")
else:
	pass
finally:
	pass

 