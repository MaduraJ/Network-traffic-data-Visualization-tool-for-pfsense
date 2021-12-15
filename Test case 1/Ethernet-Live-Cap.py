import pyshark
import json

try:
	capture = pyshark.LiveCapture(interface='Ethernet')
	while True:
		capture.sniff(timeout=0)
		for packet in capture.sniff_continuously():
			print(packet)
			jsonString=json.dump(packet)
			jsonFile=open("tempNetTraffic.json","w")
			jsonFile.write(jsonString)
			jsonFile.close()
			

except EOFError as e:
    print(e)
except Exception as e:
	e
except KeyboardInterrupt:
	jsonFile.close()
	type(capture)
	print("Press Ctrl-C to terminate while statement")
else:
	pass
finally:
	pass

 