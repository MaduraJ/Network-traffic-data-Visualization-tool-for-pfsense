
import pyshark

capture = pyshark.LiveCapture(interface='Ethernet')
while True:
	capture.sniff(timeout=1)
	for packet in capture.sniff_continuously():
		print(packet)

 