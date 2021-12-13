import pyshark


try:
	capture = pyshark.LiveCapture(interface='Ethernet')
	while True:
		capture.sniff(timeout=0)
		for packet in capture.sniff_continuously():
			#f=open("TempNetTraffic.pcapng", "w")
			#f.write(packet)
			print(packet)
			

except Exception as e:
	raise
except KeyboardInterrupt:
	#f.close
	type(capture)
	print("Press Ctrl-C to terminate while statement")
else:
	pass
finally:
	pass

 