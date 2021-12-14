import pyshark
try:
	capture=pyshark.RemoteCapture("192.168.1.10","wifi")
	while True:
		capture.sniff(timeout=0)
		for packet in capture.sniff_continuously():
			print(packet)
except Exception as e:
	raise
else:
	pass
finally:
	pass
