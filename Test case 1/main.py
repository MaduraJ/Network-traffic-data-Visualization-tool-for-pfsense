import Ethernet_Live_Cap, threading,gc ,re


if __name__ == '__main__':
	SpamANDTorNodeBlock=Ethernet_Live_Cap.TrafficCapture("Ethernet")
	TestThread=threading.Thread(target=SpamANDTorNodeBlock.Capture)
	gc.enable()
	TestThread.start()


