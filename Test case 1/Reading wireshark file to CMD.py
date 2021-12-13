from pcapng import FileScanner

with open('J:/Wireshark/20212101208.pcapng', 'rb') as fp:
    scanner = FileScanner(fp)
    for block in scanner:
        print(block);