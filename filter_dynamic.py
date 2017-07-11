from utils import *

data_path = '../Data/'
default_filter = ""
default_fileName = 'shark_dump_1496654992.pcap'
default_time = 10
default_pktNum = 2

class Dynamic_Filter():

    def __init__(self, fileName=default_fileName, filter=default_filter, time=default_time, pktNum=default_pktNum):
        """provide pcap file name, print function, package filter an operation mode"""
        self.fileName = fileName
        self.filter = filter
        self.time = time
        self.pktCount = pktNum
        self.ARP_Collection = {}
        self.IP_Collection = {}
        self.APR_Package = {}
        self.IP_Package = {}

    def push_collections(self, pkt):
        protocol = pkt._fields["Protocol"]
        length = int(pkt._fields["Length"])
        time = pkt._fields["Time"]
        source = pkt._fields["Source"]

        if protocol == "ARP":
            if source not in valid_mac:
                return

            if source not in self.ARP_Collection:
                self.ARP_Collection[source] = [[0, time]]
            else:
                frameNo = len(self.ARP_Collection[source])
                self.ARP_Collection[source].append([frameNo, time])

            if source not in self.APR_Package:
                self.APR_Package[source] = [[0, length]]
            else:
                frameNo = len(self.ARP_Collection[source])
                self.APR_Package[source].append([frameNo, length])

        if protocol == "TCP" or protocol == "UDP":
            if source not in valid_ip:
                return

            if source not in self.IP_Collection:
                self.IP_Collection[source] = [[0, time]]
            else:
                frameNo = len(self.IP_Collection[source])
                self.IP_Collection[source].append([frameNo, time])

            if source not in self.IP_Package:
                self.IP_Package[source] = [[0, length]]
            else:
                frameNo = len(self.IP_Package[source])
                self.IP_Package[source].append([frameNo, length])


    def live_Capture(self):
        """
        Generate LiveCapture interface and sniff continuously
        APR_Collection = {src: [delta_time]} / IP_Collection = {src: [delta_time]}
        APR_Package = {src: [pkt_size]} / IP_Package = {src: [pkt_size]}
        """
        cap = pyshark.LiveCapture(interface="eth0", bpf_filter=self.filter, only_summaries=True)
        cap.set_debug()
        cap.sniff(timeout=self.time)
        #cap.sniff(packet_count=self.pktCount)
        for pkt in cap._packets:
            self.push_collections(pkt)

        for src, lists in self.ARP_Collection.iteritems(): #lists = [(frameNo, time)]
            for i in range(len(lists)-1, 0, -1):
                lists[i][1] = float(lists[i][1]) - float(lists[i-1][1])
            lists[0][1] = 0.0

        for src, lists in self.IP_Collection.iteritems():
            for i in range(len(lists) - 1, 0, -1):
                lists[i][1] = float(lists[i][1]) - float(lists[i-1][1])
            lists[0][1] = 0.0

        return [self.ARP_Collection, self.APR_Package, self.IP_Collection, self.IP_Package]

if __name__ == "__main__":
    host_ip = get_host_ip()
    filter = Dynamic_Filter(time=10)
    list = filter.live_Capture()
    print "a"
