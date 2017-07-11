from utils import *

data_path = '../Data/'
default_filter = ""
default_fileName = 'shark_dump_1496654992.pcap'
default_time = 10

class Static_Filter():

    def __init__(self, fileName=default_fileName, filter=default_filter, time=default_time):
        """provide pcap file name, print function, package filter an operation mode"""
        self.fileName = fileName
        self.filter = filter
        self.time = time
        self.cap = self.build_Capture()

    def build_Capture(self):
        """Apply filter to pcap specified by fileName and return."""
        source = self.fileName
        cap = pyshark.FileCapture(source, display_filter=self.filter)
        cap.set_debug()
        return cap

    def show_Basic(self):
        """Print out basic package information specified by conversions"""
        cap = self.cap
        cap.apply_on_packets(print_conversion_package, timeout=100)

    def detect_Device(self):
        """classify devices by their IP address, return dict {ip:[bytes sent, bytes received]}"""
        cap = self.cap
        device_List = detect_device_traffic(cap)
        return device_List

    def detect_Package(self):
        """process captured ip packages to present time delta from previous frame, {ip: [0, delta1, delta2 ...]}"""
        cap = self.cap
        package_Delta = detect_package_delta(cap)
        return package_Delta


if __name__ == "__main__":
    host_ip = get_host_ip()
    filter = Static_Filter(fileName="temporary/temp_pcap_file.pcap")
    packages_delta = filter.detect_Package()