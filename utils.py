import socket
import pyshark
import os
import numpy as np

valid_ip = ["192.168.1.2", "192.168.1.4", "192.168.1.6", "192.168.1.136"]
valid_mac = ["30:20:10:fb:7c:05", "50:c7:bf:24:c3:f0", "b0:c5:54:2d:c5:09"]

def get_host_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    host_ip = s.getsockname()[0]
    s.close()
    return host_ip

def print_dns_info(pkt):
    """"Print DNS information"""
    if pkt.dns.qry_name:
        print 'DNS Request from %s: %s' % (pkt.ip.src, pkt.dns.qry_name)
    elif pkt.dns.resp_name:
        print 'DNS Response from %s: %s' % (pkt.ip.src, pkt.dns.resp_name)

def print_conversation_header(pkt):
    """Print basic package src ip -> des ip information"""
    try:
        protocol =  pkt.transport_layer
        src_addr = pkt.ip.src
        src_port = pkt[pkt.transport_layer].srcport
        dst_addr = pkt.ip.dst
        dst_port = pkt[pkt.transport_layer].dstport
        print '%s  %s:%s --> %s:%s' % (protocol, src_addr, src_port, dst_addr, dst_port)
    except AttributeError as e:
        #ignore packets that aren't TCP/UDP or IPv4
        pass

def print_conversion_package(pkt):
    """Print basic package src ip -> des ip & size information"""
    try:
        protocol = pkt.transport_layer
        src_addr = pkt.ip.src
        src_port = pkt[pkt.transport_layer].srcport
        dst_addr = pkt.ip.dst
        dst_port = pkt[pkt.transport_layer].dstport
        pkt_size = pkt.ip.len
        print '%s  %s:%s --> %s:%s %sbyte' % (protocol, src_addr, src_port, dst_addr, dst_port, pkt_size)
    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass

def detect_device_traffic(cap):
    """Detect current active devices and their sent out ip package size"""
    device_List = {}  # list of existing devices
    for pkt in cap:
        try:
            src_addr = str(pkt.ip.src)
            if not src_addr in valid_ip:
                continue
            pkt_size = int(pkt.ip.len)
            pkt_time = float(pkt.sniff_timestamp)
            if src_addr in device_List:
                device_List[src_addr].append((pkt_time, pkt_size))
            else:
                device_List[src_addr] = [(pkt_time, pkt_size)]
        except AttributeError as e:
            # ignore packets that aren't TCP/UDP or IPv4
            pass
    return device_List

def detect_package_delta(cap):
    """Base on captured ip packages, generate delta info list"""
    delta_list = {} #ip_addr serves as key
    for pkt in cap:
        try:
            src_addr = str(pkt.ip.src)
            if not src_addr in valid_ip:
                continue
            timestamp = pkt.sniff_time
            if src_addr in delta_list:
                delta_list[src_addr].append(timestamp)
            else:
                delta_list[src_addr] = [timestamp]
        except AttributeError as e:
            # ignore packets that aren't TCP/UDP or IPv4
            pass

    for ip_addr, timeobjs in delta_list.iteritems():
        start_time = timeobjs[0]
        for i in range(1, len(timeobjs)):
            elapse_time = timeobjs[i] - start_time
            timeobjs[i] = elapse_time.seconds
        timeobjs[0] = 0
    return delta_list


if __name__ == "__main__":
    print get_host_ip()
