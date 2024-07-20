from scapy.all import *
import threading

stop_sniffer = threading.Event()

def start_sniffer(filter_str, update_function):
    def packet_handler(packet):
        if stop_sniffer.is_set():
            return False
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            update_function(f"IP Packet: {ip_src} -> {ip_dst}")
        return True

    stop_sniffer.clear()
    sniff(filter=filter_str, prn=packet_handler, stop_filter=lambda x: stop_sniffer.is_set())

def stop_sniffer_function():
    stop_sniffer.set()
