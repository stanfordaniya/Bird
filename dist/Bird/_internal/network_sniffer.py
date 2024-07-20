from scapy.all import *
import threading

stop_sniffer = threading.Event()

def start_sniffer(filter_str, update_function):
    def packet_handler(packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            update_function(f"IP Packet: {ip_src} -> {ip_dst}")
        if stop_sniffer.is_set():
            return

    sniff(filter=filter_str, prn=packet_handler, stop_filter=lambda x: stop_sniffer.is_set())

def stop_sniffer_func():
    stop_sniffer.set()
