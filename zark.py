#!/usr/bin/python

from scapy.all import *
import socket
import datetime
from colorama import init, Fore
import pyfiglet
import os

init(autoreset=True)
figlet = pyfiglet.Figlet()

log_choice = input("Do you want to log network traffic to a file? (y/n): ").strip().lower()

if log_choice == "y":
    log_file = input("Enter your log file:")
    if not os.path.exists(log_file):
        with open(log_file, "w"):
            pass
else:
    log_file = None

def log_packet(packet_info):
    if log_file:
        with open(log_file, "a") as f:
            f.write(packet_info + "\n")

def format_packet_info(pkt):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if pkt.haslayer(IP):
        ip_packet = pkt[IP]
        
        if socket.gethostbyname(socket.gethostname()) == ip_packet.dst:
            direction = Fore.LIGHTGREEN_EX + "Incoming" + Fore.RESET
        elif socket.gethostbyname(socket.gethostname()) == ip_packet.src:
            direction = Fore.LIGHTBLUE_EX + "Outgoing" + Fore.RESET
        else:
            direction = Fore.LIGHTYELLOW_EX + "Unknown" + Fore.RESET
        
        mac_src = pkt.src
        mac_dst = pkt.dst
        packet_size = len(pkt)
        protocol = ip_packet.proto
        
        if pkt.haslayer(TCP):
            protocol_name = "TCP"
        elif pkt.haslayer(UDP):
            protocol_name = "UDP"
        else:
            protocol_name = "Other"
        
        packet_info = (
            f"{Fore.CYAN}Timestamp: {timestamp}\n"
            f"Direction: {direction}\n"
            f"Source IP: {Fore.LIGHTCYAN_EX}{ip_packet.src}{Fore.RESET}\n"
            f"Destination IP: {Fore.LIGHTCYAN_EX}{ip_packet.dst}{Fore.RESET}\n"
            f"Source MAC: {Fore.LIGHTMAGENTA_EX}{mac_src}{Fore.RESET}\n"
            f"Destination MAC: {Fore.LIGHTMAGENTA_EX}{mac_dst}{Fore.RESET}\n"
            f"Packet Size: {Fore.LIGHTMAGENTA_EX}{packet_size} bytes{Fore.RESET}\n"
            f"Protocol: {Fore.LIGHTMAGENTA_EX}{protocol_name}{Fore.RESET}\n"
        )
        return packet_info

def network_monitoring(pkt):
    packet_info = format_packet_info(pkt)
    
    if packet_info:
        log_packet(packet_info)
        print(packet_info)
        print("-" * 60)  

if __name__ == '__main__':
    banner = figlet.renderText("zark")
    print(Fore.RED + "Author:            Aether" + Fore.RESET)
    print(Fore.MAGENTA + banner + Fore.RESET)
    print("Network Monitoring Started. Press Ctrl+C to stop.")
    try:
        sniff(prn=network_monitoring)
    except KeyboardInterrupt:
        print("Network Monitoring Stopped.")
#If you see my Ex.Please tell that ("Zaw Wanz will always love you 'Shwe'")
