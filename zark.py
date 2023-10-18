from scapy.all import *
import socket
import datetime
from colorama import init, Fore
import pyfiglet
import os
init(autoreset=True)
llllIIIlIIIllll = pyfiglet.Figlet()
llIIIIIlIlll = input("Do you want to log network traffic to a file? (y/n): ").strip().lower()
if llIIIIIlIlll == "y":
    IIIIIIlIIIIlIllIlI = input("Enter your log file:")
    if not os.path.exists(IIIIIIlIIIIlIllIlI):
        with open(IIIIIIlIIIIlIllIlI, "w"):
            pass
else:
    IIIIIIlIIIIlIllIlI = None
def IIIllIIIllIIIIlII(IlIlllIIIlll):
    if IIIIIIlIIIIlIllIlI:
        with open(IIIIIIlIIIIlIllIlI, "a") as lIIlIIllIllllIllI:
            lIIlIIllIllllIllI.write(IlIlllIIIlll + "\n")
def IIIIIllllI(IlIlllIl):
    IlllllllllIIIIlIl = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if IlIlllIl.haslayer(IP):
        lIIllIllIIlIIIlIIl = IlIlllIl[IP]
        if socket.gethostbyname(socket.gethostname()) == lIIllIllIIlIIIlIIl.dst:
            llllIlIIll = Fore.LIGHTGREEN_EX + "Incoming" + Fore.RESET
        elif socket.gethostbyname(socket.gethostname()) == lIIllIllIIlIIIlIIl.src:
            llllIlIIll = Fore.LIGHTBLUE_EX + "Outgoing" + Fore.RESET
        else:
            llllIlIIll = Fore.LIGHTYELLOW_EX + "Unknown" + Fore.RESET
        IIlIlIlIIIlIll = IlIlllIl.src
        llIIIllllllIlIllIllI = IlIlllIl.dst
        lIlIllIII = len(IlIlllIl)
        llllIIllllIlIlIlIIll = lIIllIllIIlIIIlIIl.proto
        if IlIlllIl.haslayer(TCP):
            lIllIlIlIllIlIlIIl = "TCP"
        elif IlIlllIl.haslayer(UDP):
            lIllIlIlIllIlIlIIl = "UDP"
        else:
            lIllIlIlIllIlIlIIl = "Other"
        IlIlllIIIlll = (
            lIIlIIllIllllIllI"{Fore.CYAN}Timestamp: {IlllllllllIIIIlIl}\n"
            lIIlIIllIllllIllI"Direction: {llllIlIIll}\n"
            lIIlIIllIllllIllI"Source IP: {Fore.LIGHTCYAN_EX}{lIIllIllIIlIIIlIIl.src}{Fore.RESET}\n"
            lIIlIIllIllllIllI"Destination IP: {Fore.LIGHTCYAN_EX}{lIIllIllIIlIIIlIIl.dst}{Fore.RESET}\n"
            lIIlIIllIllllIllI"Source MAC: {Fore.LIGHTMAGENTA_EX}{IIlIlIlIIIlIll}{Fore.RESET}\n"
            lIIlIIllIllllIllI"Destination MAC: {Fore.LIGHTMAGENTA_EX}{llIIIllllllIlIllIllI}{Fore.RESET}\n"
            lIIlIIllIllllIllI"Packet Size: {Fore.LIGHTMAGENTA_EX}{lIlIllIII} bytes{Fore.RESET}\n"
            lIIlIIllIllllIllI"Protocol: {Fore.LIGHTMAGENTA_EX}{llllIIllllIlIlIlIIll_name}{Fore.RESET}\n"
        )
        return IlIlllIIIlll
def IllIlIIllIIIlIIllIl(IlIlllIl):
    IlIlllIIIlll = IIIIIllllI(IlIlllIl)
    if IlIlllIIIlll:
        IIIllIIIllIIIIlII(IlIlllIIIlll)
        print(IlIlllIIIlll)
        print("-" * 60)  
if __name__ == '__main__':
    lIIIlIIIl = llllIIIlIIIllll.renderText("zark")
    print(Fore.RED + "Author:            Zaw Wanz" + Fore.RESET)
    print(Fore.MAGENTA + lIIIlIIIl + Fore.RESET)
    print("Network Monitoring Started. Press Ctrl+C to stop.")
    try:
        sniff(prn=IllIlIIllIIIlIIllIl)
    except KeyboardInterrupt:
        print("Network Monitoring Stopped.")
