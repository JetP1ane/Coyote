# coding=utf-8

import time
import socket
import subprocess
from scapy.all import *


class Autoconf :

	def __init__(self):
		self.hostmac = ""
		self.hostip = ""
		self.conf = True
		self.ifaceHost = "eth0"
		# Commented as to only bind and listen to the host interface
		self.ifaceNetwork = "eth1"
		self.sockHost = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
		self.sockNetwork = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))


	def flipNic(self):
		print("Restarting Interface to initiate EAPOL negotiation...")
		subprocess.run(["ifconfig", "eth0", "down"])
		time.sleep(15)
		subprocess.run(["ifconfig", "eth0", "up"])
		time.sleep(15)
		print("Network Interfaces restarted")


	def startAutoconf(self):

		self.flipNic()		# Disable/Enable Nic to restart host 802.1x negotiation

		try:
			self.sockHost.bind((self.ifaceHost, 0))
			self.sockNetwork.bind((self.ifaceNetwork, 0))
		except:
			print("You need 2 physical network interfaces to use Coyote !")
		self.inputs = [self.sockHost]

		print("Trying to detect @mac and @ip of spoofed host...")
		while self.conf == True :
			print('Listening on Host NIC...')
			try:
				inputready,outputready,exceptready = select.select(self.inputs, [], [])
			except select.error as e:
				break
			except socket.error as e:
				break
			for socketReady in inputready :
					#We check packets from iface1 and fwd them to iface2
					if socketReady == self.sockHost :
						packet = self.sockHost.recvfrom(1500)
						pkt = packet[0]
						dpkt = Ether(packet[0])
						if 'ARP' in dpkt :
							print('ETH-Frame: ' + dpkt[Ether].src)
							self.hostmac = dpkt[Ether].src
						elif 'IP' in dpkt :
							print('IP-Pak: ' + dpkt[Ether].src)
							self.hostip = dpkt[IP].src
							self.hostmac = dpkt[Ether].src
						#We send the packet to the other interface
						self.sockNetwork.send(pkt)
					#We forward packet from iface2 to iface1
					if socketReady == self.sockNetwork :
						packet = self.sockNetwork.recvfrom(1500)
						pkt = packet[0]
						self.sockHost.send(pkt)
			if self.hostip and self.hostmac and self.hostip != "0.0.0.0" and self.hostmac != "ff:ff:ff:ff:ff":
				self.conf = False
				print('MAC:: ' + self.hostmac)
				return self.hostip, self.hostmac
