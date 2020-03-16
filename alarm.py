# Andrew Crofts
# Incident scanner alarm
# This program takes in internet traffic and outputs a warning if certain incidents occur

#!/usr/bin/python3

from scapy.all import *
import pcapy
import argparse
import base64

global num_incidents
num_incidents = 0
global incident
incident = False
global uname
uname = " "
def packetcallback(packet):
        global num_incidents
        global incident
        global uname
        try:
            if packet[TCP]:
                payload = packet[TCP].load.decode('utf-8')
                # check for XMAS scan
                if packet[TCP].flags.FPU:
                    incidenttype = "XMAS scan"
                    incident = True
                    num_incidents = num_incidents + 1
                    pro_port = "TCP"
                # check for FIN scan
                elif packet[TCP].flags.F:
                    incidenttype = "FIN scan"
                    incident = True
                    num_incidents = num_incidents + 1
                    pro_port = "TCP"
                # check for RDP scan
                elif packet [TCP].dport == 3389:
                    incidenttype = "RDP scan"
                    incident = True
                    num_incidents = num_incidents + 1
                    pro_port = "3389"
                # check for null scan
                elif not packet[TCP].flags:
                    incidenttype = "NULL scan"
                    incident = True
                    num_incidents = num_incidents + 1
                    pro_port = "TCP"
                elif ("Nikto" in payload):
                    incidenttype = "Nikto scan"
                    incident = True
                    num_incidents = num_incidents + 1
                    pro_port = "TCP"
                elif (packet[TCP].dport == 21):
                    if("USER" in payload):
                        uname = payload.split("USER")[1].strip()
                    if ("PASS" in payload):
                        num_incidents  = num_incidents + 1
                        password = payload.split("PASS")[1].strip()
                        topr = "ALERT " + "#" + str(num_incidents) + ": Usernames and passwords sent in-the-clear (FTP) (username:" + str(uname) + ", password:" + str(password) + ")"
                        print(topr)
                if ("Authorization: Basic" in payload):
                        incidenttype = "pass"
                        index = payload.find("Authorization: Basic")
                        index = index + 21
                        encoded = payload[index:]
                        decoded = base64.b64decode(encoded)
                        decoded = decoded.decode('ascii')
                        splitindex = decoded.find(":")
                        user = decoded[:splitindex]
                        password = decoded[(splitindex + 1):]
                        num_incidents = num_incidents + 1
                        to_pr = "ALERT " + "#" + str(num_incidents) + ": Usernames and passwords sent in-the-clear (HTTP) username:" + str(user) + ", password:" + str(password)
                        print(to_pr)
                        user = ""
                        password = ""
            if incident:
                ip = str(packet[IP].src)
                to_print = "ALERT " + "#" + str(num_incidents) + ": " + incidenttype + " is detected from " + str(ip) + " (" + pro_port + ")!"
                print(to_print) 
                incident = False
        except:
                pass
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except pcapy.PcapError:
    print("Sorry, error opening network interface %(interface)s. It does not exist." % {"interface" : args.interface})
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
