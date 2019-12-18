from scapy.all import rdpcap

pkts_list = rdpcap('default.pcap')

print(pkts_list[3])


