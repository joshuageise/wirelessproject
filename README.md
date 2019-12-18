# wirelessproject

#Dependencies

Killerbee:
https://github.com/riverloopsec/killerbee

Dpkt:
pip install dpkt

#Classifiers.py Help

Options Structure: classifications.py [Hunt or Train] [Case #] [pcap for hunting] [all pcaps for training data]
Options: --hunt or --train , 1 or 2, a single pcap for hunt or any number of pcaps for training
Example 1: python classifications.py --hunt 1 hunt.pcap
Example 2: python classifications.py --train 1 one.pcap two.pcap three.pcap ... x.pcap

#gen_zbpcap.py Help

Please enter case number, base pcap file, and output pcap file
Example: python gen_zbpcap.py 1 in.pcap out.pcap
Case1: 1, Case2(1): 2, Case2(2): 3, Case2(3): 4
