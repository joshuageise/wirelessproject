from killerbee import *
from killerbee.scapy_extensions import *
from scapy.utils import hexdump

import sys

####
#Hard Coded values, change as necessary
global DOOR
global MOTION
####

#Case 1: Populating a pcap with random amount of currences in each phase of the day
#Occurence number can be changed by modifying the randint range
def gen_case1(data, epoch):
    modified = []
    check=0
    
    #Number of packets in the morning
    #Multiplied by two for open/close
    daytime = random.randint(1, 15)*2 
    current = 0

    for p in data:
        rand = random.randint(0, 2)
        p.src_addr=DOOR

        if check==daytime:
            epoch+=21600
            current+=1
            check=0
            if current==1:
                #Number of packets in the afternoon
                #Multiplied by two for open/close
                daytime=random.randint(1,8)*2
            elif current==2:
                #Number of packets in the evening
                #Multiplied by two for open/close
                daytime=random.randint(1,18)*2
            elif current==3:
                #Number of packets during the night
                #Multiplied by two for open/close
                daytime=random.randint(1,5)*2
        
        if current>3:
            break

        p.time = epoch+rand
        epoch += rand
            
        pmod = p
        p.time
        p.src_addr
        modified.append(pmod)
        check+=1

    return modified

#Case 2 Scenario 1: Door Opens --> Motion Detected --> Door Closes
#Gives chance that motion response time will be above threshold
def gen_case2_1(data, epoch):
    modified = []
    alternate=2
    #Designates upper range for randomly generated response time from motion detector
    motion_rand = 4

    for p in data:
        if alternate%2==1:
            p.src_addr=MOTION
            rand = random.randint(0,motion_rand)
        else:
            p.src_addr=DOOR
            rand = random.randint(0, 2)

        p.time = epoch+rand
        epoch += rand
            
        pmod = p
        p.time
        p.src_addr
        modified.append(pmod)

        alternate+=1

    return modified

#Case 2 Scenario 2: Door Opens --> Door Closes --> Motion Detected
#Gives chance that motion response time will be above threshold
def gen_case2_2(data, epoch):
    modified = []
    alternate=1
    
    #Designates upper range for randomly generated response time from motion detector
    motion_rand = 4

    for p in data:
        
        if alternate%3==0:
            p.src_addr=MOTION
            rand = random.randint(0,motion_rand)
        else:
            p.src_addr=DOOR
            rand = random.randint(0, 2)

        p.time = epoch+rand
        epoch += rand
            
        pmod = p
        p.time
        p.src_addr
        modified.append(pmod)

        alternate+=1

    return modified

#Case 2 Scenario 3: Door Opens --> Door Closes --> Motion Never Detected
def gen_case2_3(data, epoch):
    modified = []
    
    for p in data:
        p.src_addr=DOOR
        rand = random.randint(0, 2)

        p.time = epoch+rand
        epoch += rand
            
        pmod = p
        p.time
        p.src_addr
        modified.append(pmod)

    return modified

if __name__ == '__main__':

    DOOR = 13124
    MOTION = 13331

    if len(sys.argv) < 4 or sys.argv[1]=='-h':
        print 'Please enter case number, base pcap file, and output pcap file'
        print 'Example: python '+sys.argv[0]+' 1 in.pcap out.pcap'
        print 'Case1: 1, Case2(1): 2, Case2(2): 3, Case2(3): 4'
        sys.exit()
    
    #Modify epoch to change base date/time
    epoch = 1576668628
    data = kbrdpcap(sys.argv[2])

    if sys.argv[1] == '1':
        modified = gen_case1(data, epoch)
    elif sys.argv[1] == '2':
        modified = gen_case2_1(data, epoch)
    elif sys.argv[1] == '3':
        modified = gen_case2_2(data, epoch)
    elif sys.argv[1]== '4':
        modified = gen_case2_3(data, epoch)
    else:
        print 'Incorrect case entered, please try again'
        print 'Pass in no arguments or -h to learn more'
        sys.exit()

    wrpcap(sys.argv[3],modified)
    
    
