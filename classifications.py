from killerbee import *
from killerbee.scapy_extensions import *
from scapy.utils import hexdump

import dpkt
import time
import numpy
import sys

global DOOR
global MOTION

global M_THRESH
global A_THRESH
global E_THRESH
global N_THRESH

def initialize_phasetimes():
    DOOR = 13124
    MOTION = 13331

def get_timesection(hour):
    #Modify these variables to change phase time allocations
    morning_start = 5
    morning_end = 9
    afternoon_start = 10
    afternoon_end = 15
    evening_start = 16
    evening_end = 21
    night_start = 22
    night_end = 4

    if hour >= morning_start and hour <= morning_end:
        return 'M'
    elif hour >= afternoon_start and hour <= afternoon_end:
        return 'A'
    elif hour >= evening_start and hour <= evening_end:
        return 'E'
    elif (hour >= night_start and hour <= 23) or (hour >= 0 and hour<= night_end):
        return 'N' 

def get_hour(epoch):
    return int(time.strftime('%H', time.localtime(epoch)))

def case_1(filename):
    
    data = kbrdpcap(filename)

    time_dict = {
        'M': 0, 
        'A': 0, 
        'E': 0, 
        'N': 0
    }

    times = get_times(filename)

    index = 0
    for p in data:
        if p.src_addr == DOOR:
            timesection = get_timesection(get_hour(times[index]))
            time_dict[timesection]=time_dict[timesection]+1
           
        index+=1

    errors = []

    if time_dict['M'] > M_THRESH:
        errors.append('Anamoly Detected: Morning Alerts exceeded threshold')
    
    if time_dict['A'] > A_THRESH:
        errors.append('Anamoly Detected:Afternoon Alerts exceeded threshold')

    if time_dict['E'] > E_THRESH:
        errors.append('Anamoly Detected: Evening Alerts exceeded threshold')

    if time_dict['N'] > N_THRESH:
        errors.append('Anamoly Detected: Night Alerts exceeded threshold')

    if not errors:
        errors.append('No Anomalies Found')

    return time_dict, errors

def get_times(filename):
    times = []
    with open(filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        for ts, buf in pcap:
            times.append(ts)

    return times

def case_2(filename):
    times = get_times(filename)
    data = kbrdpcap(filename)
    errors = []    
    DOOR_count = 0 
    tmp = None
    tmpIndex = None
    index = 0
    isDoor = False
    isMotion = False

    for p in data:  
        if p.src_addr == DOOR:
            isDoor = True
            isMotion = False
            if DOOR_count == 0:
                tmp = p
                tmpIndex = index
            DOOR_count+=1
        elif p.src_addr == MOTION:
            isDoor = False
            isMotion = True

            if DOOR_count > 0:
                time_diff = times[index] - times[tmpIndex]

                if time_diff >= 3:
                    errors.append('Anomaly Detected: Time between DOOR open and MOTION is '+str(time_diff)+' seconds')
                 
            DOOR_count=0
            tmp = None
            tmpIndex = None

        if DOOR_count > 2:
            errors.append('MOTION Sensor never activated')
            DOOR_count = 0
        
        index +=1

    if not errors:
        errors.append('No Anomalies Found')
    
    return errors

def calc_threshold(dataset):
        mean = numpy.mean(dataset)

        stdev = numpy.std(dataset)

        return mean + (stdev*2)

def train_case1(pcaps):
    thresh_dict = {
        'M': 0, 
        'A': 0, 
        'E': 0, 
        'N': 0
    }

    #Initialize Arrays
    morning = []
    afternoon = []
    evening = []
    night = []

    for pcap in pcaps:
        time_results, anomalies = case_1(pcap)

        #Append results to appropriate array
        morning.append(time_results['M'])
        afternoon.append(time_results['A'])
        evening.append(time_results['E'])
        night.append(time_results['N'])

    #Calculate Thresholds
    thresh_dict['M']=calc_threshold(morning)
    thresh_dict['A']=calc_threshold(afternoon)
    thresh_dict['E']=calc_threshold(evening)
    thresh_dict['N']=calc_threshold(night)

    return thresh_dict
    
def help():
    print 'Options Structure: '+sys.argv[0]+' [Hunt or Train] [Case #] [pcap for hunting] [all pcaps for training data]'
    print 'Options: --hunt or --train , 1 or 2, a single pcap for hunt or any number of pcaps for training'
    print 'Example 1: python '+sys.argv[0]+' --hunt 1 hunt.pcap'
    print 'Example 2: python '+sys.argv[0]+' --train 1 one.pcap two.pcap three.pcap ... x.pcap'    
    sys.exit()

if __name__ == '__main__':

    #Define Global Variables
    DOOR = 13124
    MOTION = 13331 
    M_THRESH = 24.2640520362
    A_THRESH = 12.437902833
    E_THRESH = 30.654316751
    N_THRESH = 7.2189514165

    if len(sys.argv) == 1 or sys.argv[1]=='-h':
        help()
    elif len(sys.argv) >= 4 and sys.argv[1]=='--train':

        if sys.argv[2]=='1':
            pcaps = []
            for pcap in range(3, len(sys.argv)):
                pcaps.append(sys.argv[pcap])

            print train_case1(pcaps)

        elif sys.argv[2]=='2':
            print 'This feature is not supported yet'
        else:
            help()
        
    elif len(sys.argv) >= 4 and sys.argv[1]=='--hunt':
        if sys.argv[2]=='1':
            time_results, errors = case_1(sys.argv[3])
            for x in errors:
                print(x)
        elif sys.argv[2]=='2':
            errors = case_2(sys.argv[3])            
            for x in errors:
                print(x)
        else:
            help()

    else:
        help()
    

    
