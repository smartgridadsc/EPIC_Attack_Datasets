

from scapy.all import *

def check_mms( pckt, storeRequestContent = True ):
        #the return means  is correct mms, invokedid, is request type, only hwen invoikedid >=0  then other returns r valid
        eot = True
        result = {"isvalid": False, "isrequest": False, "invokeid": None, "querykey": None,"datafield": None,"isfragment" : False}
        print("check_mms")
        if pckt.haslayer(Raw) == False:
            return result
        rawdata = bytes(pckt["Raw"])
        rawdata_len = len(rawdata)
        #hexdump(rawdata)
        
        tempdata = bytearray([0x00, 0x00])
        tempdata[0] = rawdata[2]
        tempdata[1] = rawdata[3] #3
        #print(tempdata[0])
        #print(tempdata[1])
        tpkt_len = struct.unpack('>H', tempdata)[0]
        #print("=====> rawdata_len: " + str(rawdata_len) + "   tpkt_len  " + str(tpkt_len) )
        #print(rawdata[4])
        #hexdump(rawdata[6])

        print("check 8073, iso8073_len is " )
        print(rawdata[4])
        if hex(rawdata[4]) != '0x2':
           return result

        print("Eot check")
        #hexdump(rawdata[6])
        eot_int = rawdata[6]
        print("Eot check  " + str(eot_int))
        if eot_int & 128 != 0 :
          print("Eot check true ")
          eot = True
        else:
          print("Eot check false ")
          eot = False
          result["isfragment"]  = True
          return result # need to change to true
        if eot == True: # only packeet that eot = 0
          print("iso83237_spdu_type, iso83237_spdu_len,iso83237_1spdu_type,iso83237_1spdu_len:")
          #print(rawdata[7], rawdata[8], rawdata[9], rawdata[10])
          if hex(rawdata[7]) != '0x1' or hex(rawdata[8]) != '0x0' or hex(rawdata[9]) != '0x1' or hex(rawdata[10]) != '0x0':
             print ("iso83237 and iso83237_1 has issue")
             result["isfragment"]  = True
             return result # need to change to true
          print("check cpc-type PPDU part")
          offset = 0
          mms_invoke_len = 1
          after_invokeid_index = 0
          if  tpkt_len < 140:
              print( " check for short packt <140B")
              if hex(rawdata[11]) != '0x61':
                  print("not 0x61")
                  return result

              if hex(rawdata[13]) != '0x30':
                  print("not 0x30")
                  return result

              if hex(rawdata[17]) != '0x3':
                  print("not 0x03")
                  return result
              if hex(rawdata[18]) != '0xa0': #a0
                  print("not 0xa0")
                  return result
              if hex(rawdata[20]) == '0xa0':
                 print ("#a0 request")
                 result["isrequest"] = True
              else:
                 print ("#a1 response")
                 result["isrequest"]  = False


              mms_invoke_len = rawdata[23]
              #if it is response, i will store all the rawdata
              offset = 24
          else:
              print( " check for short packt >=140B")
              offset = 11
              if hex(rawdata[offset]) != '0x61':
                 print("not 0x61")
                 return result
              offset+=1
              if hex(rawdata[offset]) == '0x81':
                 offset +=2
              elif hex(rawdata[offset]) == '0x82':
                 offset +=3

              if hex(rawdata[offset]) != '0x30':
                 print("not 0x30")
                 return result
              offset+=1
              if hex(rawdata[offset]) == '0x81':
                 offset +=4
              elif hex(rawdata[offset]) == '0x82':
                 offset +=5

              if hex(rawdata[offset]) != '0x3':
                 print ("iso83237 and iso8823 has issue")
                 isfragment  = True
                 return result# need to change to true
              offset+=1
              if hex(rawdata[offset]) != '0xa0': #a0
                 print("not 0xa0")
                 return result
              offset+=1
              if hex(rawdata[offset]) == '0x81':
                 offset +=2
              elif hex(rawdata[offset]) == '0x82':
                 offset +=3
              print ("check request or response")
              if hex(rawdata[offset]) == '0xa0':
                 print ("#a0 request")
                 result["isrequest"] = True
              else:
                 print ("#a1 response")
                 result["isrequest"]  = False
              offset+=1
              if hex(rawdata[offset]) == '0x81':
                 offset +=3
              elif hex(rawdata[offset]) == '0x82':
                 offset +=4
              mms_invoke_len = orb(rawdata[offset])
              offset += 1

          if mms_invoke_len == 1:
             print ("mms_invoke_len == 1")
             result["invokeid"] = orb(rawdata[offset])
             offset +=1
          elif  mms_invoke_len == 2:
             print ("mms_invoke_len == 2")
             tempdata[0] = rawdata[offset]
             tempdata[1] = rawdata[offset+1]
             result["invokeid"] = struct.unpack('>H', tempdata)[0]
             offset +=2
          elif mms_invoke_len == 3:
             print ("mms_invoke_len == 3")
             result["invokeid"] = (((orb(rawdata[offset]) & 0xFF)<<16) | ((orb(rawdata[offset+1]) & 0xFF) << 8) | ((orb(rawdata[offset+2]) & 0xFF) << 0))
             offset +=3
          after_invokeid_index = offset
          result["isvalid"]  = True
          #hexdump(rawdata)

          result["after_invokeid_index"] = after_invokeid_index
          
          if result["isrequest"] ==True:

              if rawdata_len > tpkt_len :
                  result["querykey"] = rawdata[rawdata_len - 19:rawdata_len]
              else:
                  result["querykey"] = rawdata[rawdata_len - 19:]

              if storeRequestContent == True:
                  if rawdata_len > tpkt_len:
                      result["datafield"] = rawdata[after_invokeid_index:rawdata_len - 1]
                  else:
                      result["datafield"] = rawdata[after_invokeid_index:rawdata_len]

          else: # for response i only save the parket after mms pdu invokeid
          
          
              if rawdata_len >tpkt_len :
                   result["datafield"] = rawdata[after_invokeid_index:rawdata_len -1]
              else:
                   result["datafield"] = rawdata[after_invokeid_index:rawdata_len]
          print("mms_invoke_len is " + str(mms_invoke_len)+" invokeid is " + str(result["invokeid"]))
          #hexdump(result["datafield"])

        return result

