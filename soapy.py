import socket
import struct
import binascii
import time

MCAST_GRP = '224.0.0.252'
MCAST_PORT = 3702

send_ip = '239.255.255.250'
malip = '127.0.0.1'
port = 3702

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('127.0.0.1', 64444))  # use MCAST_GRP instead of '' to listen only to MCAST_GRP, not all groups on MCAST_PORT
mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


aaa = '''<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof" xmlns:pub="http://schemas.microsoft.com/windows/pub/2005/07"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</wsa:Action><wsa:MessageID>urn:uuid:b1233b21-ebf7-45d8-9432-24b2fd819322</wsa:MessageID><wsd:AppSequence InstanceId="69" SequenceId="urn:uuid:cab4893b-9c5d-4638-a9b4-bfc3bdf57e34" MessageNumber="1"></wsd:AppSequence></soap:Header><soap:Body><wsd:Hello><wsa:EndpointReference><wsa:Address>urn:uuid:efd10641-9f23-4fd3-98a4-02c3d2b28e66</wsa:Address></wsa:EndpointReference><wsd:Types>wsdp:Device pub:Computer</wsd:Types><wsd:XAddrs>http://127.0.0.1:5358/efd10641-9f23-4fd3-98a4-02c3d2b28e66/</wsd:XAddrs><wsd:MetadataVersion>1</wsd:MetadataVersion></wsd:Hello></soap:Body></soap:Envelope>'''

aa = '''<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>urn:uuid:b1233b21-ebf7-45d8-9432-24b2fd819322</wsa:MessageID></soap:Header><soap:Body><wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe></soap:Body></soap:Envelope>'''


while True:
	time.sleep(1)
	ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.sendto(aa, (send_ip, port))
	sock.sendto(aaa, (send_ip, port))
