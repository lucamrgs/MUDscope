
import json
import subprocess

from mudscope.Constants import *

def generate_mud_config(gw_mac, gw_ip4, gw_ip6, target_mac, target_name, srcpcap):
    mud_config = {
        'defaultGatewayConfig': {
            "macAddress" : gw_mac if gw_mac is not None else "a4:91:b1:1e:57:90",
            "ipAddress": gw_ip4 if gw_ip4 is not None else "192.168.1.1",
            "ipv6Address": gw_ip6 if gw_ip6 is not None else "",
        },
        "deviceConfig":{
            "device": target_mac if target_mac is not None else "00:0c:29:a8:3a:da",
            "deviceName": target_name if target_name is not None else "test_device"
        },
        "pcapLocation": srcpcap #TODO: differentiate for MUD generation (as above)
    }

    with open('last_mud_config.json', 'w') as json_file:
        return json.dump(mud_config, json_file, indent=4)

def run_mudgee(mud_config_file):
    print(">>> DEBUG: MUDgee directory at: {}".format(MUDGEE_FOLDER))
    result = subprocess.call(["java",  "-jar", MUDGEE_FOLDER + "/target/mudgee-1.0.0-SNAPSHOT.jar", mud_config_file])
    print(">>> MUDgee invocation result: {}".format(result))
    return result