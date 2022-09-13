
import json
import subprocess

from mudscope.Constants import *

def generate_mud_config(
        gw_mac = "a4:91:b1:1e:57:90",
        gw_ip4 = "192.168.1.1",
        gw_ip6 = "",
        target_mac = "00:0c:29:a8:3a:da",
        target_name = "test_device",
        srcpcap = "",
    ):
    mud_config = {
        'defaultGatewayConfig': {
            "macAddress" : gw_mac,
            "ipAddress": gw_ip4,
            "ipv6Address": gw_ip6,
        },
        "deviceConfig":{
            "device": target_mac,
            "deviceName": target_name,
        },
        "pcapLocation": srcpcap,
    }

    with open('last_mud_config.json', 'w') as json_file:
        return json.dump(mud_config, json_file, indent=4)

def run_mudgee(mud_config_file):
    print(">>> DEBUG: MUDgee directory at: {}".format(MUDGEE_FOLDER))
    result = subprocess.call(["java",  "-jar", MUDGEE_FOLDER + "/target/mudgee-1.0.0-SNAPSHOT.jar", mud_config_file])
    print(">>> MUDgee invocation result: {}".format(result))
    return result