
"""
    TODO: Documentation
"""

import sys
import argparse
import json
import os
from pathlib import Path

cwd = os.getcwd()
sys.path.insert(1, cwd + '/src')
from Constants import *


def is_valid_path(path, check_dir=True, check_file=True):
    if check_dir and check_file:
        return os.path.isfile(path) or os.path.isdir(path)
    if check_dir and not check_file:
        return os.path.isdir(path)
    if check_file and not check_dir:
        return os.path.isfile(path)
    return False


def module_main(arguments=None):

    parser = argparse.ArgumentParser(description='TBD')


    parser.add_argument('--devname', help='Name of the device referred for MRT generation and overall pipeline.', required=True)
    parser.add_argument('--dev_mac', help='MAC address of device', required=True)
    
    parser.add_argument('--gw_mac', help='MAC address of default gateway', required=True)
    parser.add_argument('--gw_ip4', help='IPv4 address of default gateway.', required=True)
    parser.add_argument('--gw_ip6', help='IPv6 address of default gateway.', required=False)

    parser.add_argument('--tgt_dir', help='Full path to directory containing PCAPs to MRT-ize', required=True)
    
    args = parser.parse_args(arguments)

    devname = args.devname
    devmac = args.dev_mac

    gwmac = args.gw_mac
    gwip4 = args.gw_ip4
    gwip6 = args.gw_ip6 if args.gw_ip6 is not None else '-'

    tgtdir = args.tgt_dir
    
    if not is_valid_path(tgtdir, check_file=False):
        raise ValueError(f">>> ERROR: Invalid path to dir for reject_config: {tgtdir}. Exiting.")
    
    rjt_conf_dir = REJECT_CONFIGS_FOLDER + devname + '/'
    Path(rjt_conf_dir).mkdir(parents=True, exist_ok=True)
    
    tgt = os.fsencode(tgtdir)
    for file in os.listdir(tgt):
        fname = os.fsdecode(file)
        if fname.endswith('.pcap'):
            file = os.fsdecode(tgtdir) + fname if os.fsdecode(tgtdir).endswith('/') else os.fsdecode(tgtdir) + '/' + fname
            config_json = {
                "defaultGatewayConfig": {
                    "macAddress": gwmac,
                    "ipAddress": gwip4,
                    "ipv6Address": gwip6
                },
                "deviceConfig": {
                    "device": devmac,
                    "deviceName": devname
                },
                "filterPcapLocation": file
            }
            
            rjt_conf_name = 'rjt_' + devname + '_' + fname + '.json'
            rjt_conf_path = rjt_conf_dir + rjt_conf_name
            
            print(f'>>> DEBUG: {rjt_conf_path}')
            with open(rjt_conf_path, 'w') as outfile:
                json.dump(config_json, outfile, indent=4)

if __name__ == '__main__':
    module_main()
    sys.exit(0)