
"""
    Requisites for this script are:
        - Parametric on an IP address / IP range
        - Time-constrained if possible

        - Ultimately, it has to implement an automated procedure (experiment)

    Multiple scanning techniques can be tested, integrating more than one tool/library.
    Some quick links:

        - Nmap: https://nmap.org/book/man.html 
        - Masscan: https://github.com/robertdavidgraham/masscan

    NMAP NOTE: 
        1. (auto) Host discovery: https://nmap.org/book/man-host-discovery.html
            - Ping types and ports:
                -Pn skips host discovery
                -PS <ports> uses TCP SYN ping
                -PA <ports> uses TCP ACK ping
                -PU <ports> uses UDP ping
                -n specifies NO DNS resolution

        2. Port scanning types 
            - Scanning techniques
                -sS tcp syn
                -sU udp
                -sT tcp syn that does not require root privileges, as it issues actual connections to the hosts (and does not fabricate raw pkts)
                -sn specifies to NOT PERFORM port scanning
                -p <ports> to specify ports

        3. Targeted recognaissance
            -sV enables service detection for found ports
            -O enables OS detecion https://nmap.org/book/man-os-detection.html

        4. VULNERABILITY SCANNING WITH NSE could be a good test case

        5. FIREWALL EVASION:
            - https://nmap.org/book/man-bypass-firewalls-ids.html

        6. Troubleshooting?
            --send-eth (??)

    MASSCAN NOTE:
        Can be used to perform wide-generic scans and see if they are captured
"""

"""
    TODO:
        - basically an nmap wrapper
        - Provide experiments-specific macros

        - Abstracts parameters to call functions types (e.g., host_discovery_only(), syn_scan(), udp_scan())
            Interface top down:
                PARAMS: ip/subnet
                * host discovery only on subnet
                
                PARAMS: ip/subnet, host discovery, aggressivity, top ports number, service detection, OS detection
                * tcp syn scan 
                * udp scan 
                
                * vulnerability scanning 
                    https://ethr.medium.com/how-to-install-nmap-and-use-it-for-vulnerability-scanning-60dd84e06a53
                    >>> --script=vuln (tests all vulnerability scripts),
                    --script=vulscan/ (requires additional github installation)
                    --script=vulners tests one script
"""

"""
    TODO:
        - Add save results to file
"""

##################################################################################################
# IMPORTS ETC
##################################################################################################

import sys
import argparse
import os
import re
import ipaddress
import subprocess
import shlex

#cwd = os.getcwd()
#sys.path.insert(1, cwd + '/src')
#from Constants import *
from utils import *

SCAN_TYPES = ['syn', 'udp', 'syn_udp', 'con']
MODE_PRESET = 'preset'
MODE_CUSTOM = 'custom'
MAX_PORTS=1024
MAX_TIMEOUT_S=60


##################################################################################################
# SUPPORT FUNCTIONS
##################################################################################################

def get_nmap_path(): # from https://github.com/nmmapper/python3-nmap/blob/1c60dff9b557e8127545604e029e763cb0c4f3f3/nmap3/nmap3.py#L256
    """
        #Returns the location path where nmap is installed
        #by calling which nmap
    """
    cmd = "which nmap"
    args = shlex.split(cmd)
    sub_proc = subprocess.Popen(args, stdout=subprocess.PIPE)

    try:
        output, errs = sub_proc.communicate(timeout=15)
    except Exception as e:
        print(e)
        sub_proc.kill()
    else:
            return output.decode('utf8').strip()

##################################################################################################
# NMAP CALLS
##################################################################################################

def print_popen_output(func):
    def inner(opts, target, timeout=None):
        #print('hi')
        for output in func(opts, target, timeout=timeout):
            print(output)
    return inner

@print_popen_output
def run_nmap(opts, target, timeout=MAX_TIMEOUT_S):
    
    # Taken and adapted from https://github.com/nmmapper/python3-nmap/tree/1c60dff9b557e8127545604e029e763cb0c4f3f3
    """
        Runs the nmap command using popen
        @param: cmd--> the command we want run eg /usr/bin/nmap -oX -  nmmapper.com --top-ports 10
        @param: timeout--> command subprocess timeout in seconds.
    """
    check_valid_target(target)
    
    check_int_var(timeout, 0, MAX_TIMEOUT_S)
    timeout = int(timeout) if timeout is not None else None
    nmaptool = get_nmap_path()
    print(nmaptool)
    if (os.path.exists(nmaptool)):
        cmd = nmaptool + ' ' + opts + ' ' + target
        args = shlex.split(cmd)

        print(cmd)
        
        sub_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        
        # Live print to terminal, from https://stackoverflow.com/questions/4417546/constantly-print-subprocess-output-while-process-is-running
        for stdout_line in iter(sub_proc.stdout.readline, ""):
            yield stdout_line
        sub_proc.stdout.close()
        #return_code = sub_proc.wait()
        #if return_code != 0:
        #    raise subprocess.CalledProcessError(return_code, cmd)
        
        try:
            output, errs = sub_proc.communicate(timeout=timeout)
        except Exception as e:
            sub_proc.kill()
            raise (e)
        else:
            if 0 != sub_proc.returncode:
                raise ValueError('>>> ERROR during command: "' + cmd + '"\n\n' + errs)#.decode('utf8'))
            return output#.decode('utf8').strip()
    else:
        raise ValueError(f'>>> ERROR: nmap does not appear to be installed. Exiting.')
        

def base_scan(target, scan_type='syn', host_detection=True, ports_scan=True, service_disc=False, os_disc=False, evasion_lvl=3, top_ports=MAX_PORTS, scan_vulns=False, dns=False, timeout=None):
    # Avoid command injection...
    check_valid_target(target)
    check_string_value(scan_type, SCAN_TYPES)
    check_boolean_var(host_detection)
    check_boolean_var(ports_scan)
    check_boolean_var(service_disc)
    check_boolean_var(os_disc)
    check_boolean_var(scan_vulns)
    check_int_var(evasion_lvl, 0, 5)
    check_int_var(top_ports, 0, MAX_PORTS)
    check_boolean_var(dns)
    if timeout is not None:
        check_int_var(timeout, 0, MAX_TIMEOUT_S)

    base_opts = '--randomize-hosts ' + f'-T{evasion_lvl} ' + f'--top-ports {top_ports}, -p 80,8080'
    
    if not ports_scan:
        base_opts = base_opts + ' -sn '
    else:
        # -sn incompatible with ports scan options
        if scan_type == 'udp':
            base_opts = base_opts + ' -sU'
        elif scan_type == 'syn':
            base_opts = base_opts + ' -sS'
        elif scan_type == 'con':
            base_opts = base_opts + ' -sT'
        elif scan_type == 'syn_udp':
            base_opts = base_opts + ' -sU -sS'
        else:
            raise ValueError(f'>>> ERROR: scan_type parameter {scan_type} invalid. Exiting.')
        # -sn incompatible with OS discovery
        if os_disc:
            base_opts = base_opts + ' -O'
    
    """
        NOTE TODO
        This below is a temporary solution that implements hard timeout JUST for single-host scans!
    """
    if timeout is not None:
        base_opts = base_opts + f' --host-timeout {timeout}'

    if not host_detection:
        base_opts = base_opts + ' -Pn'
    if service_disc:
        base_opts = base_opts + ' -sV'
    if scan_vulns:
        base_opts = base_opts + ' --script=vuln'
    if not dns:
        base_opts = base_opts + ' -n'

    opts = base_opts
    print(opts)
    print(target)
    run_nmap(opts, target, timeout=timeout)


##################################################################################################
# PRESET BASE SCANS
##################################################################################################

supported_functions = {}

###### Scan types with configurable options
def syn_scan(target, host_detection=True, ports_scan=True, service_disc=False, os_disc=False, evasion_lvl=3, top_ports=MAX_PORTS, dns=True, timeout=None): # same as base_scan
    res = base_scan(target, 'syn', host_detection=host_detection, ports_scan=ports_scan, service_disc=service_disc, os_disc=os_disc, evasion_lvl=evasion_lvl, top_ports=top_ports, dns=dns, timeout=timeout)
supported_functions[syn_scan.__name__] = syn_scan

def udp_scan(target, host_detection=True, ports_scan=True, service_disc=False, os_disc=False, evasion_lvl=3, top_ports=MAX_PORTS,  dns=True, timeout=None):
    res = base_scan(target, 'udp', host_detection=host_detection, ports_scan=ports_scan, service_disc=service_disc, os_disc=os_disc, evasion_lvl=evasion_lvl, top_ports=top_ports, dns=dns, timeout=timeout)
supported_functions[udp_scan.__name__] = udp_scan

def con_scan(target, host_detection=True, ports_scan=True, service_disc=False, os_disc=False, evasion_lvl=3, top_ports=MAX_PORTS,  dns=True, timeout=None):
    res = base_scan(target, 'syn', host_detection=host_detection, ports_scan=ports_scan, service_disc=service_disc, os_disc=os_disc, evasion_lvl=evasion_lvl, top_ports=top_ports, dns=dns, timeout=timeout)
supported_functions[con_scan.__name__] = con_scan

def syn_udp_scan(target, host_detection=True, ports_scan=True, service_disc=False, os_disc=False, evasion_lvl=3, top_ports=MAX_PORTS,  dns=True, timeout=None):
    res = base_scan(target, 'syn', host_detection=host_detection, ports_scan=ports_scan, service_disc=service_disc, os_disc=os_disc, evasion_lvl=evasion_lvl, top_ports=top_ports, dns=dns, timeout=timeout)
supported_functions[syn_udp_scan.__name__] = syn_udp_scan

###### Baselines presets
def host_discovery_only(target, timeout=None):
    check_valid_target(target)
    base_opts = '-sn --randomize-hosts'
    res = run_nmap(base_opts, target, timeout)
    return res

def scan_top_1024_ports(target, timeout=MAX_TIMEOUT_S):
    res = base_scan(target, top_ports=1024, timeout=timeout)
supported_functions[scan_top_1024_ports.__name__] = scan_top_1024_ports

def scan_skip_host_discovery(target, timeout=None):
    res = base_scan(target, host_detection=False, timeout=timeout)
supported_functions[scan_skip_host_discovery.__name__] = scan_skip_host_discovery

def scan_services_detection(target, timeout=None):
    res = base_scan(target, service_disc=True, timeout=timeout)
supported_functions[scan_services_detection.__name__] = scan_services_detection

def scan_os_detection(target, timeout=None):
    res = base_scan(target, os_disc=True, timeout=timeout)
supported_functions[scan_os_detection.__name__] = scan_os_detection

def scan_vulnerabilities(target, timeout=None):
    res = base_scan(target, scan_vulns=True, timeout=timeout)
supported_functions[scan_vulnerabilities.__name__] = scan_vulnerabilities



##################################################################################################
# MODULE MAIN
##################################################################################################

def module_main(arguments=None):

    ############################################################ ARGUMENTS PARSING
    parser = argparse.ArgumentParser(description='TBD')
    
    # NOTE: https://stackoverflow.com/questions/5262702/argparse-module-how-to-add-option-without-any-argument
    # NOTE: Used non-value parameters are stored as 'True'

    parser.add_argument('-t', '--target', metavar='<IPv4 address/range>', help='IPv4 address or range to target with discovery operations.', required=True)
    
    parser.add_argument('-f', '--func', help='Specifies one of the preset functions to run. One of:\n>>> {} \n>>> Requires related parameteds.'.format(supported_functions.keys()), required=False)
    parser.add_argument('-x', '--timeout', help='Specifies the duration of the scanning execution, in seconds.', required=False)

    parser.add_argument('-d', '--dns', help='If specified, does inverse DNS resolution for hosts marked as active. Refer to -n nmap documentation.', action='store_true', required=False)
    parser.add_argument('-s', '--scan_type', help='Specifies the port scanning technique that nmap uses. Currently supported:\n>>>{0} '.format(SCAN_TYPES), required=False)
    parser.add_argument('-j', '--skip_scan', help='If specified, does not perform ports scanning. Refer to nmap -sn documentation.', action='store_true', required=False)
    parser.add_argument('-a', '--skip_hosts_discovery', help='If specified, marks all target hosts as active. Refer to -Pn nmap specification', action='store_true', required=False)
    parser.add_argument('-p', '--top_ports', help='Specifies number of top ports to consider, according to nmap docs --top-ports', required=False)
    parser.add_argument('-o', '--os_discovery', help='If specified, tries to fingerprint the OS of the targets according to nmap docs -O', action='store_true', required=False)
    parser.add_argument('-v', '--service_discovery', help='If specified, tries to fingerprint the services running on scanned ports, according to nmap docs -sV', action='store_true', required=False)
    parser.add_argument('-e', '--evasion', help='Value 0-5. Determines stealthiness, maps to nmap -T parameter', required=False)
    parser.add_argument('-b', '--scan_vulns', help='If specified, invokes nmap NSE script "vuln", testing vulnerabilities on target.', action='store_true', required=False)

    args = parser.parse_args(arguments)
    
    # Value parameters
    target = args.target
    func = assign_non_req(args.func, default=None)
    timeout = assign_non_req(args.timeout, default=MAX_TIMEOUT_S)
    top_ports = assign_non_req(args.top_ports, default=MAX_PORTS)
    evasion = assign_non_req(args.evasion, default=3)
    scan_type = assign_non_req(args.scan_type, default='syn')

    # Non-value parameters
    skip_hosts_discovery = assign_non_req(args.skip_hosts_discovery, default=False)
    scan_vulns = assign_non_req(args.scan_vulns, False)
    dns = assign_non_req(args.dns, default=False)
    skip_ports_scan = assign_non_req(args.skip_scan, default=False)
    services = assign_non_req(args.service_discovery, default=False)
    os = assign_non_req(args.os_discovery, default=False)

    if func is not None:
        if func in supported_functions.keys():
            print(f'>>> Executing preset function {func} on target {target}:\n')
            try:
                return supported_functions[func](target, timeout)
            except Exception as e:
                raise (e)
        else:
            raise ValueError(f'\n>>> ERROR: incorrect -f parameter [ {func} ]. Supported -f parameters: \n>>> {supported_functions.keys()}')
    else:
        # Custom scan invocation
        base_scan(target, scan_type=scan_type, host_detection=(not skip_hosts_discovery), ports_scan=(not skip_ports_scan), service_disc=services, os_disc=os, evasion_lvl=evasion, top_ports=top_ports, dns=dns, scan_vulns=scan_vulns, timeout=timeout)


if __name__ == '__main__':
    module_main()
    #scan_top_1024_ports('192.168.1.1')
    sys.exit(0)