

import re
import os
import csv
import socket
import binascii
from mudscope.Flow import Flow
from scapy.all import *
from pathlib import Path
from datetime import datetime

from mudscope.Constants import *

debug = False

# Test ip, port for example_0
# 192.168.1.137, 57080

# A reference for analyzing captures with scapy:
# https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html


# Packet layer getter, ref: https://stackoverflow.com/questions/13549294/get-all-the-layers-in-a-packet
def get_packet_layers(packet):
    l_counter = 0
    layers = []
    while True:
        layer = packet.getlayer(l_counter)
        if layer is None:
            break
        layers.append(layer.name)
        l_counter += 1
    return layers

def process_packet(tg_ip, output):
    # Workaround not to use string filtering in sniff, BUG-ged in OSX. ref: https://gist.github.com/thepacketgeek/6876699
    def custom_action(pkt):
        # Ethernet ID is 'Ethernet'
        layers = get_packet_layers(pkt)
        print(layers)
        #print('SRC {} -> DST {}'.format(pkt.src, pkt.dst))
        #pkt.show()
        
        #print(type(pkt.src))
        mac = parse_mac_from_hexbytes(pkt.src)
        print(mac)

        test = bool(re.match(MAC_REGEX, mac))
        print ("IS MAC VALID: {}".format(test))

    return custom_action

# pcap processor
def process_pcap(filename, tg_ip, output):

    # DONE: select packets "of" specific entity (IPv4 address) only
    # TODO: dump whole packets to-from source in separate file
    # TODO: generate relative netflows
    # TODO: statistics of devices/addresses/protocols or whatever

    print('Processing {}...'.format(filename))
    
    # OSX BUG WITH SCAPY LIBPCAP PROVIDER, filter='ip and host 192.168.0.1' WON'T WORK
    sniff(offline=filename, prn=process_packet(tg_ip, output), store=0)


def parse_mac_from_hexbytes(hex_mac_addr):
    bin_mac_addr = binascii.hexlify(hex_mac_addr)
    unparsed_str_mac_addr_excess = bin_mac_addr.decode('utf-8')
    # Mac now in form 'dc56e75b61410000', with four zeors in eccess. Cropping string and adding ':'
    # 12 is number of nibbles (6 bytes)
    unparsed_str_mac_addr_crop = unparsed_str_mac_addr_excess[:12]
    mac = ':'.join(unparsed_str_mac_addr_crop[c:c+2] for c in range(0, len(unparsed_str_mac_addr_crop), 2))
    return mac


def get_pcap_csv(pcap_file, device_name, resolve_ips=False):


    # Lookup dictionary to make address solving quicker
    ip_lookup_cache = {}


    if not pcap_file.endswith('.pcap') or not os.path.isfile(pcap_file):
        print('>>> {} does not exist or is not a valid pcap file.'.format(pcap_file))
    
    # Scapy readable pcap
    scapy_pcap = rdpcap(pcap_file)

    # Takes pcap file name, generates same name .csv file
    csv_file_name = Path(pcap_file).stem + '.csv'
    output_location = OUTPUTS_FOLDER + device_name + '/'
    csv_file = output_location + csv_file_name

    # Write pcap to device-referred output location
    if not Path(output_location).exists():
        Path(output_location).mkdir(parents=True, exist_ok=True)
    
    if not Path(csv_file).is_file():
        open(csv_file, 'w+').close()

    """
    What I want:
        - src ip (resolved to host if possible)
        - dst ip (should be always device) >> socket.gethostbyaddr()
        - transport: udp / tcp
        - src port (resolved to application if possible) 
        - dst port (resolved to application if possible) >> socket.getservbyport()
        - packet size

    """
    header = ['Time', 'Eth-type', 'Source-ip', 'Destination-ip', 'Source-port', 'Destination-port', 'Transport-proto', 'Packet-size']

    with open(csv_file, 'w') as out:
        writer = csv.writer(out)

        writer.writerow(header)
    
        for pkt in scapy_pcap:
            try:
                
                time = datetime.fromtimestamp(pkt.time)

                print('PTK TIME {}'.format(time)) if debug else None

                # Ethernet type in 0x0*** format 
                eth_type = hex(pkt['Ethernet'].type)[:2] + '0' + hex(pkt['Ethernet'].type)[2:]

                print('ETH_TYPE {}'.format(eth_type)) if debug else None

                # source and dest IPs from scapy pkt are expected to be single address value
                # if resolve_ips is set to True, all addresses are attempted to be resolved. For that, the ip_lookup_cache is used.
                # if resolve_ips is set to False instead, the csv will contain just the "raw" ip addresses
                try:
                    sip_raw = pkt['IP'].src
                    if resolve_ips:
                        if not sip_raw in ip_lookup_cache.keys():
                            sip = socket.gethostbyaddr(sip_raw)[0]
                            ip_lookup_cache[sip_raw] = sip
                        else:
                            sip = ip_lookup_cache[sip_raw]
                    else:
                        sip = sip_raw
                except Exception as e:
                    sip = pkt['IP'].src
                try:
                    dip_raw = pkt['IP'].dst
                    if resolve_ips:
                        if not dip_raw in ip_lookup_cache.keys():
                            dip = socket.gethostbyaddr(dip_raw)[0]
                            ip_lookup_cache[dip_raw] = dip
                        else:
                            sip = ip_lookup_cache[sip_raw]
                    else:
                        dip = dip_raw
                except Exception as e:
                    dip = pkt['IP'].dst

                print('SIP {} -> DIP {}'.format(sip, dip)) if debug else None

                
                try:
                    # Thanks https://stackoverflow.com/questions/35444280/ip-proto-field-number-to-string
                    proto_field = pkt['IP'].get_field('proto')
                    ip_proto = proto_field.i2s[pkt['IP'].proto]
                except:
                    ip_proto = pkt['IP'].get_field('proto')
                
                print('IP_PROTO {}'.format(ip_proto)) if debug else None


                # UDP or TCP expected                
                if pkt.haslayer('TCP'):
                    sport, dport = Flow.get_scapy_pkt_ports_from_transport(pkt, 'TCP')
                elif pkt.haslayer('UDP'):
                    sport, dport = Flow.get_scapy_pkt_ports_from_transport(pkt, 'UDP')
                else:   
                    sport = '?'
                    dport = '?'
                print('SPORT {} -> DPORT {}'.format(sport, dport)) if debug else None

                packet_size = len(pkt)
                print('PACKET SIZE {}'.format(packet_size)) if debug else None

                writer.writerow([time, eth_type, sip, dip, sport, dport, ip_proto, packet_size])

            except Exception as e:
                print('Error: {}'.format(e))
                print('>>> Unable to parse packet to (IPs, ports, transport proto, payoladsize). Packet :')
                pkt.show()

                return -1
    
    return str(csv_file)


def covers(pcap_to_find, pcap_to_search):
    
    # Hashed set of packets to check if contained in pcap_to_search pcap_dest
    packets = set()
    to_find = {'cntr' : 0}
    def populate_set(packets_set, to_find_counter):
        def inner(pkt):
            packets_set.add(str(pkt))
            to_find_counter['cntr'] += 1
        return inner
    sniff(offline=pcap_to_find, prn=populate_set(packets, to_find), store=0)

    # Sniff of pcap_to_search to find var:packets of pcap_to_find
    found = {'cntr' : 0}
    def check(packets_set, counter_found):
        def inner(pkt):
            if (str(pkt) in packets_set):
                counter_found['cntr'] += 1
        return inner
    sniff(offline=pcap_to_search, prn=check(packets, found), store=10)

    coverage = float(found['cntr'] / to_find['cntr']) * 100

    return to_find['cntr'], found['cntr'], coverage


def parse_mac_from_hexbytes(hex_mac_addr):
    bin_mac_addr = binascii.hexlify(hex_mac_addr)
    unparsed_str_mac_addr_excess = bin_mac_addr.decode('utf-8')
    
    # TODO: Are there other mac formats? In case, to handle

    # Mac now in form 'dc56e75b61410000', with four zeors in eccess. Cropping string and adding ':'
    # 12 is number of nibbles (6 bytes)
    unparsed_str_mac_addr_crop = unparsed_str_mac_addr_excess[:12]
    mac = ':'.join(unparsed_str_mac_addr_crop[c:c+2] for c in range(0, len(unparsed_str_mac_addr_crop), 2))
    return mac




if __name__ == '__main__':
    # Testing things
    TON_iot_pcap_test = '/Users/lucamrgs/Big_Data/TON_IoT-Datasets/Raw_datasets/Raw_Network_dataset/Network_dataset_pcaps/normal_pcaps/normal_13.pcap'
    target_ip = '192.168.1.152'
    ton_tests_output = '/out_pcaps/ton_tests.pcap'
    # TEST mac addresses unparsed and parsed: \x00\x0c)\xd2\xb0\x02, 00:0c:29:d2:b0:02
    
    # NOTE: TON MUDgee generation is not working because if packet does not have ethernet, or if it fails to retrieve packets info
    # it ignores the packet. Now it is the case that in TON, all packets are cooked linuxes, thus missing fields that MUDgee expects
    # so MUDgee generation ignores every packet and builds 'empty' MUD data (profile and rules)

    # SOLUTION:
    # Either modify source code of MUDgee, or use other datasets.

    #process_pcap(TON_iot_pcap_test, target_ip, ton_tests_output)
    src_pcap = OUTPUTS_FOLDER + 'ieee-ezviz-complete/scan-hostport-all-ezviz-rejected.pcap'
    gt_pcap = '/Users/lucamrgs/Big_Data/IEEE-Huy-Kang/iot_intrusion_dataset/gt/gt-scan-hostport-all-ezviz.pcap'
    to_find, found, cvrg = covers(gt_pcap, src_pcap)

    print(to_find)
    print(found)
    print(cvrg)
