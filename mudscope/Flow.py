# Imports
import json
import socket
import re
import binascii
from ipaddress import ip_address, ip_network
from scapy.all import *
from mudscope.Constants import *

debug = False

"""
    TODO: Support WIFI Protocols etc. if different from Eth
"""

# WORKAROUND
LOCAL_NETWORKS_STRINGS = ['0.0.0.0/24', '255.255.255.0/24', '192.168.5.0/24', '192.168.10.0/24', '192.168.32.0/24']
KNOWN_BACKEND_NETWORKS_STRINGS = ['255.255.255.0/24', '128.14.0.0/16', '75.2.128.0/18', '75.2.0.0/17', '54.222.0.0/16', '159.65.0.0/16', '52.64.0.0/12', '52.0.0.0/10', '44.192.0.0/10', '3.0.0.0/9', '8.208.0.0/12', '52.192.0.0/12', '52.208.0.0/13', '52.223.128.0/18', '52.220.0.0/15', '52.216.0.0/14', '52.222.0.0/16', '52.223.0.0/17', '192.168.32.0/24', '18.192.0.0/16', '18.32.0.0/11', '18.64.0.0/10', '18.128.0.0/9', '34.192.0.0/10', '192.168.10.0/24']
KNOWN_BACKEND_NETWORKS = [ip_network(network) for network in KNOWN_BACKEND_NETWORKS_STRINGS]
LOCAL_NETWORKS = [ip_network(network) for network in LOCAL_NETWORKS_STRINGS]
KNOWN_BACKEND_PORTS = ['39542', '39545', '52682', '8802', '50443', '58458', '6667', '49154', '51747', '8006', '32100', '21647', '16677', '8810', '8811', '8812', '8813', '8814', '8815', '60722']

class Flow:

    origin_types = {
        ORIGIN_SCAPY_PACKET : 'SCAPY_PKT',
        ORIGIN_MUDGEE_OF_RULE : 'MUDGEE_OF_RULE'
    }

    # TODO: change logics to empty iniializer, populate after
    def __init__(self, smac, dmac, eth_type, sip, dip, sport, dport, ip_proto, origin, start_time=None):
        # TODO: add IDs
        # TODO: add start time and end time
        self.start_time = start_time
        self.smac = smac
        self.dmac = dmac
        self.eth_type = eth_type
        self.sip = sip
        self.dip = dip
        self.sport = sport
        self.dport = dport
        self.ip_proto = ip_proto # NOTE: utils: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        self.origin= origin if origin in Flow.origin_types.values() else 'invalid' # specifies if pkt flow or rule flow
        
        if self.origin == 'invalid':
            raise ValueError('Flow generated has invalid origin attribute specified. Valid origin attributes: {}. Flow referred:\n{}'.format(Flow.origin_types, self.get_json_flow_data()))
        #print('NEW FLOW CREATED')



    ##################################################################################################
    # WORKAROUND MUDGEE AMAZON/KNOWN ADDRESSES - overrides flow rules for IP match
    #   > https://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python
    ##################################################################################################
    @staticmethod
    def address_in_known_backend(ip_addr, networks=KNOWN_BACKEND_NETWORKS):
        a = int(ip_address(ip_addr))
        for n in networks:
            netw = int(n.network_address)
            mask = int(n.netmask)
            is_in = (a & mask) == netw
            if debug:
                print(f'{ip_addr} in {n} --- {is_in}')
            if is_in:
                return True
        return False

    ########################################################################
    #                             Constructors                             #
    ########################################################################


    @classmethod
    def from_scapy_pkt(cls, scapy_pkt):
        """ Pythonic constructor to generate a flow from a scapy packet
            
            Parameters
            ----------
            scapy_pkt : scapy:Packet
                Packet to inspect to generate flow
            
            Returns
            -------
            Flow: object
                Specific for packet, composed of
                (0) smac: string
                    source MAC address
                (1) dmac: string
                    destination MAC address
                (2) eth_type: string
                    0x0*** value representing protocol announced in Ethernet layer
                (3) sip: string
                    source IP address
                (4) dip: string
                    destination IP address
                (5) sport: string
                    string representing integer of source port
                (6) dport: string
                    string representing integer of destination port
                (7) ip_proto: string
                    string representing transport protocol used by packet
                (8) origin: string
                    string of metadata on wether the flow is originated via packet (as in this case) or filtering rule
            
            Exception
            ---------
            e: Exception
                Fails to create flow by parsing fields
        """
        try:
                        
            # TODO: Handle other level 1 packets (Linux Coocked Captures SLL, for instance)
            smac = scapy_pkt.src
            dmac = scapy_pkt.dst

            # Handle MAC in hex format - ON TON DATA
            if not bool(re.match(MAC_REGEX, smac)):
                print('>>> smac not std: {}'.format(smac)) if debug else None
                smac = Flow.parse_mac_from_hexbytes(smac)
            if not bool(re.match(MAC_REGEX, dmac)):
                print('>>> dmac not std: {}'.format(dmac)) if debug else None
                dmac = Flow.parse_mac_from_hexbytes(dmac)
            

            # Ethernet type in 0x0*** format to match MUDgee OFFlows rules
            eth_type = hex(scapy_pkt['Ethernet'].type)[:2] + '0' + hex(scapy_pkt['Ethernet'].type)[2:]

            # source and dest IPs from scapy pkt are expected to be single address value
            sip = scapy_pkt['IP'].src
            dip = scapy_pkt['IP'].dst


            # TODO: other transport protocols??
            if scapy_pkt.haslayer('TCP'):
                sport, dport = Flow.get_scapy_pkt_ports_from_transport(scapy_pkt, 'TCP')
            elif scapy_pkt.haslayer('UDP'):
                sport, dport = Flow.get_scapy_pkt_ports_from_transport(scapy_pkt, 'UDP')
            else:   
                sport = '?'
                dport = '?'

            ip_proto = str(scapy_pkt['IP'].proto)

            origin = Flow.origin_types[ORIGIN_SCAPY_PACKET]

            if debug:
                print('~~~~~~~~~~~~~~~~~~~~~~~~~ FROM_SCAPY_PKT FIELDS ~~~~~~~~~~~~~~~~~~~~~~~~~')
                print('SMAC {} -> DMAC {}'.format(dmac, smac))
                print('ETH_TYPE {}'.format(eth_type))
                print('SIP {} -> DIP {}'.format(sip, dip))
                print('SPORT {} -> DPORT {}'.format(sport, dport))
                print('IP_PROTO {}'.format(ip_proto))
                print('ORIGIN {}'.format(origin))

            flow = cls(smac, dmac, eth_type, sip, dip, sport, dport, ip_proto, origin)
            return flow

        except Exception as e:
            print('Exception: {}'.format(e))
            print('>>> Flow could not be created from packet {}. Try checking missing layers or unparsed data.'.format(scapy_pkt.show()))

            return -1



    @classmethod
    def from_of_rule(cls, of_rule, dvc_mac, gw_mac):
        # TODO TODO: Check OF Filtering table address resolution!
        #   Some legit IPs may be discarded depending on how they are solved, and the one registered in the pcap!
        """ Pythonic constructor to generate a flow from an OpenFlow filtering rule from MUDgee
            
            Parameters
            ----------
            of_rule : dictionary
                Dictionary listing OF fields and match for the rule
            dvc_mac : string
                MAC of device to which the rules set refer. Used to resolve <deviceMac> tag in flow rules
            gw_mac : 
                MAC of default gateway to which the rules set refer. Used to resolve <gatewayMac> tag in flow rules
            
            Returns
            -------
            Flow: object
                Specific for packet, composed of
                (0) smac: string
                    source MAC address
                (1) dmac: string
                    destination MAC address
                (2) eth_type: string
                    0x0*** value representing protocol announced in Ethernet layer
                (3) sip: list<string>
                    Contains source IP addresses resolved from domain name, or listed IP address
                (4) dip: string
                    Contains destination IP addresses resolved from domain name, or listed IP address
                (5) sport: string
                    string representing integer of source port
                (6) dport: string
                    string representing integer of destination port
                (7) ip_proto: string
                    string representing transport protocol used by packet
                (8) origin: string
                    string of metadata on wether the flow is originated via packet (as in this case) or filtering rule
            
            Exception
            ---------
            e: Exception
                Fails to create flow by parsing fields
        """
        try:
            # Parse srcMac to actual address saved by MUD enforcer
            if of_rule['srcMac'] == MUDGEE_DVCMAC_OFRULE_TAG:
                smac = dvc_mac
            elif of_rule['srcMac'] == MUDGEE_GTWMAC_OFRULE_TAG:
                smac = gw_mac
            else:
                smac = of_rule['srcMac']

            # Parse dstMac to actual address saved by MUD enforcer
            if of_rule['dstMac'] == MUDGEE_DVCMAC_OFRULE_TAG:
                dmac = dvc_mac
            elif of_rule['dstMac'] == MUDGEE_GTWMAC_OFRULE_TAG:
                dmac = gw_mac
            else:
                dmac = of_rule['dstMac']


            eth_type = of_rule['ethType']
            
            # Parse source and dest IP addresses. A list of IPs is returned
            is_src_ip_addr = of_rule['srcIp'] == '*' or bool(bool(re.match(IPV4_REGEX, of_rule['srcIp'])) or bool(re.match(IPV6_REGEX, of_rule['srcIp'])))
            is_dst_ip_addr = of_rule['dstIp'] == '*' or bool(bool(re.match(IPV4_REGEX, of_rule['dstIp'])) or bool(re.match(IPV6_REGEX, of_rule['dstIp'])))
            # TODO: check gethostbyname return values for integrity
            sip = [of_rule['srcIp']] if is_src_ip_addr else [socket.gethostbyname(of_rule['srcIp'])]
            dip = [of_rule['dstIp']] if is_dst_ip_addr else [socket.gethostbyname(of_rule['dstIp'])]

            sport = of_rule['srcPort']
            dport = of_rule['dstPort']

            ip_proto = of_rule['ipProto'] if isinstance(of_rule['ipProto'], str) else str(of_rule['ipProto'])

            origin = Flow.origin_types[ORIGIN_MUDGEE_OF_RULE]

            if debug:
                print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~ FROM_OF_RULE FIELDS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
                print('SMAC {} -> DMAC {}'.format(dmac, smac))
                print('ETH_TYPE {}'.format(eth_type))
                print('SIP {} -> DIP {}'.format(sip, dip))
                print('SPORT {} -> DPORT {}'.format(sport, dport))
                print('IP_PROTO {}'.format(ip_proto))
                print('ORIGIN {}'.format(origin))

            flow = cls(smac, dmac, eth_type, sip, dip, sport, dport, ip_proto, origin)
            return flow

        except Exception as e:
            print(e)
            print('>>> Flow could not be created from of_rule {}. Try to check unparsed fields'.format(json.dumps(of_rule, indent=4)))
            return -1


    ########################################################################
    #                          Utility methods                             #
    ########################################################################

    def get_json_flow_data(self):
        data = {
            #'start_time' : self.start_time,
            'smac' : self.smac,
            'dmac' : self.dmac,
            'eth_type' : self.eth_type,
            'sip' : self.sip,
            'dip' : self.dip,
            'sport' : self.sport,
            'dport' : self.dport,
            'ip_proto' : self.ip_proto,
            'origin' : self.origin
        }
        return json.dumps(data, indent=4)
    
    def print_flow(self):
        print(self.get_json_flow_data())

    def create_dict_key(self):
        if self.origin != Flow.origin_types[ORIGIN_SCAPY_PACKET]:
            raise ValueError('Attempting flow dict_key generation from non-packet originated flow {}.'.format(self.get_json_flow_data()))
        else:
            return FLOW_INFO_JOIN_CHAR.join([self.smac, self.dmac, self.eth_type, self.sip, self.dip, self.sport, self.dport, self.ip_proto])

    @staticmethod
    def get_scapy_pkt_ports_from_transport(scapy_pkt, transport_layer_tag):
        if debug:
            print('~~~ in ports-getter ~~~')
            print('pkt[2]:')
            scapy_pkt[2].show()

        # TODO: change to std tag or smt to be processed as int
        sport, dport = '?', '?'

        scapy_pkt_sport = str(scapy_pkt[transport_layer_tag].sport)
        scapy_pkt_dport = str(scapy_pkt[transport_layer_tag].dport)

        try:
            # parse service string ports
            is_sport_num = bool(re.match(PORT_REGEX, scapy_pkt_sport))
            is_dport_num = bool(re.match(PORT_REGEX, scapy_pkt_dport))
            sport = scapy_pkt_sport if is_sport_num else str(socket.getservbyname(int(scapy_pkt_sport)))
            dport = scapy_pkt_dport if is_dport_num else str(socket.getservbyname(int(scapy_pkt_dport)))
        except Exception as e:
            sport = scapy_pkt_sport
            dport = scapy_pkt_dport

        return sport, dport



    @staticmethod
    def get_pkt_flow_data_from_dict_key(pkt_flow_dict_key):
        smac, dmac, eth_type, sip, dip, sport, dport, ip_proto = pkt_flow_dict_key.split(FLOW_INFO_JOIN_CHAR)
        #if origin != Flow.origin_types[ORIGIN_SCAPY_PACKET]:
        #    raise ValueError('Error: attempting to create packet_flow from non-packet flow dict key {}'.format(pkt_flow_dict_key))

        try:
            flow = Flow(smac, dmac, eth_type, sip, dip, sport, dport, ip_proto, Flow.origin_types[ORIGIN_SCAPY_PACKET])
        except Exception as e:
            print('Packet flow generation failed from packet flow dict key: {}'.format(pkt_flow_dict_key))
            print(e)
        
        return flow

    @staticmethod
    def parse_mac_from_hexbytes(hex_mac_addr):
        bin_mac_addr = binascii.hexlify(hex_mac_addr)
        unparsed_str_mac_addr_excess = bin_mac_addr.decode('utf-8')
        
        # TODO: Are there other mac formats? In case, to handle

        # Mac now in form 'dc56e75b61410000', with four zeors in eccess. Cropping string and adding ':'
        # 12 is number of nibbles (6 bytes)
        unparsed_str_mac_addr_crop = unparsed_str_mac_addr_excess[:12]
        mac = ':'.join(unparsed_str_mac_addr_crop[c:c+2] for c in range(0, len(unparsed_str_mac_addr_crop), 2))
        return mac


    @staticmethod
    def equals(rule_flow, pkt_flow):
        """ Comparison function to match rule flow against packet flow. Has to be custom because of 'origin' checks
            
            Parameters
            ----------
            rule_flow : flow
                Flow originated from filtering rule. Must have origin = from OF rule
            pkt_floew : string
                Flow originated from scapy packet. Must have origin = from scapy packet
            
            Returns
            -------
            Boolean
                True : packet abides by flow rule
                False : packet does not abide by flow rule
        """

        if not isinstance(rule_flow, Flow) or not isinstance(pkt_flow, Flow):
            raise ValueError('Error: attempting "equals()" FLow comparison on non-flow objects.')
        
        if rule_flow.origin != Flow.origin_types[ORIGIN_MUDGEE_OF_RULE] or pkt_flow.origin != Flow.origin_types[ORIGIN_SCAPY_PACKET]:
            raise ValueError('Invalid flow origins for comparison. Flows comparison must be (RULE FLOW, PACKET FLOW). Flows: {} \n {}'.format(rule_flow.get_json_flow_data, pkt_flow.get_json_flow_data()))
        
        # generated flows from rules have macs already parsed
        smac_match = bool(rule_flow.smac == pkt_flow.smac or rule_flow.smac == '*')
        dmac_match = bool(rule_flow.dmac == pkt_flow.dmac or rule_flow.dmac == '*') #or (pkt_flow.dmac == 'ff:ff:ff:ff:ff:ff')
        eth_type_match = bool(rule_flow.eth_type == pkt_flow.eth_type or rule_flow.eth_type == '*')

        sip_match = bool(pkt_flow.sip in rule_flow.sip or '*' in rule_flow.sip) #or Flow.address_in_known_backend(pkt_flow.sip)
        dip_match = bool(pkt_flow.dip in rule_flow.dip or '*' in rule_flow.dip) #or Flow.address_in_known_backend(pkt_flow.dip)

        sport_match = bool(rule_flow.sport == pkt_flow.sport or rule_flow.sport == '*') or pkt_flow.sport in KNOWN_BACKEND_PORTS
        dport_match = bool(rule_flow.dport == pkt_flow.dport or rule_flow.dport == '*') or pkt_flow.dport in KNOWN_BACKEND_PORTS

        ip_proto_match = bool(rule_flow.ip_proto == pkt_flow.ip_proto or rule_flow.ip_proto == '*')

        local_broadcast = Flow.address_in_known_backend(pkt_flow.sip, networks=LOCAL_NETWORKS) and pkt_flow.dip == '255.255.255.255'


        match_condition = (smac_match and dmac_match and eth_type_match and sip_match and dip_match and sport_match and dport_match and ip_proto_match) or local_broadcast

        if (match_condition):
            return True
        else:
            if debug:
                print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~ rule_flow, packet_flow, matches ~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
                rule_flow.print_flow()
                pkt_flow.print_flow()
                print("{}, {}, {}, {}, {}, {} ,{}, {}".format(smac_match, dmac_match, eth_type_match, sip_match, dip_match, sport_match, dport_match, ip_proto_match))
            
            return False





if __name__ == '__main__':
    # Testing things
    print(str(socket.getservbyname('bootpc')))
    print(str(socket.getservbyname('bootps')))
    print('[]'.join(['a', 'b']))