
import os
import csv
import json
import socket
import difflib
import requests
import ipaddress
from Flow import Flow
from Constants import *
from scapy.all import *
from pprint import pprint
from ipwhois import IPWhois
from PacketsRegister import PacketsRegister

debug = False

# TODO: Consider having library instead of class
# TODO: Comprehensive Sankey? flow data NET-DESC > IPS > PORTS/SERVICES > IPS > PORTS/SERVICES > NET-DESC

# TODO: FILTER TOR EXIT NODES
# TODO: FILTER VPNS
# TODO: Filter universities
# TODO: FIlter sinlge-packet university sources?


# NOTE: Very useful list of VPN IPs @ https://github.com/ejrv/VPNs


class TIRegister:
    """ PER-FLOW TI register. Bound to data file source (a json register)
        Serves as a collector for all file-related intelligence information
    """

    # Intelligence to get:
    #   - IPs information (source/dest) such as location, number of associated flows
    #   - Ports/services used. Maybe focus first on destination ports of interested device


    def __init__(self, data, devname):
        """ Initialization for TI register
            Params:
            - data:     ABSOLUTE_PATH to pcap file to get information from
                    OR  ASOLUTE_PATH to json file derived from PacketsRegister
        """

        self.devname = devname

        # Data initialization
        if not os.path.isfile(data):
            raise ValueError('>>> Unknown or invalid data: {}\n Data parameter must be a file path.'.format(data))
        if not (data.endswith('.json') or data.endswith('.pcap')):
            raise ValueError('>>> Unsupported data format for TIRegister instantiation: {}\nSupported formats are ".pcap" and ".json", \
                where the json file is expected to be of PacketsRegister type.'.format(data))
        
        self.data = data

        # Rejected flows population
        if self.data.endswith('.json'):
            register = PacketsRegister.from_json(self.data)
        elif self.data.endswith('.pcap'):
            print('Gathering flows from pcap file {}....\n'.format(data))
            register = PacketsRegister(type='RejectedTrafficOnly')
            register.populate_flows_from_pcap(self.data)
        self.rejected_flows = register.get_core_flows(REJECTED_TRAFFIC)

        self.ips_info = {
            # dict content: ip_address : {@staticmethod.ip_info_entry()}}
            ORIGIN_SOURCE_TAG : {},
            ORIGIN_DESTINATION_TAG : {}
        }
        self.ports_info = {
            # dict content: port/service: {@staticmethod.port_info_entry()}}
            #                             {'number' : port_number, 'transport_proto' : tr_proto, 'cntr_flows' : cntr_flows}
            ORIGIN_SOURCE_TAG : {},
            ORIGIN_DESTINATION_TAG : {}
        }

        # Notorious backends IP addresses spaces
        self.amazon_ip_ranges = {}
        self.microsoft_ip_ranges = {}
        self.google_ip_ranges = {}


    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, indent=4)



    ########################################################################
    #                            GET IPS INFO                              #
    ########################################################################

    def gather_ips_infos(self, api='geoip'):
        """ Gathers IP-address related information and stores them to class instance registers.
            Populates both SRC and DST IPs info registers.

            Params:
            - api: supports either 'geoip' or 'ipwhois', specifies the method for IP information resolution

            NOTE (s)
                - It gathers and processes the data from PacketsRegister.get_core_flows() format
                - Behaves the same way in case of monodirectional flows
        """
        # Refer to PacketsRegister class, generated from json data

        if not api == 'geoip' or api == 'ipwhois':
            raise ValueError('Unsupported or unrecognized "api" parameter for IPs info resolution: {}\nSupported values are "geoip" or "ipwhois".'.format(api))
        
        for rejected_flow in self.rejected_flows:
            
            # Get flow source and testination IPs
            src_addr = str(rejected_flow[SIP_TAG])
            dst_addr = str(rejected_flow[DIP_TAG])

            print('processing src_addr, dst_addr: {}, {}'.format(src_addr, dst_addr)) if debug else None

            is_src_addr_registered = src_addr in self.ips_info[ORIGIN_SOURCE_TAG].keys()
            is_dst_addr_registered = dst_addr in self.ips_info[ORIGIN_DESTINATION_TAG].keys()

            if is_src_addr_registered:
                # NOTE: ips_info entries are as returned by class.ip_info_entry()
                print('src_addr [ {} ] is already registered'.format(src_addr)) if debug else None
                self.ips_info[ORIGIN_SOURCE_TAG][src_addr]['cntr_flows'] += 1 
            if is_dst_addr_registered:
                print('dst_addr [ {} ] is already registered'.format(dst_addr)) if debug else None
                self.ips_info[ORIGIN_DESTINATION_TAG][dst_addr]['cntr_flows'] += 1
            
            # Append new IP info entries to registers. They will be populated (/resolved) after, according to the specified API parameter
            if not is_src_addr_registered:
                if ipaddress.ip_address(src_addr).is_private:
                    self.ips_info[ORIGIN_SOURCE_TAG][src_addr] = TIRegister.ip_info_entry(LOCAL_ADDRESS_TAG, LOCAL_ADDRESS_TAG, 0, 0, 1)
                else:
                    self.ips_info[ORIGIN_SOURCE_TAG][src_addr] = TIRegister.unresolved_ip_entry() #self.query_ip_whois(src_addr)
            
            if not is_dst_addr_registered:
                if ipaddress.ip_address(dst_addr).is_private:
                    self.ips_info[ORIGIN_DESTINATION_TAG][dst_addr] = TIRegister.ip_info_entry(LOCAL_ADDRESS_TAG, LOCAL_ADDRESS_TAG, 0, 0, 1)
                else:
                    self.ips_info[ORIGIN_DESTINATION_TAG][dst_addr] = TIRegister.unresolved_ip_entry() #self.query_ip_whois(dst_addr)
                    
        # Resolve ip infos with specified API
        if (api == 'geoip'):
            self.resolve_ips_info_with_geoip()
        elif (api == 'ipwhois'):
            self.resolve_ips_info_with_ipwhois()
        

    def resolve_ips_info_with_geoip(self):
        # Resolve information in batches
        # GEOIP APIS Info at https://ip-api.com/docs/api:batch
        # NOTE: UP TO 100 REQUESTS PER QUERY
        src_geoip_queries = []
        dst_geoip_queries = []

        print('################## GEOIPs QUERIES ##################') if debug else None

        for ip in self.ips_info[ORIGIN_SOURCE_TAG].keys():
            src_geoip_queries.append({"query":str(ip)})
        for ip in self.ips_info[ORIGIN_DESTINATION_TAG].keys():
            dst_geoip_queries.append({"query":str(ip)})

        print('src_geoip queries list length: {}'.format(len(src_geoip_queries))) if debug else None
        print('dst_geoip queries list length: {}'.format(len(dst_geoip_queries))) if debug else None

        # APIS limit of 100 queries per batch,
        # managed with list of sublists (ref code: https://www.geeksforgeeks.org/break-list-chunks-size-n-python/)
        n = 100
        src_geoip_queries_batches = [src_geoip_queries[i:i+n] for i in range(0, len(src_geoip_queries), n)]
        dst_geoip_queries_batches = [dst_geoip_queries[i:i+n] for i in range(0, len(dst_geoip_queries), n)]

        try:
            src_response = []
            for batch in src_geoip_queries_batches:
                src_response.extend(requests.post(GEOIP_API_BATCH_URL, json=batch).json())
            
            dst_response = []
            for batch in dst_geoip_queries_batches:
                dst_response.extend(requests.post(GEOIP_API_BATCH_URL, json=batch).json())

            for ip_info in src_response:
                ref_ip = ip_info['query']
                entry_data = self.ips_info[ORIGIN_SOURCE_TAG][ref_ip]
                if ip_info['status'] == 'success':
                    # Refer to query param (the IP from the keys), and populate (lat, lon) data
                    self.ips_info[ORIGIN_SOURCE_TAG][ref_ip] = TIRegister.ip_info_entry(ip_info['countryCode'], ip_info['isp'], ip_info['lat'], ip_info['lon'], entry_data['cntr_flows'])
                else:
                    pass # Ignore

            for ip_info in dst_response:
                ref_ip = ip_info['query']
                entry_data = self.ips_info[ORIGIN_DESTINATION_TAG][ref_ip]
                if ip_info['status'] == 'success':
                    # Refer to query param (the IP from the keys), and populate (lat, lon) data
                    self.ips_info[ORIGIN_DESTINATION_TAG][ref_ip] = TIRegister.ip_info_entry(ip_info['countryCode'], ip_info['isp'], ip_info['lat'], ip_info['lon'], entry_data['cntr_flows'])
                else:
                    pass # Ignore
        
        except Exception as e:                    
            raise ValueError('Failed to solve batch IP geo-lookup requests - reference class data attribute: {}'.format(self.data)) 


    def resolve_ips_info_with_ipwhois(self):
        # NOTE: Does not resolve latitude and longitude
        # TODO: Resolve latitude and longitude...
        for ip in self.ips_info[ORIGIN_SOURCE_TAG].keys():
            if not self.ips_info[ORIGIN_SOURCE_TAG][ip]['desc'] == LOCAL_ADDRESS_TAG:
                self.ips_info[ORIGIN_SOURCE_TAG][ip] = self.query_ip_whois(ip)
        for ip in self.ips_info[ORIGIN_DESTINATION_TAG].keys():
            if not self.ips_info[ORIGIN_DESTINATION_TAG][ip]['desc'] == LOCAL_ADDRESS_TAG:
                self.ips_info[ORIGIN_DESTINATION_TAG][ip] = self.query_ip_whois(ip)
    def query_ip_whois(self, ip_addr):
        """ Given an ip_address, returns a dict containing IP-related information. Uses the IPWhois library
        """
        ret = None
        try:
            dom_obj = IPWhois(ip_addr)
            dom = dom_obj.lookup_whois()
            country_code = dom[IPWHOIS_ASN_CC_TAG]
            asn_desription = dom[IPWHOIS_ASN_DESC_TAG]
            
            # TODO: Add domain (from abuse email or emails)
            
            lat, lon = 0, 0 # Populated after cycle not to exceed API limits: https://ip-api.com/docs/api:batch
            ret = TIRegister.ip_info_entry(country_code, asn_desription, lat, lon, 1)


        except Exception as e:
            print('Exception: {}'.format(e)) if debug else None
            if str(e).__contains__('Multicast'):
                ret = TIRegister.ip_info_entry('Multicast', 'Multicast', 0, 0, 1)
            else:
                ret = TIRegister.ip_info_entry('Excepted', 'Excepted', 0, 0, 1)
        
        return ret


    ########################################################################
    #                           GET PORTS INFO                             #
    ########################################################################

    # TODO: Merge with ips function? Cycles over whole thing just once, dumps all info?
    def gather_ports_infos(self):
        """ Gathers used-ports related information and stores them to class instance register.
            Params:
                - side: string (constant)
                    ORIGIN_SOURCE_TAG : get ports infos of source port fields from input flows (self.data > to flows)
                    ORIGIN_DESTINATION_TAG : as above but takes destination ports
            NOTE:
                It gathers and processes the data from PacketsRegister.get_core_flows() format
        """
        
        for rejected_flow in self.rejected_flows:

            src_port = int(rejected_flow[SPORT_TAG]) if rejected_flow[SPORT_TAG] != '?' else -1
            dst_port = int(rejected_flow[DPORT_TAG]) if rejected_flow[DPORT_TAG] != '?' else -1
            
            if rejected_flow[TRANSPORT_PROTO_TAG] == '6': proto = 'tcp'
            elif rejected_flow[TRANSPORT_PROTO_TAG] == '17': proto = 'udp'
            else: proto = None
            print('processing sport -> dport: {} -> {}'.format(src_port, dst_port)) if debug else None

            try:
                src_service = socket.getservbyport(src_port, proto)
            except Exception as e:
                src_service = EPHEMERAL_TAG
                #src_service = str(src_port)

            try:
                dst_service = socket.getservbyport(dst_port, proto)
            except Exception as e:
                dst_service = EPHEMERAL_TAG
                #dst_service = str(dst_port)

            if src_service in self.ports_info[ORIGIN_SOURCE_TAG].keys():
                # Update counter of flows from specified port
                print('port/service {}/{} already in src ports register'.format(src_port, src_service)) if debug else None
                self.ports_info[ORIGIN_SOURCE_TAG][src_service]['cntr_flows'] += 1 # Counter is last index of list entry
            else:
                # Populate new entry
                print('Retrieving infos for src port/service {}/{}'.format(src_port, src_service)) if debug else None
                self.ports_info[ORIGIN_SOURCE_TAG][src_service] = TIRegister.port_info_entry(src_port, proto, 1)

            if dst_service in self.ports_info[ORIGIN_DESTINATION_TAG].keys():
                print('port/service {}/{} already in dst ports register'.format(dst_port, dst_service)) if debug else None
                self.ports_info[ORIGIN_DESTINATION_TAG][dst_service]['cntr_flows'] += 1 # Counter is last index of list entry
            else:
                print('Retrieving infos for dst port/service {}/{}'.format(dst_port, dst_service)) if debug else None
                self.ports_info[ORIGIN_DESTINATION_TAG][dst_service] = TIRegister.port_info_entry(dst_port, proto, 1)


    ##################################################################
    #                      Rule-out filtering                        #
    ##################################################################

    def filter_out_known_backend_flows_from_csv(self, csv_file):
        pass
    
    def filter_out_known_backends_pkts_from_pcap(self, pcap_file=None, flow_based=False):
        # TODO: INEFFICIENT, IMPROVE EFFICIENCY
        # NOTE: SRC addresses can be assumed benign, but malicious communication to DST backend ip addresses can happen. How TODO?
        #   > NOTE: Assuming that the scenario where BOTH SRC and DST are NOT-KNOWN is SUSPICIOUS
        """ Function that filters out all traffic that is very likely not harmful, as in
            it pertains to
                - IP Addresses from the Vendor
                - Amazon backends
                - Google backends
                - Microsoft backends
                - Notorious cloud supports and/or analysis
                - National security agencies?

                ALL AMAZON IPs
                https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html#filter-json-file

                ALL MICROSOFT IPs
                https://www.microsoft.com/en-us/download/confirmation.aspx?id=53602

                ALL GOOGLE IPs
                Google services https://www.gstatic.com/ipranges/goog.json
                Google CLOUD https://www.gstatic.com/ipranges/cloud.json

                ALL APPLE IPs - BEWARE NOT OFFICIAL
                https://ipinfo.io/AS714#blocks
            
            Params:
                pcap_file=None : pcap file to filter known backends from. If set to none, tries to use TIRegister self file.
                                checking if it's a pcap. Otherwise, has to be run with a generic pcap file

        """

        # Checks
        if pcap_file is not None and not os.path.isfile(pcap_file):
            raise ValueError('>>> File not found: {} \nBe sure to pass in a valid reachable path.'.format(pcap_file))
        if pcap_file is not None and not pcap_file.endswith('.pcap'):
            raise ValueError('>>> Passed file is not .pcap. Only .pcap is supported. File: {}'.format(pcap_file))
        file_ref = ''
        if pcap_file is None and self.data.endswith('.pcap'):
            file_ref = self.data
            print('\n>>> Generating known-backends-filtered rejected pcap from TIRegister instance data file: {}'.format(self.data))
        elif pcap_file is not None:
            file_ref = pcap_file
            print('\n>>> Generating known-backends-filtered rejected pcap from function argument file: {}'.format(pcap_file))
        if file_ref == '':
            raise ValueError('\n>>> Unable to resolve pcap file to filter. Either generate TIRegister instance with a pcap file as data param, or pass a pcap to this function')
        # / Chekcs
        
        out_name = os.path.splitext(os.path.basename(os.path.normpath(file_ref)))[0] + SUSPICIOUS_DATA_FILE_TAG + '.pcap'
        output_pcap = OUTPUTS_FOLDER + self.devname + '/' + out_name

        # NOTE: I pondered over having the filtered_backends register refer to already solved 'ranges', but DB-wise, I think
        #       it's better to have IP addresses as unique table keys, with respective information, eventually replicated over other IP addresses.
        #       I believe this would make practical the grouping, unions and retrieval of various information
        filtered_backends_ips = {}
        sus_ips = {}
        outpcap_writer = PcapWriter(output_pcap, append=False, sync=True)
        util_reg = PacketsRegister(type='Utility')
        
        # Inner per-packet scapy filtering function
        def refilter_on_knonw_backends(outpcap_writer, filtered_backends_ips, register):
            def inner(pkt):
                register.increment_tot_packets_counter()
                simple_progress_print(register.get_counter_tot_packets())

                if pkt.haslayer('IP'):
                    net_tag = 'IP'
                elif pkt.haslayer('IPv6'):
                    net_tag = 'IPv6'
                else:
                    raise ValueError('\n>>> Impossible to filter IPs from file, excepted packet without IP/v6 layer: {}'.format(pkt.summary()))
                    # TODO: Consider non-blocking ignore handling
                
                src = pkt[net_tag].src
                dst = pkt[net_tag].dst

                notorious_src = False
                notorious_dst = False

                src_already_sus = False
                dst_already_sus = False

                if src in sus_ips.keys():
                    #print('MATCH ON SUS SOURCE') if debug else None
                    src_already_sus = True
                    sus_ips[src] +=1
                if dst in sus_ips.keys():
                    #print('MATCH ON SUS DESTINATION') if debug else None
                    dst_already_sus = True
                    sus_ips[dst] +=1

                if not src_already_sus:
                    if src in filtered_backends_ips.keys():
                        print('MATCH ON SOURCE') if debug else None
                        notorious_src = True
                        filtered_backends_ips[src]['counter_src'] += 1
                    else:
                        print('NEW PACKET SRC {}'.format(src)) if debug else None
                        known_backend_src, service_src, range_src = self.is_known_backend(src)
                        if known_backend_src:
                            notorious_src = True
                            filtered_backends_ips[src] = {}
                            filtered_backends_ips[src]['service'] = service_src
                            filtered_backends_ips[src]['range'] = range_src
                            filtered_backends_ips[src]['counter_src'] = 1
                            filtered_backends_ips[src]['counter_dst'] = 0
                
                if not dst_already_sus:
                    if dst in filtered_backends_ips.keys():
                        print('MATCH ON DESTINATION') if debug else None
                        notorious_dst = True
                        filtered_backends_ips[dst]['counter_dst'] += 1
                    else:
                        print('NEW PACKET DST {}'.format(dst)) if debug else None
                        known_backend_dst, service_dst, range_dst = self.is_known_backend(dst)
                        if known_backend_dst:
                            notorious_dst = True
                            filtered_backends_ips[dst] = {}
                            filtered_backends_ips[dst]['service'] = service_dst
                            filtered_backends_ips[dst]['range'] = range_dst
                            filtered_backends_ips[dst]['counter_src'] = 0
                            filtered_backends_ips[dst]['counter_dst'] = 1
                
                # TODO: Add ranges to use for catching to utility register

                if not notorious_src and not src_already_sus: sus_ips[src] = 1
                if not notorious_dst and not dst_already_sus: sus_ips[dst] = 1
                
                # Save packet as suspicious if neither src and dst are known services
                if not notorious_src and not notorious_dst:
                    outpcap_writer.write(pkt)

            return inner

        sniff(offline=file_ref, prn=refilter_on_knonw_backends(outpcap_writer, filtered_backends_ips, util_reg), store=10)
        print('\n>>> The capture containing traffic from only non-notorious addresses has been saved at > \n{}'.format(output_pcap))



    ########################################################################
    #                               UTILITY                                #
    ########################################################################
    

    ############################## IPs Utility ##############################


    # Utility ip_info_entry
    @staticmethod
    def ip_info_entry(country_code, desc, lat, lon, cntr_flows):
        return {'country_code' : country_code, 'desc' : desc, 'lat_lon' : (lat, lon), 'cntr_flows' : cntr_flows}
    @staticmethod
    def unresolved_ip_entry():
        return TIRegister.ip_info_entry(UNRESOLVED_TAG, UNRESOLVED_TAG, 0, 0, 1)


    def get_ips_infos(self, side):
        """ Returns list of per-flow IP information, as saved in the ips_info instance dictionary
            Params:
            - side: either ORIGIN_SOURCE_TAG or ORIGIN_DESTINATION_TAG,
                Specifies wether to get ips_info about
                    source addresses of flows in traffic data, or
                    destination addresses of flows in traffic data
        """

        # Parameter checks
        if not (side == ORIGIN_SOURCE_TAG or side == ORIGIN_DESTINATION_TAG):
            print('Unknown IP side type for register: {}. Accepted sides: {}, {}'.format(side, ORIGIN_SOURCE_TAG, ORIGIN_DESTINATION_TAG))

        if len(self.ips_info[side]) == 0:
            raise ValueError('Looks like registers are empty. Try run <ti_register>.gather_ips_info() first.')
        
        return self.ips_info[side]

    
    def get_ips_graph_data_description_per_flows(self):
        """ Gives information of flow-based frequencies of IP addresses found in source or destination fields, taken
                from the ips_info class register
        """
        if len(self.ips_info[ORIGIN_DESTINATION_TAG]) == 0 or len(self.ips_info[ORIGIN_SOURCE_TAG]) == 0:
            raise ValueError('Looks like registers are empty. Try run <ti_register>.gather_ips_info() first.')

        src_ips_graph_data = {}
        dst_ips_graph_data = {}

        src_ips_info = self.ips_info[ORIGIN_SOURCE_TAG]
        dst_ips_info = self.ips_info[ORIGIN_DESTINATION_TAG]

        for ip in src_ips_info.keys():
            asn = src_ips_info[ip]['desc']
            if asn in src_ips_graph_data.keys():
                src_ips_graph_data[asn] += int(src_ips_info[ip]['cntr_flows'])
            else:
                src_ips_graph_data[asn] = int(src_ips_info[ip]['cntr_flows'])
        
        for ip in dst_ips_info.keys():
            asn = dst_ips_info[ip]['desc']
            if asn in dst_ips_graph_data.keys():
                dst_ips_graph_data[asn] += int(dst_ips_info[ip]['cntr_flows'])
            else:
                dst_ips_graph_data[asn] = int(dst_ips_info[ip]['cntr_flows'])

        # Order by number of flows
        src_ips_graph_data = {k: v for k, v in sorted(src_ips_graph_data.items(), key=lambda item : (item[1], item[-1]))}
        dst_ips_graph_data = {k: v for k, v in sorted(dst_ips_graph_data.items(), key=lambda item : (item[1], item[-1]))}

        return src_ips_graph_data, dst_ips_graph_data



    ############################## Ports Utility ##############################

    @staticmethod
    def port_info_entry(port_number, tr_proto, cntr_flows):
        return {'number' : port_number, 'transport_proto' : tr_proto, 'cntr_flows' : cntr_flows}
        

    def get_ports_infos(self, side):
        """ Returns list of per-flow ports information, as saved in the ports_info instance dictionary
            Params:
            - side: either ORIGIN_SOURCE_TAG or ORIGIN_DESTINATION_TAG,
                Specifies wether to get ports_info about
                    source ports of flows in traffic data, or
                    destination ports of flows in traffic data
        """

        # Parameter checks
        if not (side == ORIGIN_SOURCE_TAG or side == ORIGIN_DESTINATION_TAG):
            print('Unknown origin side type for register: {}. Accepted sides: {}, {}'.format(side, ORIGIN_SOURCE_TAG, ORIGIN_DESTINATION_TAG))

        if len(self.ports_info[side]) == 0:
            raise ValueError('Looks like registers are empty. Try run <ti_register>.gather_ports_info() first.')
        return self.ports_info[side]


    def get_ports_graph_data_service_per_flows(self):
        """ Gives information of per-flow frequency of utilized ports in source and destination fields, from the ports_info
                class register.
            Returns:
                - <origin>_ports_graphs_data : {service/port : #flows}
                - src_dst_ports_graph_data = [src_port, dst_port, #packets]
        """
        if len(self.ports_info[ORIGIN_DESTINATION_TAG]) == 0 or len(self.ports_info[ORIGIN_SOURCE_TAG]) == 0:
            raise ValueError('Looks like registers are empty. Try run <ti_register>.gather_ports_info() first.')

        src_ports_graph_data = {}
        dst_ports_graph_data = {}

        src_dst_ports_graph_data = []

        src_ports_info = self.ports_info[ORIGIN_SOURCE_TAG]
        dst_ports_info = self.ports_info[ORIGIN_DESTINATION_TAG]

        for service in src_ports_info.keys():
            if service in src_ports_graph_data.keys():
                src_ports_graph_data[service] += int(src_ports_info[service]['cntr_flows'])
            else:
                src_ports_graph_data[service] = int(src_ports_info[service]['cntr_flows'])
        
        for service in dst_ports_info.keys():
            if service in dst_ports_graph_data.keys():
                dst_ports_graph_data[service] += int(dst_ports_info[service]['cntr_flows'])
            else:
                dst_ports_graph_data[service] = int(dst_ports_info[service]['cntr_flows'])

        for rejected_flow in self.rejected_flows:
            # TODO: Add UDP/TCP information
            src_port = int(rejected_flow[SPORT_TAG]) if rejected_flow[SPORT_TAG] != '?' else -1
            dst_port = int(rejected_flow[DPORT_TAG]) if rejected_flow[DPORT_TAG] != '?' else -1

            if rejected_flow[TRANSPORT_PROTO_TAG] == '6': proto = 'tcp'
            elif rejected_flow[TRANSPORT_PROTO_TAG] == '17': proto = 'udp'
            else: proto = None

            try:
                src_service = socket.getservbyport(src_port, proto)
            except Exception as e:
                src_service = EPHEMERAL_TAG
                #src_service = str(src_port)

            try:
                dst_service = socket.getservbyport(dst_port, proto)
            except Exception as e:
                #dst_service = str(dst_port)
                dst_service = EPHEMERAL_TAG

            src_dst_ports_graph_data.append([src_service, dst_service, rejected_flow[PACKETS_NUMBER_TAG]])
            
        """
            # Merge one-flow ports
            src_one_flow_only = {SINGLETON_SRC_PORT_PER_FLOW_TAG : 0}
            for k, v in src_ports_graph_data.items():
                if int(v) == 1:
                    src_one_flow_only[SINGLETON_SRC_PORT_PER_FLOW_TAG] += v
            src_ports_graph_data[SINGLETON_SRC_PORT_PER_FLOW_TAG] = src_one_flow_only[SINGLETON_SRC_PORT_PER_FLOW_TAG]

            dst_one_flow_only = {SINGLETON_DST_PORT_PER_FLOW_TAG : 0}
            for v in dst_ports_graph_data.values():
                if int(v) == 1:
                    dst_one_flow_only[SINGLETON_DST_PORT_PER_FLOW_TAG] += v
            dst_ports_graph_data[SINGLETON_DST_PORT_PER_FLOW_TAG] = dst_one_flow_only[SINGLETON_DST_PORT_PER_FLOW_TAG]
            
            # for src_dst_ports_graph_data, single flow is given on single packet
            
            src_ports_graph_data = {k: v for k, v in src_ports_graph_data.items() if int(v) > 1}
            dst_ports_graph_data = {k: v for k, v in dst_ports_graph_data.items() if int(v) > 1}


            src_ports_graph_data = {k: v for k, v in sorted(src_ports_graph_data.items(), key=lambda item : item[1], reverse=True) if int(v) > 1}
            dst_ports_graph_data = {k: v for k, v in sorted(dst_ports_graph_data.items(), key=lambda item : item[1], reverse=True) if int(v) > 1}
        """
        return src_ports_graph_data, dst_ports_graph_data, src_dst_ports_graph_data



    ############################## Class Utility ##############################

    def populate_known_ranges(self):
        """ Populates class dictionaries with IP ranges from well-known service providers
        """
        # Amazon
        try:
            amz_ip_ranges = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json').json()['prefixes']
            amazon_ips = {data['ip_prefix']: data['service'] for data in amz_ip_ranges}
            self.amazon_ip_ranges = amazon_ips
        except Exception as e:
            print('>>> {}'.format(e))
            print('>>> Failed to fetch IP ranges from Amazon @ https://ip-ranges.amazonaws.com/ip-ranges.json')
        
        # Microsoft
        try:
            msft_ip_ranges = {}
            with open(MICROSOFT_IP_RANGES_CSV, newline='') as csv_file:
                csv_reader = csv.DictReader(csv_file, delimiter=',')
                for row in csv_reader:
                    msft_ip_ranges[row['Prefix']] = row['Type']
            self.microsoft_ip_ranges = msft_ip_ranges
        except Exception as e:
            print('>>> {}'.format(e))
            print('>>> Failed to fetch IP ranges from Microsoft @ file {}'.format(MICROSOFT_IP_RANGES_CSV))
        
        # Google
        try:
            ggl_ip_ranges = requests.get('https://www.gstatic.com/ipranges/goog.json').json()['prefixes']
            pprint(ggl_ip_ranges) if debug else None
        except Exception as e:
            print('>>> {}'.format(e))
            print('>>> Failed to fetch IP ranges from Google @ https://www.gstatic.com/ipranges/goog.json')
        try:
            ggl_cloud_ip_ranges = requests.get('https://www.gstatic.com/ipranges/cloud.json').json()['prefixes']
            pprint(ggl_cloud_ip_ranges) if debug else None
        except Exception as e:
            print('>>> {}'.format(e))
            print('>>> Failed to fetch cloud IP ranges from Google Clouds @ https://www.gstatic.com/ipranges/cloud.json')
        ggl_ips = {list(data.values())[0] : list(data.keys())[0] for data in ggl_ip_ranges}
        ggl_cl_ips = {list(data.values())[0] : data['scope'] for data in ggl_cloud_ip_ranges}
        pprint(ggl_ips) if debug else None
        pprint(ggl_cl_ips) if debug else None
        self.google_ip_ranges = {**ggl_ips, **ggl_cl_ips}
        pprint(self.google_ip_ranges) if debug else None


    def is_known_vpn(self, ip_addr):
        """ Checks saved numpy array list of known VPN IP ranges and addresses
        """
        ip = ''
        i = 0
        try:
            ip = ipaddress.ip_address(ip_addr)
        except Exception as e:
            print(e)
            print('Could not solve ip [ {} ] to a valid ipaddress library object'.format(ip_addr))
        if (type(ip) == ipaddress.IPv4Address):
            for item in KNOWN_IPV4_VPNS:
                i += 1
                print(i)
                if ip in ipaddress.ip_network(item):
                    return True, item
        elif (type(ip) == ipaddress.IPv6Address):
            for item in KNOWN_IPV6_VPNS:
                if ip in ipaddress.ip_network(item):
                    return True, item
        else:
            raise ValueError('Could not match ip address [ {} ] to a valid ipaddress library type'.format(ip_addr))
        # Did not return anything before, so no matches
        return False, None
        

    def is_known_backend(self, ip_addr):

        # TODO: Make more efficient with IPv4, IPv6 distinction, and smarter lookup iterating on IP param possible subnets
        # REVERSE(/8, /9, ..., /23, /24) for IPv4 (constant time check instead of whole register)
        # Idk how IPv6 works exactly

        for range in self.amazon_ip_ranges.keys():
            if ipaddress.ip_address(ip_addr) in ipaddress.ip_network(range):
                return True, AMAZON_ADDRESS_TAG, range
        for range in self.microsoft_ip_ranges.keys():
            if ipaddress.ip_address(ip_addr) in ipaddress.ip_network(range):
                return True, MICROSOFT_ADDRESS_TAG, range
        for range in self.google_ip_ranges.keys():
            if ipaddress.ip_address(ip_addr) in ipaddress.ip_network(range):
                return True, GOOGLE_ADDRESS_TAG, range
        
        # If here, address was not resolved
        return False, None, None

        

         
if __name__ == '__main__':
    file = OUTPUTS_FOLDER + 'ieee-ezviz-complete/mirai-httpflooding-all-ezviz-rejected.json'
    ti_reg_test = TIRegister(file, 'ieee-ezviz')
    ti_reg_test.populate_known_ranges()
    #pcap = OUTPUTS_FOLDER + 'ieee-ezviz-complete/mirai-httpflooding-all-ezviz-rejected.pcap'
    pcap = OUTPUTS_FOLDER + 'ieee-ezviz/mirai-httpflooding-all-ezviz-rejected-sus.pcap'
    ti_reg_test.filter_out_known_backends_pkts_from_pcap(pcap_file=pcap)
