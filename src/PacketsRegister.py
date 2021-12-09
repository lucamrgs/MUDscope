
import json
from Flow import Flow
from Constants import *
from scapy.all import *

debug = False

# TODO: Change name to RejectedTrafficRegister
class PacketsRegister:

    # TODO: Logically link to VMUDEnforcer and include meta-data
    #   INITIALIZE REGISTER ON PCAP FILE
    # TODO: Add timings for filtering
    # TODO: Add VOLUME of traffic per flow (pkt size)

    def __init__(self, type='VMUDEnforcer'):
        self.__type = type # Utility variable to know how the register is expected to be populated/used
        self.counter_tot_packets = 0
        self.counter_rejected_packets = 0
        self.counter_accepted_packets = 0
        self.counter_unrelated_packets = 0
        self.counter_bootstrap_packets = 0
        self.counter_unhandled_packets = 0
        self.accepted_pkt_flows = {}
        self.rejected_pkt_flows = {}
        self.bootstrap_pkt_flows = {}
        self.counter_accepted_pkt_flows = 0
        self.counter_rejected_pkt_flows = 0
        self.counter_bootstrap_pkt_flows = 0
        self.unhandled_packets = {
                'arp_counter': 0,
                'eapol_counter' : 0,
                'ipv6_counter' : 0,
                '802.3_counter' : 0,
                'other_counter' : 0
            }
        self.unhandled_packets_data = []

    @classmethod
    def from_json(cls, file):
        # NOTE: consider os.path.abspath(file_path)
        """ Generates and populates new PacketsRegister class isntance from json file
            Json file is assumed to be obtained from the PacketsRegister.to_json() function
        """
        register = cls()
        try:
            with open(file) as f:
                reg_json = json.load(f)
            for k in reg_json.keys():
                setattr(register, k, reg_json[k])
        except Exception as e:
            print(e)
            print('Impossible to generate class instance from JSON file {}'.format(file))    
        #print(json.dumps(reg_json, indent=4))
        #print(register.to_json())
        return register

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, indent=4)


    # Counters getters
    def get_counter_tot_packets(self):
        return self.counter_tot_packets
    def get_counter_rejected_packets(self):
        return self.counter_rejected_packets
    def get_counter_accepted_packets(self):
        return self.counter_accepted_packets
    def get_counter_unrelated_packets(self):
        return self.counter_unrelated_packets
    def get_counter_bootstrap_packets(self):
        return self.counter_bootstrap_packets
    def get_counter_unhandled_packets(self):
        return self.counter_unhandled_packets

    # Counters incrementers
    def increment_tot_packets_counter(self):
        self.counter_tot_packets += 1
    def increment_rejected_packets_counter(self):
        self.counter_rejected_packets += 1
    def increment_accepted_packets_counter(self):
        self.counter_accepted_packets  += 1
    def increment_unrelated_packets_counter(self):
        self.counter_unrelated_packets += 1
    def increment_bootstrap_packets_counter(self):
        self.counter_bootstrap_packets += 1
    def increment_unhandled_packets_counter(self):
        self.counter_unhandled_packets += 1

    # O(1) checks if flow already saved
    def is_accepted_flow_registered(self, flow_key):
        return (flow_key in self.accepted_pkt_flows.keys())
    def is_rejected_flow_registered(self, flow_key):
        return (flow_key in self.rejected_pkt_flows.keys())
    def is_bootstrap_flow_registered(self, flow_key):
        return (flow_key in self.bootstrap_pkt_flows.keys())

    def is_flow_registered(self, flow_key):
        return (self.is_accepted_flow_registered(flow_key) or self.is_rejected_flow_registered(flow_key) or self.is_bootstrap_flow_registered(flow_key))

    # Flow regiters updates. Handle both cases where flow is new, or has to be updated
    def update_accepted_flows(self, flow_key):
        if not self.is_accepted_flow_registered(flow_key):
            self.accepted_pkt_flows[flow_key] = 1
            return NEW_FLOW
        else:
            self.accepted_pkt_flows[flow_key] += 1
            self.increment_accepted_packets_counter()
            return UPDATED_FLOW
    def update_rejected_flows(self, flow_key):
        if not self.is_rejected_flow_registered(flow_key):
            self.rejected_pkt_flows[flow_key] = 1
            return NEW_FLOW
        else:
            self.rejected_pkt_flows[flow_key] += 1
            self.increment_rejected_packets_counter()
            return UPDATED_FLOW
    def update_bootstrap_flows(self, flow_key):
        if not self.is_bootstrap_flow_registered(flow_key):
            self.bootstrap_pkt_flows[flow_key] = 1
            return NEW_FLOW
        else:
            self.bootstrap_pkt_flows[flow_key] += 1
            self.increment_bootstrap_packets_counter()
            return UPDATED_FLOW

    def update_unhandled_packets(self, unhandled_type, packet_data):
        if unhandled_type == ARP_TAG:
            self.unhandled_packets['arp_counter'] += 1
        elif unhandled_type == EAPOL_TAG:
            self.unhandled_packets['eapol_counter'] += 1
        elif unhandled_type == IPV6_TAG:
            self.unhandled_packets['ipv6_counter'] += 1
        elif unhandled_type == ETH802_3_TAG:
            self.unhandled_packets['802.3_counter'] += 1
        elif unhandled_type == OTHERS_TAG:
            self.unhandled_packets['other_counter'] += 1
        else:
            raise ValueError('Incorrect unhandled packet type: {}.'.format(unhandled_type))

        self.unhandled_packets_data.append(packet_data)

    def total_accepted_flows(self):
        tot = len(self.accepted_pkt_flows.keys())
        self.counter_accepted_pkt_flows = tot
        return tot
    def total_rejected_flows(self):
        tot = len(self.rejected_pkt_flows.keys())
        self.counter_rejected_pkt_flows = tot
        return tot
    def total_bootstrap_flows(self):
        tot = len(self.bootstrap_pkt_flows.keys())
        self.counter_bootstrap_pkt_flows = tot
        return tot

    def update_flow_counters(self):
        self.total_accepted_flows()
        self.total_rejected_flows()
        self.total_bootstrap_flows()

    # TODO: Could make CSV file for memory efficiency
    def get_core_flows(self, flows_list):
        output = []
        # TODO: Not tuples but dicts
        if flows_list == REJECTED_TRAFFIC:
            for k, v in self.rejected_pkt_flows.items():
                flow = Flow.get_pkt_flow_data_from_dict_key(k)
                core_flow = ({SIP_TAG: flow.sip, DIP_TAG: flow.dip, SPORT_TAG: flow.sport, DPORT_TAG: flow.dport, TRANSPORT_PROTO_TAG: flow.ip_proto, PACKETS_NUMBER_TAG : v})
                output.append(core_flow)
        elif flows_list == ACCEPTED_TRAFFIC:
            for k, v in self.accepted_pkt_flows.items():
                flow = Flow.get_pkt_flow_from_dict_key(k)
                core_flow = ({SIP_TAG: flow.sip, DIP_TAG: flow.dip, SPORT_TAG: flow.sport, DPORT_TAG: flow.dport, TRANSPORT_PROTO_TAG: flow.ip_proto, PACKETS_NUMBER_TAG : v})
                output.append(core_flow)
        elif flows_list == BOOTSTRAP_TRAFFIC:
            for k, v in self.bootstrap_pkt_flows.items():
                flow = Flow.get_pkt_flow_from_dict_key(k)
                core_flow = ({SIP_TAG: flow.sip, DIP_TAG: flow.dip, SPORT_TAG: flow.sport, DPORT_TAG: flow.dport, TRANSPORT_PROTO_TAG: flow.ip_proto, PACKETS_NUMBER_TAG : v})
                output.append(core_flow)
        else:
            raise ValueError('Unrecognised flows-list type: {}'.format(flows_list))
        
        return output

    @classmethod
    def create_dict_key_from_scapy_pkt_flow(scapy_pkt_flow):
        if scapy_pkt_flow.origin != Flow.origin_types[ORIGIN_SCAPY_PACKET]:
            raise ValueError('Attempting flow dict_key generation from non-packet originated flow {}.'.format(scapy_pkt_flow.get_json_flow_data()))
        else:
            return FLOW_INFO_JOIN_CHAR.join([scapy_pkt_flow.smac, scapy_pkt_flow.dmac, scapy_pkt_flow.eth_type, scapy_pkt_flow.sip, scapy_pkt_flow.dip, scapy_pkt_flow.sport, scapy_pkt_flow.dport, scapy_pkt_flow.ip_proto])


    
    def populate_flows_from_pcap(self, pcap_file, pcap_limit=None, flow_type=REJECTED_TRAFFIC, mode=FILTER_MODE_LISTEN):
        # All packets are of interest. Just has to populate packet flows

        if not os.path.isfile(pcap_file) or not pcap_file.endswith('.pcap'):
            raise ValueError('Unknown or invalid data: {}\n Data parameter must be a file path.'.format(pcap_file))

        if pcap_limit is not None:
            pcap_limit = int(pcap_limit)
            print('>>> Packet limit set at {}'.format(pcap_limit))

        print('>>> Generating flows information from file: {}'.format(pcap_file))

        def collect_pcap_data(self):
            def inner(pkt):
                simple_progress_print(self.get_counter_tot_packets())
                self.increment_tot_packets_counter()
                if not (pkt.haslayer('Ether') and pkt.haslayer('IP')): #Flow cannot be generated
                    print('Ethernet or IP layer not found - cannot create packet flow. Packet summary: {}'.format(pkt.summary())) if debug else None
                    
                    flag_known_case = False

                    if (pkt.haslayer('EAPOL')):
                        self.update_unhandled_packets(EAPOL_TAG, pkt.summary())
                        flag_known_case = True
                    if (pkt.haslayer('ARP')):
                        self.update_unhandled_packets(ARP_TAG, pkt.summary())
                        flag_known_case = True
                    if (pkt.haslayer('802.3')):
                        self.update_unhandled_packets(ETH802_3_TAG, pkt.summary())
                        flag_known_case = True
                    if (pkt.haslayer('IPv6')):
                        self.update_unhandled_packets(IPV6_TAG, pkt.summary())
                        flag_known_case = True
                    
                    if not flag_known_case:
                        self.update_unhandled_packets(OTHERS_TAG, pkt.summary())

                # Generate flow data from packets
                pkt_flow = Flow.from_scapy_pkt(pkt)
                
                if pkt_flow == -1:
                    raise ValueError('A flow could not be parsed from packet {} \n{}'.format(pkt.summary(), pkt.show()))

                # NOTE: CONSIDER MEMORY USAGE
                pkt_flow_dict_key = pkt_flow.create_dict_key()

                print('PKT FLOW DICT KEY: {}'.format(pkt_flow_dict_key)) if debug else None
                
                if mode == FILTER_MODE_BLOCK:
                    if self.is_flow_registered(pkt_flow_dict_key):
                        return FLOW_ALREADY_RECORDED

                # update_*_flows handles flow already existing, or to be created and registered

                # BOOTSTRAP PORTS - automatic filtering
                if (pkt.haslayer('UDP')):
                    if (pkt['UDP'].sport == int(BOOTSTRAP_CLNT_PORT) and pkt['UDP'].dport == int(BOOTSTRAP_SRVR_PORT)) or (pkt['UDP'].sport == int(BOOTSTRAP_SRVR_PORT) and pkt['UDP'].dport == int(BOOTSTRAP_CLNT_PORT)):
                        self.update_bootstrap_flows(pkt_flow_dict_key)
                        return PKT_BOOTSTRAP
                
                # Otherwise, simple rejected packet belonging to flow
                if flow_type == REJECTED_TRAFFIC:
                    self.update_rejected_flows(pkt_flow_dict_key)
                elif flow_type == ACCEPTED_TRAFFIC:
                    pass
                else:
                    raise ValueError('Unknown flow_type parameter specified: {}\nAccepts REJECTED_TRAFFIC or ACCEPTED_TRAFFIC constants'.format(flow_type))

            return inner

        if pcap_limit is not None:
            sniff(offline=pcap_file, prn=collect_pcap_data(self), store=10, count=pcap_limit)
        else:
            sniff(offline=pcap_file, prn=collect_pcap_data(self), store=10)
