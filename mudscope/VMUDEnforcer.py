
import csv
from pathlib import Path
from scapy.all import *

from pprint import pprint

from mudscope.Flow import Flow
from mudscope.Constants import *
from mudscope.PacketsRegister import PacketsRegister

# Takes as input:
#   * pcap file
#   * MUDgee generated rules (result/<device>/<device>rule.csv)
#       NOTE: rules shall represent a whitelist (all rest: drop)
#   * device MAC
#   * gateway MAC
#
# Then scans through a pcap,
#   - first selects packets to/from device (mac)
#   - then matches packet against rules
#       - if match ok, nothing relevant
#       - if match fails, save packet to other pcap
#
# Possibly, extend input type to FLOWS (or don't, it's desireable to have the whole information anyway)

"""
    TODO TODO: Check OF Filtering table address resolution! Some legit IPs may be discarded depending on how they are solved, and the one registered in the pcap!
    TODO: Manage ICMP (what about IGMP?)
"""

debug = False

class Virtual_MUD_enforcer:

    def __init__(self, device_mac, device_name, gateway_mac, filter_rules):
        self.devname = device_name
        self.devmac = device_mac
        self.gwmac = gateway_mac
        self.rules = []
        with open(filter_rules) as csv_f:
            reader = csv.DictReader(csv_f)
            for row in reader:
                self.rules.append(Flow.from_of_rule(row, device_mac, gateway_mac))
    




    ##################################################################################################
    # Enforcing routines
    ##################################################################################################
    
    def enforce_online(self, interface, time_limit=None):

        # NOTE: This is not a switch, so all traffic device-related does happen. This routine "dumps" packets
        #   that SHOULD NOT reach the device, but does not block them.
        #   Project-wise, it would be better to actually BLOCK and evtl RE-ROUTE unauthorized packets, to give more deployment-realistic data
        # TODO: Collection metadata and format

        # Name output file and setup output location. File is named as <pcap>-<rejected-tag>.pcap
        output_basename = self.devname + '-onlilne' + REJECTED_DATA_FILE_TAG
        output_pcap = output_basename + '.pcap'
        output_location = OUTPUTS_FOLDER + self.devname + '/'
        output_full_path = output_location + output_pcap

        # Write pcap to device-referred output location
        if not Path(output_location).exists():
            Path(output_location).mkdir(parents=True, exist_ok=True)
        if not Path(output_full_path).is_file():
            open(output_full_path, 'w+').close()

        outpcap_writer = PcapWriter(output_full_path, append=False, sync=True)
        # TODO: support autonomous generation of register form rejected pcap
        pcap_register = PacketsRegister()

        # Inner function for sniff filtering
        def analyse_packet(outpcap_writer, pcap_reg):
            def inner(pkt):
                self.scapy_inner_sniff_callback(pkt, pcap_reg, outpcap_writer)
            
            # Allows working with sniff. Also, direct filter declaration is sniff appears to be BUG ged in OSX
            return inner


        # default to 1 min capture, 60 seconds
        if time_limit is None:
            time_limit = 60

        print('>>> Analyzing online traffic from iface {} \n>>> Timer set for [ {} ] seconds'.format(interface, time_limit), end='', flush=True)
        sniff(iface=interface, prn=analyse_packet(outpcap_writer, pcap_register), store=10, timeout=time_limit)

        # Update Flow counters of register
        pcap_register.update_flow_counters()

        #print(pcap_register.get_core_flows(REJECTED_TRAFFIC))

        # JSON Register for utility
        output_json = output_basename + '.json'
        pcap_reg_fullpath = output_location + output_json
        json_pcap_register = open(pcap_reg_fullpath, 'w')
        json_pcap_register.write(pcap_register.to_json())
        #print('\n' + pcap_register.to_json())
        json_pcap_register.close()
        
        print('\n>>> Rejected packets collected in {}\n>>> Pcap register saved in {}'.format(output_pcap, output_json))






    def enforce_in_pcap(self, pcap_file, pcap_limit=None, save_json=False, named_dir=None):

        """ Read pcap and apply device-specific flow rules
        """
        print(f">>> DEBUG: NAMED DIR = {named_dir}")
        # Name output file and setup output location. File is named as <pcap>-<rejected-tag>.pcap

        # Set default named_dir
        if named_dir is None:
            named_dir = OUTPUTS_FOLDER

        # Generate output path
        output_full_path = (
            Path(named_dir).absolute() /
            self.devname /
            f"{Path(pcap_file).stem}{REJECTED_DATA_FILE_TAG}.pcap"
        )

        # Ensure directory exists
        output_full_path.parent.mkdir(parents=True, exist_ok=True)

        # Write pcap to device-referred output location
        if not Path(output_full_path).is_file():
            open(output_full_path, 'w+').close()
        
        outpcap_writer = PcapWriter(str(output_full_path), append=False, sync=True)

        # TODO: support autonomous generation of register form rejected pcap
        pcap_register = PacketsRegister()

        print('>>> Analyzing pcap {} \n'.format(pcap_file), end='', flush=True)
        if pcap_limit is not None:
            pcap_limit = int(pcap_limit)
            print('>>> Packet limit set at {}'.format(pcap_limit))

        # Nested function #1
        def analyse_packet(pcap_reg, outpcap_writer):
            """ Nested function to process input packet by packet. Needed to pass parameters to packet processing
            
                Parameters
                ----------
                pcap_reg : dictionary 
                    Defined above, contains utility information on current processing
                outpcap_writer : scapy:PcapWriter
                    Writer to output pcap to append the filtered packets
            
                Returns
                -------
                inner: fcn
                    Filtering function used by scapy:sniff
            """
            # Nested function #2
            def inner(pkt):
                self.scapy_inner_sniff_callback(pkt, pcap_reg, outpcap_writer)

            # Allows working with sniff. Also, direct filter declaration is sniff appears to be BUG ged in OSX
            return inner

        # TODO: Start sniffing after device is bootstrapped, which is from when the MUD is enforced, of course

        if pcap_limit is not None:
            sniff(offline=pcap_file, prn=analyse_packet(pcap_register, outpcap_writer), store=10, count=pcap_limit)
        else:
            sniff(offline=pcap_file, prn=analyse_packet(pcap_register, outpcap_writer), store=10)
        
        # Update Flow counters of register
        pcap_register.update_flow_counters()

        #pprint(pcap_register.get_core_flows(REJECTED_TRAFFIC))

        """
        NOTE:   PARAMOUNT THING TO CONSIDER
        NOTE:   WORKAROUND: Added to insert at least one packet in MRT traffic - so that my pipeline does not crash with the whole amount of processing later
                If 0 packets are rejected, I still say I 'reject' the first packet (with TCP or UDP layer) from the capture.
        """
        try:
            cap = rdpcap(str(output_full_path))
        except scapy.error.Scapy_Exception as e:
            PACKETS_COPY = 1
            count = 0
            for pkt in PcapReader(pcap_file):
                if pkt.haslayer('UDP') or pkt.haslayer('TCP'):
                    outpcap_writer.write(pkt)
                    count += 1
                if count == PACKETS_COPY:
                    break

        # JSON Register for utility
        if save_json:
            with open(output_full_path.with_suffix('.json'), 'w') as outfile:
                outfile.write(pcap_register.to_json())

            print('>>> Pcap register saved in {}'.format(self.devname + REJECTED_DATA_FILE_TAG + '.json'))

        
        print('\n>>> Rejected packets collected in {}\n'.format(output_full_path))




    ##################################################################################################
    # MUDgee filtering
    ##################################################################################################


    def scapy_inner_sniff_callback(self, pkt, pcap_reg, outpcap_writer):

        pcap_reg.increment_tot_packets_counter()
        
        # Progression prints to terminal
        simple_progress_print(pcap_reg.get_counter_tot_packets())

        # TODO: Parse MACs and handle multicast (?)

        # Discard packets not to/from device. Broadcast packets are also considered
        if not self.is_pkt_of_interest(pkt):
            pcap_reg.increment_unrelated_packets_counter()
            return

        # MUDgee filtering invocation
        filter_res = self.filter_mudgee_rule(pkt, pcap_reg)
        
        # TODO: include volume of communication! Packet sizes
        # Update pcap sniff general data
        if filter_res == PKT_ACCEPTED:
            pcap_reg.increment_accepted_packets_counter()
        elif filter_res == PKT_REJECTED:
            # Append pcap to output pcap file
            outpcap_writer.write(pkt)
            pcap_reg.increment_rejected_packets_counter()
        elif filter_res == PKT_ERROR: # error packets
            if debug:
                pkt.show()
            pcap_reg.increment_unhandled_packets_counter()
        elif filter_res == PKT_BOOTSTRAP:
            pcap_reg.increment_bootstrap_packets_counter()
        elif filter_res == FLOW_ALREADY_RECORDED:
            return



    def filter_mudgee_rule(self, pkt, pcap_reg, mode=FILTER_MODE_LISTEN):
        """ Nested function to process input packet by packet. In charge of generating packet flow and handling cases.
            
            Parameters
            ----------
            pkt : scapy:Packet 
                Packet to match against allowed flows
            pcap_reg : dictionary
                Defined above, contains utility info for current pcap analysis
            mode : string constant
                Indicates wheter to not consider all flows that are already recorded, as a semi-simulation of actual blocking behaviour
                NOTE: It records both incoming connection flow, and outgoing connection flow (or vice versa), where the second flow would not
                    be detected, in case of an actual enforcement
            
            Returns: MUD filtering result
            -------
            Integer
                1 : packet accepted - PKT_ACCEPTED
                -1: packet rejected - PKT_REJECTED
                2: bootstrap packet, accepted - PKT_BOOTSTRAP
                0 : unhandled error in reading packet - PKT_ERROR
        """

        # NOTE: MUDgee flow table is designed on OpenFlow standard
        # DONE: FIX IP PARSING WHICH GIVES ERRORS AND DROPS PACKETS
        
        print('############## filtering packet ##############') if debug else None

        # TODO: extend to non-ether/non-ip cases 
        #   >>> ARP
        #   >>> IPv6
        #   >>> EAPOL
        #   >>> 802.3
        # TODO: change to still account for above protocol packets directed/from interested device:
        #   - at this point, packet interest the device (to/from), because of above filtering
        #   - the packet is rejected because it cannot be matched against filter rules
        #   - 
        if not (pkt.haslayer('Ether') and pkt.haslayer('IP')): #Flow cannot be generated
            
            print('Ethernet or IP layer not found - cannot create packet flow. Packet summary: {}'.format(pkt.summary())) if debug else None
            
            flag_known_case = False

            if (pkt.haslayer('EAPOL')):
                pcap_reg.update_unhandled_packets(EAPOL_TAG, pkt.summary())
                flag_known_case = True
            if (pkt.haslayer('ARP')):
                pcap_reg.update_unhandled_packets(ARP_TAG, pkt.summary())
                flag_known_case = True
            if (pkt.haslayer('802.3')):
                pcap_reg.update_unhandled_packets(ETH802_3_TAG, pkt.summary())
                flag_known_case = True
            if (pkt.haslayer('IPv6')):
                pcap_reg.update_unhandled_packets(IPV6_TAG, pkt.summary())
                flag_known_case = True
            
            if not flag_known_case:
                pcap_reg.update_unhandled_packets(OTHERS_TAG, pkt.summary())

            return PKT_ERROR


        # Generate flow data from packets
        pkt_flow = Flow.from_scapy_pkt(pkt)
        
        if pkt_flow == -1:
            # debug
            raise ValueError('A flow could not be parsed from packet {} \n{}'.format(pkt.summary(), pkt.show()))

        # NOTE: CONSIDER MEMORY USAGE

        pkt_flow_dict_key = pkt_flow.create_dict_key()

        if debug:
            print('PKT FLOW DICT KEY: {}'.format(pkt_flow_dict_key))

        if mode == FILTER_MODE_BLOCK:
            if pcap_reg.is_flow_registered(pkt_flow_dict_key):
                return FLOW_ALREADY_RECORDED

        # update_*_flows handles flow already existing, or to be created and registered

        # BOOTSTRAP PORTS - automatic filtering
        if (pkt.src == self.devmac and pkt.haslayer('UDP')):
            if (pkt['UDP'].sport == int(BOOTSTRAP_CLNT_PORT) and pkt['UDP'].dport == int(BOOTSTRAP_SRVR_PORT)) or (pkt['UDP'].sport == int(BOOTSTRAP_SRVR_PORT) and pkt['UDP'].dport == int(BOOTSTRAP_CLNT_PORT)):
                pcap_reg.update_bootstrap_flows(pkt_flow_dict_key)
                return PKT_BOOTSTRAP

        # Otherwise, FILTERING MATCH AGAINST EACH RULE
        filter_mask = []
        for rule in self.rules:
            filter_mask.append(Flow.equals(rule, pkt_flow))

        # Check if a rule is matched, return corresponding outcome
        if True in filter_mask:
            if debug:
                print('~~ PKT ACCEPTED ~~')
                print('Filter mask: {}'.format(filter_mask))
            # Update hash register
            pcap_reg.update_accepted_flows(pkt_flow_dict_key)
            return PKT_ACCEPTED
        else:
            if debug:
                print('>> PKT REJECTED <<')
                print('Filter mask: {}'.format(filter_mask))
                pkt.show()

            # TODO: Manage edge cases EAPOL: AuthN, ARP, Unsupported filtering: IPv6, 802.3
            
            # Update hash register
            pcap_reg.update_rejected_flows(pkt_flow_dict_key)
            return PKT_REJECTED


    ##################################################################################################
    # Utility
    ##################################################################################################

    def is_mac_matched(self, rule_mac, mac):
        if rule_mac == GTW_MAC_TAG or rule_mac == DVC_MAC_TAG:
            if mac == self.devmac or mac == self.gwmac:
                return True
        else:
            if rule_mac == mac:
                return True
        return False

    def is_pkt_of_interest(self, pkt):
        ret = True
        # Discard packets not to/from device. Broadcast packets are also considered
        if ((pkt.dst != self.devmac and pkt.src != self.devmac) and pkt.dst != MAC_BROADCAST):
            ret = False
            if debug:
                print('pkt not device-related\ndevice mac: {}\npkt src mac: {}\npkt dst mac: {}\n'.format(self.devmac, pkt.src, pkt.dst))
                pkt.show()
        return ret

    @staticmethod # FROM MIT CODE @ https://gist.github.com/vladignatyev/06860ec2040cb497f0f3
    def progress(count, total, status=''):
        bar_len = 60
        filled_len = int(round(bar_len * count / float(total)))

        percents = round(100.0 * count / float(total), 1)
        bar = '=' * filled_len + '-' * (bar_len - filled_len)

        sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', status))
        sys.stdout.flush()




if __name__ == '__main__':
    # Testing...

    # DEVICE MAC wlan 30m D-LINK e4:6f:13:d3:0f:22

    # Phillips Hue IoT-23 00:17:88:75:b3:82

    pcapfile = "outputs/ieee-ezviz-complete/mirai-ackflooding-all-ezviz-rejected.pcap"
    gw_mac = "b8:27:eb:fd:68:e2"
    dv_mac = "00:0c:43:b0:b6:4b"
    filter_rules = "./result/eyeplus-babycam/eyeplus-babycamrule.csv"

    #test_enforcer = Virtual_MUD_enforcer(dv_mac, 'devtest' gw_mac, filter_rules)
    #test_enforcer.enforce_in_pcap(pcapfile)
    
    def process_packet(pkt):
        if pkt.haslayer('IP'):
            if pkt['IP'].src == '0.0.0.0':
                try:
                    print(socket.gethostbyaddr(pkt['IP'].dst))
                except Exception as e:
                    print(pkt['IP'].dst)
    sniff(prn=process_packet, iface='en0', store=False)