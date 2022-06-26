
import os
import numpy as np

""" NOTE: CHANGE ON OWN DIRECTORIES THE BELOW LIST OF CONSTANTS
    TODO: Dockerize
"""
# NOTE: Assumes main directory is one parent directory above
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/' #'/Users/lucamrgs/mudscope/'

# --- DISCONTINUED --- Flows provenance analysis
# Download from: https://www.microsoft.com/en-us/download/confirmation.aspx?id=53602
#MICROSOFT_IP_RANGES_CSV = '/Users/lucamrgs/Downloads/msft-public-ips.csv'
# Download from: https://github.com/ejrv/VPNs
#KNOWN_IPV4_VPNS_TXT = '/Users/lucamrgs/Downloads/VPNs-master/vpn-ipv4.txt'
#KNOWN_IPV6_VPNS_TXT = '/Users/lucamrgs/Downloads/VPNs-master/vpn-ipv6.txt'
#KNOWN_IPV4_VPNS = np.genfromtxt(KNOWN_IPV4_VPNS_TXT, dtype='str')
#KNOWN_IPV6_VPNS = np.genfromtxt(KNOWN_IPV6_VPNS_TXT, dtype='str')



# Project directories
SRC_FOLDER = BASE_DIR + 'src/'
CONFIGS_FOLDER = BASE_DIR + 'configs/'
MUD_CONFIGS_FOLDER = CONFIGS_FOLDER + 'mudgen_configs/'
REJECT_CONFIGS_FOLDER = CONFIGS_FOLDER + 'reject_configs/'
CHATACTERIZATION_METADATA_FOLDER = CONFIGS_FOLDER + 'characterization_datas/'
MONITOR_OUTPUTS_FOLDER = BASE_DIR + 'monitor_outputs/'

MUDGEE_FOLDER = BASE_DIR + 'mudgee/'
MUDGEE_RESULTS_FOLDER = BASE_DIR + 'result/'

MUD_DEFAULT_CONFIG_FILE = MUD_CONFIGS_FOLDER + 'last_mud_config.json'

OUTPUTS_FOLDER = BASE_DIR + 'outputs/'

# Main run.py actions
MODE_MUDGEN = 'mudgen'
MODE_REJECT = 'reject'
MODE_ANALYZE = 'analyze'
MODE_FLOWS_GENERATION = 'flows_gen'
MODE_MONITOR = 'monitor'

ANALYSIS_ACTION_IPS_MAP = 'ips_map'
ANALYSIS_ACTION_PKTS_CSV = 'packets_csv'
ANALYSIS_ACTION_MRTA_CHARACTERIZE = 'mrta_characterize'
ANALYSIS_ACTION_IPS_FLOWS_GRAPHS = 'ips_flows_graphs'
ANALYSIS_ACTION_PORTS_FLOWS_GRAPHS = 'ports_flows_graphs'
ANALYSIS_ACTION_FILTER_KNOWN_PROVIDERS = 'filter_known_providers'
ANALYSIS_ACTION_DEVICE_MRT_EVOLUTION_DATAGEN = 'device_mrt_evolution_datagen'


REJECTED_DATA_FILE_TAG = '-rejected'
SUSPICIOUS_DATA_FILE_TAG = '-sus'

# Packet tags for unhandled cases
ARP_TAG = 'arp'
ETH802_3_TAG = '802.3'
IPV6_TAG = 'ipv6'
EAPOL_TAG = 'eapol'
OTHERS_TAG = 'other'

IPV4_TAG = 'ipv4'

# PacketsRegister
NEW_FLOW = 1
UPDATED_FLOW = 0



# Utility Regexs
IPV4_REGEX = '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
IPV6_REGEX = '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
PORT_REGEX = '([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-3][0-9]|6553[0-5])'
MAC_REGEX = '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'

MUDGEE_DVCMAC_OFRULE_TAG = '<deviceMac>'
MUDGEE_GTWMAC_OFRULE_TAG = '<gatewayMac>'

ORIGIN_SCAPY_PACKET = 'scapy_packet'
ORIGIN_MUDGEE_OF_RULE = 'mudgee_of_rule'

FLOW_INFO_JOIN_CHAR = '~'


# Static to MUDgee
DVC_MAC_TAG = '<deviceMac>'
GTW_MAC_TAG = '<gatewayMac>'

MAC_BROADCAST = 'ff:ff:ff:ff:ff:ff'
IP_BROADCAST = '255.255.255.255'

# DHCP and alike bootstrapping
BOOTSTRAP_SRVR_PORT = '67'
BOOTSTRAP_CLNT_PORT = '68'

# MUDgee filter routine in VMUDEnforcer, return values
PKT_REJECTED = -1
PKT_ACCEPTED = 1
PKT_ERROR = 0
PKT_BOOTSTRAP = 2
FLOW_ALREADY_RECORDED = 3

FILTER_MODE_LISTEN = 'listen'
FILTER_MODE_BLOCK = 'block'

# PacketsRegister
REJECTED_TRAFFIC = 'rejected'
ACCEPTED_TRAFFIC = 'accepted'
BOOTSTRAP_TRAFFIC = 'bootstrap'

SIP_TAG = 'sip'
DIP_TAG = 'dip'
SPORT_TAG = 'sport'
DPORT_TAG = 'dport'
TRANSPORT_PROTO_TAG = 'tr_proto'
PACKETS_NUMBER_TAG = 'cntr_packets'


# IPWHOIS CONSTANTS
IPWHOIS_ASN_CC_TAG = 'asn_country_code'
IPWHOIS_ASN_DESC_TAG = 'asn_description'
IPWHOIS_NETS_TAG = 'nets'

# TIRegister Constants
ORIGIN_SOURCE_TAG = 'source'
ORIGIN_DESTINATION_TAG = 'destination'
GEOIP_API_JSON_URL = 'http://ip-api.com/json/'
GEOIP_API_BATCH_URL = 'http://ip-api.com/batch/'

UNRESOLVED_TAG = 'unresolved'
LOCAL_ADDRESS_TAG = 'Local-address'

# MRT to CSV constants
CUSTOM_FORMAT_TAG = '-custom-format.csv'
CUSTOM_HEADER_TAG = '-custom-hdr.csv'
CSV_CLEAN_LABEL = '-CLN.csv'


SINGLETON_SRC_PORT_PER_FLOW_TAG = 'singleton-src-port-to-flow'
SINGLETON_DST_PORT_PER_FLOW_TAG = 'singleton-dst-port-to-flow'

EPHEMERAL_TAG = 'EPHEMERAL_PORT'

AMAZON_ADDRESS_TAG = 'amazon'
GOOGLE_ADDRESS_TAG = 'google'
MICROSOFT_ADDRESS_TAG = 'microsoft'

def simple_progress_print(count):
    # Progression prints to terminal
    if count % 2000 == 0:
        print('.', end='', flush=True)
    if count % 10000 == 0:
        print('[{}]'.format(count), end='', flush=True)


# UTILITY IEEE IoT NIDS PROCESSING

DEFAULT_MALICIOUSNESS_LABEL = 0
DEFUALT_ATK_LABEL = 'Unknown'
IEEE_EZVIZ_GT_CSV = '/Users/lucamrgs/Big_Data/IEEE-Huy-Kang/iot_intrusion_dataset/attacks-all-ezviz/GT-ALL-EZVIZ-LABELLED-V2-3PREC.csv'


STRFTIME_READABLE_FORMAT = "%Y/%m/%d,%H:%M:%S"


# MRT FEEDS CORRELATION
MRT_WINDOW_SIGNATURE_DF_NAME_TAG = '_signature_'
MRT_SIGNATURES_COMPARISON_MATRIX_PLACEHOLDER = 2.0
MRT_SIGNATURES_CORRELATION_THRESHOLD = 0.65 # ARBITRARY
MRT_SIGNATURES_COMBINED_CORRELATION_THESHOLD = 0.6 # Average of (maximum correlation over features, average correlation over features)
FEEDS_SIGNATURES_CORRELATION_DICTIONARIES_KEY_LINK = '---'



# Tests...
if __name__ == '__main__':
    import ipaddress
    from pprint import pprint

    #print(len(KNOWN_IPV4_VPNS))
    #print(len(KNOWN_IPV6_VPNS))
    print(BASE_DIR)
    ip_addr = ipaddress.ip_network('2a0b:e181:500::/40')
    print(type(ip_addr))
    print(ipaddress.ip_address('10.0.1.0') in ipaddress.ip_network('10.0.2.0'))