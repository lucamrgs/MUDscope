"""
Takes filtering rules CSV and a target folder containing the pcaps to enforce for our MUD tests
"""

import sys
import argparse
import os

import run


def module_main(rules_arg, tgt_folder, pcap_limit=None):

    if not os.path.isfile(rules_arg) or not os.path.isdir(tgt_folder):
        print('>>> File "{}" and/or reject_pcaps folder "{}" not found'.format(rules_arg, tgt_folder), file=sys.stderr)
        sys.exit(-1)


    print('>>> TGT FOLDER: {}'.format(tgt_folder))
    print('>>> MUD FILTER RULES FILE: {}'.format(rules_arg))

    #GT_EZVIZ_TESTS_FOLDER = '/Users/lucamrgs/Big_Data/IEEE-Huy-Kang/iot_intrusion_dataset/gt/'

    config_folder_base = os.path.basename(os.path.normpath(tgt_folder))
    print('>>> IN-CONFIG FOLDER: {}'.format(config_folder_base))
    
    tgt_dir = os.fsencode(tgt_folder)
    for file in os.listdir(tgt_dir):
        filename = os.fsdecode(file)
        if filename.endswith('.json'):
            
            print('>>>>>>>>>>>>>>>>>')
            print('######################## Filtering from config: \n{}'.format(filename))
            print('>>>>>>>>>>>>>>>>>')

            run.main(['--mode', 'reject', '--reject_config', config_folder_base + '/' + filename, '--reject_mud_rules', rules_arg])

            print('<<<<<<<<<<<<<<<<<')
            print('######################## Done filtering from config: \n{}'.format(filename))
            print('<<<<<<<<<<<<<<<<<')





if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='TBD')
    
    parser.add_argument('--rules_arg', help='relative path to CSV file containing OpenFlow csv filtering rules', required=True)
    parser.add_argument('--tgt_folder', help='relative path to folder containing all reject_configs to filter from', required=True)

    parser.add_argument('--pcap_limit', metavar='<integer>', help='Number to indicate how many packets will be processed by either functionality', required=False)

    args = parser.parse_args()

    rules_arg = args.rules_arg
    tgt_folder = args.tgt_folder

    pcap_limit = args.pcap_limit if args.pcap_limit is not None else None

    if not os.path.isfile(rules_arg) or not os.path.isdir(tgt_folder):
        print('>>> File "{}" and/or reject_pcaps folder "{}" not found'.format(rules_arg, tgt_folder), file=sys.stderr)
        sys.exit(-1)


    print('>>> TGT FOLDER: {}'.format(tgt_folder))
    print('>>> MUD FILTER RULES FILE: {}'.format(rules_arg))

    GT_EZVIZ_TESTS_FOLDER = '/Users/lucamrgs/Big_Data/IEEE-Huy-Kang/iot_intrusion_dataset/gt/'

    config_folder_base = os.path.basename(os.path.normpath(tgt_folder))
    print('>>> IN-CONFIG FOLDER: {}'.format(config_folder_base))
    
    tgt_dir = os.fsencode(tgt_folder)
    for file in os.listdir(tgt_dir):
        filename = os.fsdecode(file)
        if filename.endswith('.json'):
            
            print('>>>>>>>>>>>>>>>>>')
            print('######################## Filtering from config: \n{}'.format(filename))
            print('>>>>>>>>>>>>>>>>>')

            run.main(['--mode', 'reject', '--reject_config', config_folder_base + '/' + filename, '--reject_mud_rules', rules_arg])

            print('<<<<<<<<<<<<<<<<<')
            print('######################## Done filtering from config: \n{}'.format(filename))
            print('<<<<<<<<<<<<<<<<<')

    sys.exit(0)