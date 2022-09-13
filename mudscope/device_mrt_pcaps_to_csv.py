
"""
    - Takes a device-related folder as input, or anyway a folder containing all MUD rejected-traffic pcaps
    - Generates all flow-files per-pcap
    - Derives comprehensive NetFlow CSV per-pcap
    - Merges all CSVs together
"""
import sys
import csv
import argparse
import ipaddress
import json
import numpy as np
import os
import socket
import subprocess
import pandas as pd

# Remove directories without errors, from https://stackoverflow.com/questions/31977833/rm-all-files-under-a-directory-using-python-subprocess-call
import shutil
import requests
import time

from mudscope.Constants import *
from pathlib import Path

debug = False

# TODO: remove hard-coded paths
BASH_AUTO_PCAP_TO_FLOWS = BASE_DIR + 'mudscope/auto-scripts/bash/pcap_to_flows.sh'
BASH_AUTO_FLOWS_TO_CSV = BASE_DIR + 'mudscope/auto-scripts/bash/flows_to_csv.sh'
BASH_AUTO_MERGE_CSVS = BASE_DIR + 'mudscope/auto-scripts/bash/merge_csvs.sh'

FLOWS_DIR_TAG = '-flows'
ALL_CSV_FLOWS_DIR_TAG = '-all-flows-csv'


################################################################################
################### >>> GEO IP
################################################################################
"""
    NOTE: GEO-DATA NOT SUPPORTED AT THE MOMENT
"""
GEOIP2_LICENSE_KEY = ''
import asyncio
#import geoip2.webservice

# To query the GeoLite2 web service, you must set the "host" keyword argument
# to "geolite.info"
#async_client = geoip2.webservice.AsyncClient(587289, GEOIP2_LICENSE_KEY, host='geolite.info')



################################################################################
################### >>> Get Arguments
################################################################################


def get_args(arguments=None):
    parser = argparse.ArgumentParser(
        description='Transform pcaps to Netflows'
    )

    parser.add_argument(
        'pcaps_dir',
        metavar = '<path to directory>',
        help    = 'Path to directory with only PCAPs containing MUD-rejected traffic.',
    )

    parser.add_argument(
        '--outdir',
        metavar = '<path to directory>',
        help    = 'path to output directory'
    )
    
    # Return arguments
    return parser.parse_args(arguments)


################################################################################
################### >>> DIRECTORY CLEANING
################################################################################

def clean_up_flow_folders(pcap_dir, ask=False):
    print('>>> Removing all temporary flows folders...')
    dir = os.fsencode(pcap_dir)
    for data in os.listdir(dir):
        data_name = os.fsdecode(data)
        if data_name.endswith(FLOWS_DIR_TAG):
            path_to_file = pcap_dir + data_name
            if ask:
                print('>>> REMOVE : {} ?'.format(path_to_file))
                resp = input('Type y for Yes, whatever for No\n>>> ')
                if resp == 'y':
                        shutil.rmtree(path_to_file)
                        #subprocess.run(['rmdir', '-rf', path_to_file], shell=True)
                else:
                    print('>>> File [ {} ] salvaged'.format(path_to_file))
            else:
                shutil.rmtree(path_to_file)
                print('>>> Removed: {}'.format(path_to_file))

def clean_up_unused_csvs(csvs_dir):
    print('>>> Removing all unformatted CSV files...')
    dir = os.fsencode(csvs_dir)
    for data in os.listdir(dir):
        data_name = os.fsdecode(data)
        if not data_name.endswith(CSV_CLEAN_LABEL):
            path_to_file = csvs_dir + '/' + data_name
            os.remove(path_to_file)
            print('>>> Removed: {}'.format(path_to_file))


################################################################################
################### >>> PCAPs > FLOWS > CSV Pipeline
################################################################################

def pcaps_to_flows(pcaps_dir):

    #subprocess.call(BASH_AUTO_PCAP_TO_FLOWS + " " + pcaps_dir, shell=True)
    dir = os.fsencode(pcaps_dir)
    for file in os.listdir(dir):
        # Gets string of every file name in directory
        pcap_file = os.fsdecode(file)  
        if pcap_file.endswith('.pcap') and not (pcap_file.startswith('.')):

            file_dir = os.path.splitext(pcap_file)[0]
            file_path = pcaps_dir + pcap_file
            output_path = pcaps_dir + file_dir + FLOWS_DIR_TAG + '/'

            """
            NOTE TODO: PARAMOUNT ACTION: NO PACKETS ARE MALIGN -> PCAP HAS 0 PACKETS - MANAGE!!            
            #cap = rdpcap(file_path)
            #if len(cap) < 1:
            #    print('>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> NO PACKETS CASE')
            #    print(DEFAULT_SINGLE_PACKET)
            wrpcap(file_path, DEFAULT_SINGLE_PACKET, append=True)
            """

            print('>>> Generating flow directory and files for \n>>> {}'.format(file_path))

            # Create output dir if does not exist
            Path(output_path).mkdir(parents=True, exist_ok=True)
            subprocess.run(['nfpcapd', '-r', file_path, '-l', output_path])
            print('>>> Flows generated at\n>>> {}'.format(output_path))
    

def flows_to_aggregated_csvs(pcaps_dir, merge_all_csvs=False, outdir=None):
    
    # To then copy all per-pcap flow csv into one directory
    if outdir is None:
        pcaps_flows_csvs_dir = pcaps_dir + os.path.basename(os.path.normpath(pcaps_dir)) + ALL_CSV_FLOWS_DIR_TAG
    else:
        pcaps_flows_csvs_dir = outdir

    if os.path.isdir(pcaps_flows_csvs_dir):
        print('')
        print('>>> >>> ERROR <<<')
        print('')
        print(f">>> It seems that a Flows CSV file for this directory was already generated. You may find it at \n>>> [ {pcaps_flows_csvs_dir} ]")
        print(f">>> If you intend to generate it again, either DELETE the above folder or CHANGE ITS LOCATION/NAME.")
        print(f">>> Cleaning temporary directories...")
        print('')
        clean_up_flow_folders(pcaps_dir)
        sys.exit(1)

    print(pcaps_flows_csvs_dir)
    Path(pcaps_flows_csvs_dir).mkdir(parents=True, exist_ok=True)
    
    dir = os.fsencode(pcaps_dir)
    for data in os.listdir(dir):
        # Gets string of every file name in directory
        data_name = os.fsdecode(data)
        # Target only folders generated previously. NOTE: Assumes no folder with FLOWS-DIR-TAG is "manually" generated
        if data_name.endswith(FLOWS_DIR_TAG) and not (data_name.startswith('.')):
            path_to_flows = pcaps_dir + data_name
            print('>>> Generating and aggregating CSV NetFlow files for flows at tmp directory:\n>>> {}'.format(path_to_flows))
            
            subprocess.call(BASH_AUTO_FLOWS_TO_CSV + " " + path_to_flows, shell=True)
            subprocess.call(BASH_AUTO_MERGE_CSVS + " " + path_to_flows, shell=True) # all_csvs_file name is named after the directory

            merged_csv_name = data_name + '.csv'
            merged_csv_path = path_to_flows + '/' + merged_csv_name
            #print('MERGED CSV FLOWS PATH : {}'.format(merged_csv_path))
            if os.path.isfile(merged_csv_path):
                # Add csv to all pcaps-to-csvs folder
                subprocess.run(['cp', merged_csv_path, pcaps_flows_csvs_dir + '/' + merged_csv_name])

    aggregated_csvs_filename = '_'
    if merge_all_csvs:    
        # Merge all CSV flows into single CSV
        subprocess.call(BASH_AUTO_MERGE_CSVS + ' ' + pcaps_flows_csvs_dir, shell=True)
        print('>>> All per-pcap CSVs have been saved in [ {} ], both separately and in a single CSV.'.format(pcaps_flows_csvs_dir))
        aggregated_csvs_filename = os.path.basename(os.path.normpath(pcaps_flows_csvs_dir)) + '.csv'
        print('>>> Merged all generated per-pcap CSV NetFlows to single CSV file at:\n>>> {}'.format(aggregated_csvs_filename))
    return pcaps_flows_csvs_dir, aggregated_csvs_filename




############################################################################################################
################### >>> CSV METADATA MANIPULATION
############################################################################################################


def change_all_csv_header_to_custom(csvs_dir):
    """ Only targets the all_csvs file, aggregating all flows
    """
    tgt_file_path = csvs_dir + '/' + os.path.basename(os.path.normpath(csvs_dir)) + '.csv' # I manually select the name of what I know is the all_csvs file
    if not tgt_file_path.endswith('.csv'):
        print(f">>> ERROR: tgt_file_path [ {tgt_file_path} ] is not a CSV file. Exiting.")
        sys.exit(0)

    out_path = os.path.splitext(tgt_file_path)[0] + CUSTOM_FORMAT_TAG
    print(out_path)

    with open(tgt_file_path, newline='') as inFile, open(out_path, 'w', newline='') as outfile:
        r = csv.reader(inFile)
        w = csv.writer(outfile)
        new_header = ['ts','te','td','pr','sa','da','sp','dp','sas','pas','ipkt','opkt','ibyt','obyt','flg','dir','bps','pps','bpp','cl','sl','al']
        next(r, None)  # skip the first row from the reader, the old header
        # write new header
        w.writerow(new_header)

        # copy the rest
        for row in r:
            w.writerow(row)

    return out_path


def change_csvs_headers_to_custom(csvs_dir):

    dir = os.fsencode(csvs_dir)
    for file in os.listdir(dir):
        # Gets string of every file name in directory
        tgt_file_path = csvs_dir + '/' + os.fsdecode(file)
        
        if not tgt_file_path.endswith('.csv'):
            #print(f">>> ERROR: tgt_file_path [ {tgt_file_path} ] is not a CSV file. Exiting.")
            #sys.exit(0)
            continue
        if tgt_file_path.endswith(CUSTOM_HEADER_TAG) or tgt_file_path.startswith('.'):
            continue

        out_path = os.path.splitext(tgt_file_path)[0] + CUSTOM_HEADER_TAG

        with open(tgt_file_path, newline='') as inFile, open(out_path, 'w', newline='') as outfile:
            r = csv.reader(inFile)
            w = csv.writer(outfile)
            new_header = ['ts','te','td','pr','sa','da','sp','dp','sas','pas','ipkt','opkt','ibyt','obyt','flg','dir','bps','pps','bpp','cl','sl','al']
            next(r, None)  # skip the first row from the reader, the old header
            # write new header
            w.writerow(new_header)
            # copy the rest
            for row in r:
                w.writerow(row)

############################################################################################################
################### >>> CSV VALUES MANIPULATION
############################################################################################################


def to_float(val):
    if isinstance(val, float):
        if not np.isnan(val):
            return float(val)
    elif isinstance(val, str):
        try:
            return float(val)
        except Exception as e:
            if val.endswith('M'): # Manual 'Million' value from nfdump parsing
                num = val.split()[0]
                return float(num) * 1000000
            return 0
    return 0


def to_consistent_float_fields(df):
    """ Used in clean_duplicates"""
    # TODO: FORMAT CONSISTENCY
    df['td'] = df['td'].apply(to_float)
    df['sas'] = df['sas'].apply(to_float)
    df['pas'] = df['pas'].apply(to_float)
    df['ipkt'] = df['ipkt'].apply(to_float)
    df['opkt'] = df['opkt'].apply(to_float)
    df['ibyt'] = df['ibyt'].apply(to_float)
    df['obyt'] = df['obyt'].apply(to_float)
    df['bps'] = df['bps'].apply(to_float)
    df['pps'] = df['pps'].apply(to_float)
    df['bpp'] = df['bpp'].apply(to_float)
    df['cl'] =  df['cl'].apply(to_float)
    df['sl'] =  df['sl'].apply(to_float)
    df['al'] =  df['al'].apply(to_float)

    return df


def map_ports(csv_file):
    df = pd.read_csv(csv_file)
    values = {'sp' : [], 'dp': []}
    tot_entries = df.shape[0]
    for idx, entry in df.iterrows():
        sp = int(entry.sp)
        dp = int(entry.dp)
        proto = str(entry.pr).lower()
        try:
            s_serv = socket.getservbyport(sp, proto)
        except Exception as e:
            s_serv = 'ephemeral'
        try:
            d_serv = socket.getservbyport(dp, proto)
        except Exception as e:
            d_serv = 'ephemeral'

        #print('{}, {}'.format(s_serv, d_serv))
        values['sp'].append(s_serv)
        values['dp'].append(d_serv)

    df['sp'] = values['sp']
    df['dp'] = values['dp']

    out_path = os.path.splitext(csv_file)[0] + '-portlabels.csv'
    df.to_csv(out_path, sep=',', index=False)
    print('OUT PATH: {}'.format(out_path))
    return out_path


def remove_spaces_from_addr_cols_in_csv(csv_in):
    """Utility cleaning"""
    if not os.path.isfile(csv_in):
        raise ValueError('\n>>> File \n>>>[ {} ] \n>>>does not seem to exist, or is not a file'.format(csv_in))

    df = pd.read_csv(csv_in)
    def lambda_func(x):
        return x.replace(' ', '')
    for col in ['sa', 'da']:
        df[col] = df[col].apply(lambda_func)
    
    df.to_csv(csv_in, sep=',', index=False)


def remove_spaces_from_addr_cols(df):
    """Utility cleaning"""
    for col in ['sa', 'da']:
        df[col].apply(lambda x: x.replace(' ', '') if isinstance(x, str) else x)
    return df

# TODO: pip install maxminddb-geolite2
# 'Fastest way to solve IP to country?' @ https://stackoverflow.com/questions/40211314/pandas-fastest-way-to-resolve-ip-to-country
# ACCESS MAXMIND GEOLITE2 ACCOUNT @ https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
"""
    NOTE: GEO-DATA NOT SUPPORTED AT THE MOMENT
"""
def add_geo_data_m3(csv_file):
    """
        DOES NOT WORK, 1k calls per day....
    """
    if not os.path.isfile(csv_file):
        raise ValueError('\n>>> File \n>>>[ {} ] \n>>>does not seem to exist, or is not a file'.format(csv_file))

    df = pd.read_csv(csv_file)
    df = remove_spaces_from_addr_cols(df)

    df['sa_country_geoip2'] = ['unresolved'] * df.shape[0]
    df['da_country_geoip2'] = ['unresolved'] * df.shape[0]

    # Consult @ https://dev.maxmind.com/geoip/geolocate-an-ip/web-services?lang=en
    async def solve_addresses():
        async with geoip2.webservice.AsyncClient(587289, GEOIP2_LICENSE_KEY, host='geolite.info') as client:
            for idx, row in df.iterrows():
                try:
                    print(df.iloc[idx]['sa'])
                    r_sa = await client.country(df.iloc[idx]['sa'])
                    response_sa = r_sa.country.iso_code
                    df.iloc[idx]['sa_country_geoip2'] = response_sa
                except Exception as e:
                    print(e)

                try:
                    print(df.iloc[idx]['da'])
                    r_da = await client.country(df.iloc[idx]['da']).country.iso_code
                    response_da = r_da.country.iso_code
                    df.iloc[idx]['da_country_geoip2'] = response_da
                except Exception as e:
                    print(e)
    asyncio.run(solve_addresses())
                    
    print(df.head(10))
    

"""
    NOTE: GEO-DATA NOT SUPPORTED AT THE MOMENT
"""
def add_geo_data_m2(csv_file):
    if not os.path.isfile(csv_file):
        raise ValueError('\n>>> File \n>>>[ {} ] \n>>>does not seem to exist, or is not a file'.format(csv_file))

    df = pd.read_csv(csv_file)

    df = remove_spaces_from_addr_cols(df)
    print(df.head(5))

    new_cols = ['sa_country', 'sa_city', 'sa_lat', 'sa_lon', 'sa_org', 'sa_asname', 'da_country', 'da_city', 'da_lat', 'da_lon', 'sa_org', 'da_asname']
    new_cols_init = ['unresolved', 'unresolved', 0, 0, 'unresolved', 'unresolved', 'unresolved', 'unresolved', 0, 0, 'unresolved', 'unresolved']
    df[new_cols] = pd.DataFrame([new_cols_init], index=df.index)
    #print(df.head(10))

    src_cols = ['sa_country', 'sa_city', 'sa_lat', 'sa_lon', 'sa_org', 'sa_as']
    dst_cols = ['da_country', 'da_city', 'da_lat', 'da_lon', 'da_org', 'da_as']

    local_vals = ['local', 'local', 0, 0, 'local', 'local',]
    unsolved_vals = ['unresolved', 'unresolved', 0, 0, 'unresolved', 'unresolved']

    addresses_cache = {}
    if os.path.isfile('geo_cache.json'):
        with open('geo_cache.json') as json_file:
            addresses_cache = json.load(json_file)

    try:
        for idx, row in df.iterrows():
            sa = row['sa']
            da = row['da']

            ############ Source address ############
            if not sa in addresses_cache.keys():
                try:
                    if ipaddress.ip_address(sa).is_private:
                            df.loc[idx, src_cols] = local_vals
                            addresses_cache[sa] = local_vals
                    else:
                        ip_info = requests.get(GEOIP_API_JSON_URL + sa)
                        xrl = ip_info.headers['X-Rl']
                        ttl = ip_info.headers['X-Ttl']
                        ip_info = ip_info.json()
                        print(ip_info)
                        if ip_info['status'] == 'success':
                            vals = [ip_info['country'], ip_info['city'], ip_info['lat'], ip_info['lon'], ip_info['org'], ip_info['as']]
                            df.loc[idx, src_cols] = vals
                            addresses_cache[sa] = vals
                        else:
                            # Already unresolved
                            addresses_cache[sa] = unsolved_vals
                        if int(xrl) <= 1:
                            secs_wait = int(ttl) + 1
                            print('>>> API query frequency exceeded. Waiting for {} seconds before resuming queries.'.format(secs_wait))
                            time.sleep(secs_wait)
                except Exception as e:
                    print('>>> EXCEPTED')
                    print(e)
                    df.loc[idx, src_cols] = unsolved_vals
                    addresses_cache[sa] = unsolved_vals
                    
            else:
                print('>>> SA CACHED')
                df.loc[idx, src_cols] = addresses_cache[sa]

            ############ Destination address ############
            if not da in addresses_cache.keys():
                try:
                    if ipaddress.ip_address(da).is_private:
                            df.loc[idx, dst_cols] = local_vals
                            addresses_cache[da] = local_vals
                    else:
                        ip_info = requests.get(GEOIP_API_JSON_URL + da)
                        xrl = ip_info.headers['X-Rl']
                        ttl = ip_info.headers['X-Ttl']
                        ip_info = ip_info.json()
                        print(ip_info)
                        if ip_info['status'] == 'success':
                            vals = [ip_info['country'], ip_info['city'], ip_info['lat'], ip_info['lon'], ip_info['org'], ip_info['as']]
                            df.loc[idx, dst_cols] = vals
                            addresses_cache[da] = vals
                        else:
                            # Already unresolved
                            addresses_cache[da] = unsolved_vals
                        if int(xrl) <= 1:
                            secs_wait = int(ttl) + 1
                            print('>>> API query frequency exceeded. Waiting for {} seconds before resuming queries.'.format(secs_wait))
                            time.sleep(secs_wait)
                except Exception as e:
                    print('>>> EXCEPTED')
                    print(e)
                    df.loc[idx, dst_cols] = unsolved_vals
                    addresses_cache[da] = unsolved_vals
                    
            else:
                print('>>> DA CACHED')
                df.loc[idx, dst_cols] = addresses_cache[da]

            print(df.iloc[idx][src_cols])
            print(df.iloc[idx][dst_cols])
        ############ For loop end ############
            
    except KeyboardInterrupt:
        print('Interrupted')
        print('>>> EXCEPTED')
        with open('geo_cache.json', 'w') as outfile: 
            json.dump(addresses_cache, outfile, indent=4)	
        sys.exit(0)	

    with open('geo_cache.json', 'w') as outfile: 
        json.dump(addresses_cache, outfile, indent=4)

    df.to_csv('geo_df_csv.csv', sep=',')
            

############################################################################################################
################### >>> CSV CLEANING
############################################################################################################

def remove_meta_rows(csv_file):

    if not os.path.isfile(csv_file):
        raise ValueError('\n>>> File \n>>>[ {} ] \n>>>does not seem to exist, or is not a file'.format(csv_file))

    filename = os.path.basename(os.path.normpath(csv_file))
    csv_in = pd.read_csv(csv_file)

        
    #df = csv_in[(csv_in.ts != 'Summary') & (csv_in.ts != 'flows') & (~(csv_in.ts.astype(str).str.isnumeric()))]
    df = pd.DataFrame(csv_in)
    #print(df)
    out_path = os.path.splitext(csv_file)[0]+'-clear.csv'
    print('OUT PATH: {}'.format(out_path))
    df.to_csv(out_path, index = False)
    return out_path



def dataset_add_flags_cols(df):
    print(df.head(5))
    def flag_tag_to_binary_array(flgs):
        # Flags left-to-right : CWR, ECE, URGENT, ACK, PUSH, RESET, SYN, FIN (reminder: https://www.johnpfernandes.com/2018/12/17/tcp-flags-what-they-mean-and-how-they-help/)
        flgs_vals = list(flgs)
        output = tuple(map(lambda x : 0.0 if x == '.' else 1.0, flgs_vals))
        return output
    def flag_tag_to_binary_int_representation(flgs):
        flgs_vals = list(flgs) #string to elements
        binary_str = ''.join(list(map(lambda x : '0' if x == '.' else '1', flgs_vals))) #sringify array of 0/1 corresponding to flags
        binary_int = int(binary_str, 2) # 0/1 string converted to int value
        return binary_int
        # One liner: return int(''.join(list(map(lambda x : '0' if x == '.' else '1', list(flgs)))), 2)
    def flags_col_to_onehot_and_int(df):
        """
        # TODO NOTE : SOME ONE-HOT REPRESENTATIONS ARE CORRUPT??? ANYWAY THE INT_REPR WORKS WELL, AND I ONLY USE THAT IN CLUSTERING
        """
        # Ref https://stackoverflow.com/questions/48168348/pandas-replace-a-column-within-a-data-frame-by-two-columns
        flags_df = df['flg'].apply(flag_tag_to_binary_array) # new df encoding flags
        flags_int_val = df['flg'].apply(flag_tag_to_binary_int_representation)
        flags_df = pd.DataFrame(flags_df.values.tolist()) # explode to self.dataset cols
        print()
        print()
        print()
        print('flagsdf:')
        print(flags_df)
        print()
        print()
        print()
        flags_cols = ['flg_cwr', 'flg_ece', 'flg_urg', 'flg_ack', 'flg_psh', 'flg_rst', 'flg_syn', 'flg_fin']
        df[flags_cols] = flags_df # append new cols to existing self.dataset
        df['flgs_int'] = flags_int_val
        final_flags_cols = ['flgs_int', 'flg_cwr', 'flg_ece', 'flg_urg', 'flg_ack', 'flg_psh', 'flg_rst', 'flg_syn', 'flg_fin']
        # Ref https://stackoverflow.com/questions/41968732/set-order-of-columns-in-pandas-dataframe, https://stackoverflow.com/questions/7376019/list-extend-to-index-inserting-list-elements-not-only-to-the-end
        idx_at = list(df.columns).index('flg') # Reorder self.dataset indexes ...
        df_new_index_order = list(df.columns)
        df_new_index_order[idx_at+1:idx_at+1] = final_flags_cols
        df = df.reindex(columns=df_new_index_order)
        df = df.loc[:,~df.columns.duplicated()]
        return df
    df = df.dropna()
    df = flags_col_to_onehot_and_int(df)
    return df

def set_complete_clean_csv(csv_file):
    if not os.path.isfile(csv_file):
        raise ValueError('\n>>> File \n>>>[ {} ] \n>>>does not seem to exist, or is not a file'.format(csv_file))

    df = pd.read_csv(csv_file)
    df = to_consistent_float_fields(df)
    df = remove_spaces_from_addr_cols(df)
    print(df)
    print()
    print()
    print()
    print('csv file')
    print(csv_file)
    print()
    print()
    print()
    df = dataset_add_flags_cols(df)
    
    #print(df.head(5))
    print('DF SHAPE BEFORE DROPNA: {}'.format(df.shape))

    #df = df.loc[:, (df != 0).any(axis=0)] # https://stackoverflow.com/questions/21164910/how-do-i-delete-a-column-that-contains-only-zeros-in-pandas
    df = df.replace(np.nan, 0)
    df = df.replace("", np.nan)
    df = df.dropna()
    df.reset_index(drop=True, inplace=True)

    print('DF SHAPE BEFORE REMOVING DUPS: {}'.format(df.shape))

    dups_stable_fields = ['ts', 'pr', 'sa', 'da', 'sp', 'dp', 'flg', 'bpp']
    df = df.drop_duplicates(dups_stable_fields, keep='last').sort_values('ts')
    

    out_path = os.path.splitext(csv_file)[0]+ CSV_CLEAN_LABEL
    df.to_csv(out_path, sep=',', float_format='%.3f', index=False)
    print('DF SHAPE AFTER REMOVING DUPS: {}'.format(df.shape))
    print(df)

    #print(df.sample(10))

    return out_path

def set_all_csvs_clean(csvs_dir):
    dir = os.fsencode(csvs_dir)
    for file in os.listdir(dir):
        # Gets string of every file name in directory
        """
        # TODO TO FIX TODO
        # ENTER COMPLETE tgt_file PATH OR IT DOES NOT FIND IT!!!
        """
        tgt_file = csvs_dir + '/' + os.fsdecode(file)
        if tgt_file.endswith(CUSTOM_HEADER_TAG) and not tgt_file.startswith('.'):
            set_complete_clean_csv(tgt_file)
        

############################################################################################################
################### >>> WRAPPER FUNCTION
############################################################################################################

def module_main(pcaps_dir):

    dir = pcaps_dir if pcaps_dir.endswith('/') else pcaps_dir + '/'

    pcaps_to_flows(dir)
    
    all_csvs_dir, all_csvs_file = flows_to_aggregated_csvs(dir)
    print(all_csvs_dir)

    all_csvs_file = change_all_csv_header_to_custom(all_csvs_dir)
    print(all_csvs_file)

    all_csvs_file = set_complete_clean_csv(all_csvs_file)
    print('ALL CSVS FILE: {}'.format(all_csvs_file))
    
    clean_up_unused_csvs(all_csvs_dir)
    clean_up_flow_folders(dir)


# TODO: Add 'generate all complete CSVs for each pcap in folder' function

def module_each_pcap_to_complete_csv(pcaps_dir, outdir=None):
    dir = pcaps_dir if pcaps_dir.endswith('/') else pcaps_dir + '/'
    pcaps_to_flows(dir)
    
    all_csvs_dir, _ = flows_to_aggregated_csvs(dir, outdir=outdir)
    print(all_csvs_dir)

    change_csvs_headers_to_custom(all_csvs_dir)
    set_all_csvs_clean(all_csvs_dir)

    clean_up_unused_csvs(all_csvs_dir)
    clean_up_flow_folders(dir)


if __name__ == '__main__':
    # Get arguments
    args = get_args()

    if os.path.isdir(args.pcaps_dir):
        print('>>> Starting pcaps to labelled IEEE-IoT-NIDS csvs generation from directory: {}'.format(args.pcaps_dir))
        if args.pcaps_dir.endswith('/'):
            dir = args.pcaps_dir
        else:
            dir = args.pcaps_dir + '/'
    else:
        raise ValueError('Directory [ {} ] does not seem to exist. Exiting.'.format(args.pcaps_dir))


    print(dir)

    pcaps_to_flows(dir)
    
    all_csvs_dir, all_csvs_file = flows_to_aggregated_csvs(
        dir,
        merge_all_csvs = True,
        outdir = args.outdir,
    )
    print(all_csvs_dir)

    all_csvs_file = change_all_csv_header_to_custom(all_csvs_dir)
    print(all_csvs_file)

    all_csvs_file = set_complete_clean_csv(all_csvs_file)
    print('ALL CSVS FILE: {}'.format(all_csvs_file))
    
    clean_up_flow_folders(dir)
    
    
    # Tests
    

    sys.exit(0)