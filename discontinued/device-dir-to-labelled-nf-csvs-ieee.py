
"""
    - Takes a device-related folder as input, or anyway a folder containing all MUD rejected-traffic pcaps
    - Generates all flow-files per-pcap
    - Derives comprehensive NetFlow CSV per-pcap
    - Labels the CSV according to the IEEE IoT NIDS dataset, EZVIZ ground truth
    - Merges all CSVs together

    Uses custom bash scripts
"""
import sys
import csv
import argparse
import ipaddress
import json
import os
import socket
import subprocess
from pathlib import Path
import pandas as pd

# Remove directories without errors, from https://stackoverflow.com/questions/31977833/rm-all-files-under-a-directory-using-python-subprocess-call
import shutil
import requests
import time

cwd = os.getcwd()
sys.path.insert(1, cwd + '/src/')
sys.path.insert(2, cwd + '/src/auto-scripts')

#from CsvProcessingUtilsIEEE import *
from Constants import *

debug = False

BASH_AUTO_PCAP_TO_FLOWS = BASE_DIR + 'src/auto-scripts/bash/pcap_to_flows.sh'
BASH_AUTO_FLOWS_TO_CSV = BASE_DIR + 'src/auto-scripts/bash/flows_to_csv.sh'
BASH_AUTO_MERGE_CSVS = BASE_DIR + 'src/auto-scripts/bash/merge_csvs.sh'

FLOWS_DIR_TAG = '-flows'
ALL_CSV_FLOWS_DIR_TAG = '-all-flows-csv'



######################################################
################### >>> Get arguments
######################################################


def get_args(arguments=None):
    parser = argparse.ArgumentParser(description='TBD')
    parser.add_argument('--pcaps_dir', metavar='<path to directory>', help='Path to directory with only PCAPs containing MUD-rejected traffic.', required=True)
    args = parser.parse_args(arguments)

    pcaps_dir = args.pcaps_dir
    if os.path.isdir(pcaps_dir):
        print('>>> Starting pcaps to labelled IEEE-IoT-NIDS csvs generation from directory: {}'.format(pcaps_dir))
        return pcaps_dir if pcaps_dir.endswith('/') else pcaps_dir + '/'
    else:
        raise ValueError('Directory [ {} ] does not seem to exist. Exiting.'.format(pcaps_dir))




############################################################################################################
################### >>> BASH SCRIPTS INVOKATIONS
############################################################################################################


def pcaps_to_flows(pcaps_dir):

    #subprocess.call(BASH_AUTO_PCAP_TO_FLOWS + " " + pcaps_dir, shell=True)
    dir = os.fsencode(pcaps_dir)
    for file in os.listdir(dir):
        # Gets string of every file name in directory
        pcap_file = os.fsdecode(file)  
        if pcap_file.endswith('.pcap'):
            file_dir = os.path.splitext(pcap_file)[0]
            file_path = pcaps_dir + pcap_file
            output_path = pcaps_dir + file_dir + FLOWS_DIR_TAG + '/'

            print('>>> Generating flow directory and files for \n>>> {}'.format(file_path))

            # Create output dir if does not exist
            Path(output_path).mkdir(parents=True, exist_ok=True)
            subprocess.run(['nfpcapd', '-r', file_path, '-l', output_path])
            print('>>> Flows generated at\n>>> {}'.format(output_path))
    

def flows_to_aggregated_csvs(pcaps_dir):
    
    # To then copy all per-pcap flow csv into one directory
    pcaps_flows_csvs_dir = pcaps_dir + os.path.basename(os.path.normpath(pcaps_dir)) + ALL_CSV_FLOWS_DIR_TAG
    print(pcaps_flows_csvs_dir)
    Path(pcaps_flows_csvs_dir).mkdir(parents=True, exist_ok=True)
    
    dir = os.fsencode(pcaps_dir)
    for data in os.listdir(dir):
        # Gets string of every file name in directory
        data_name = os.fsdecode(data)
        # Target only folders generated previously. NOTE: Assumes no folder with FLOWS-DIR-TAG is "manually" generated
        if data_name.endswith(FLOWS_DIR_TAG):
            path_to_flows = pcaps_dir + data_name
            print('>>> Generating and aggregating CSV NetFlow files for flows at tmp directory:\n>>> {}'.format(path_to_flows))
            subprocess.call(BASH_AUTO_FLOWS_TO_CSV + " " + path_to_flows, shell=True)
            subprocess.call(BASH_AUTO_MERGE_CSVS + " " + path_to_flows, shell=True)
            merged_csv_name = data_name + '.csv'
            merged_csv_path = path_to_flows + '/' + merged_csv_name
            #print('MERGED CSV FLOWS PATH : {}'.format(merged_csv_path))
            if os.path.isfile(merged_csv_path):
                # Add csv to all pcaps-to-csvs folder
                subprocess.run(['cp', merged_csv_path, pcaps_flows_csvs_dir + '/' + merged_csv_name])
        
    # Merge all CSV flows into single flow
    subprocess.call(BASH_AUTO_MERGE_CSVS + ' ' + pcaps_flows_csvs_dir, shell=True)
    print('>>> All per-pcap CSVs have been saved in [ {} ], both separately and in a single CSV.'.format(pcaps_flows_csvs_dir))
    aggregated_csvs_filename = os.path.basename(os.path.normpath(pcaps_flows_csvs_dir)) + '.csv'
    print('>>> Merged all generated per-pcap CSV NetFlows to single CSV file at:\n>>> {}'.format(aggregated_csvs_filename))
    return pcaps_flows_csvs_dir, aggregated_csvs_filename




############################################################################################################
################### >>> CSV METADATA MANIPULATION
############################################################################################################


def change_all_csv_header_to_custom(csvs_dir):
	tgt_file_path = csvs_dir + '/' + os.path.basename(os.path.normpath(csvs_dir)) + '.csv'
	if not tgt_file_path.endswith('.csv'):
		sys.exit(0)

	out_path = os.path.splitext(tgt_file_path)[0] + '-custom-fromat.csv'
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


def to_consistent_float_fields_ieee(df):
	""" Used in clean_duplicates"""

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


def remove_spaces_from_string_cols(df):
	"""Utility cleaning"""
	def lambda_func(x):
		return x.replace(' ', '') if isinstance(x, str) else x
	for col in df.columns:
		df[col] = df[col].apply(lambda_func)
	return df

def add_geo_data_m2(csv_file):
	if not os.path.isfile(csv_file):
		raise ValueError('\n>>> File \n>>>[ {} ] \n>>>does not seem to exist, or is not a file'.format(csv_file))

	df = pd.read_csv(csv_file)

	df = remove_spaces_from_string_cols(df)
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
################### >>> CSV LABELLINGS
############################################################################################################

def assign_default_labels(csv_file):

	csv_in = pd.read_csv(csv_file)
	#print(csv_in.sample(5))
	csv_in['MALICIOUS'] = [DEFAULT_MALICIOUSNESS_LABEL] * len(csv_in)
	csv_in['ATK_TYPE'] = [DEFUALT_ATK_LABEL] * len(csv_in)

	#print(csv_in.sample(5))
	print(csv_in.shape)

	csv_in = csv_in.sort_values('ts')
	print(csv_in.sample(10))

	out_path = os.path.splitext(csv_file)[0]+'-READY.csv'
	csv_in.to_csv(out_path, sep=',', index = False)
	print('OUT PATH: {}'.format(out_path))
	return out_path


def assign_ieee_labels(csv_to_label, csv_labelled):

	if not os.path.isfile(csv_to_label) or not os.path.isfile(csv_labelled):
		raise ValueError('>>> Unable to read file \n[ {} ] \nor [ {} ]. Exiting.'.format(csv_to_label, csv_labelled))

	# IEEE IoT NIDS default csv_labelled @ 
	# /Users/lucamrgs/Big_Data/IEEE-Huy-Kang/iot_intrusion_dataset/attacks-all-ezviz/GT-ALL-EZVIZ-LABELLED.csv

	pd_csv_to_label = pd.read_csv(csv_to_label)
	pd_csv_labelled = pd.read_csv(csv_labelled)

	#pd_csv_to_label = to_consistent_float_fields_ieee(pd_csv_to_label)
	#pd_csv_labelled = to_consistent_float_fields_ieee(pd_csv_labelled)

	idx = ['ts', 'te', 'td', 'sa', 'da', 'sp', 'dp', 'pr', 'flg', 'fwd', 'stos',
	 		'ipkt', 'ibyt', 'opkt', 'obyt', 'in', 'out', 'sas', 'das', 'smk', 'dmk',
		'dtos', 'dir', 'nh', 'nhb', 'svln', 'dvln', 'ismc', 'odmc', 'idmc',
		'osmc', 'mpls1', 'mpls2', 'mpls3', 'mpls4', 'mpls5', 'mpls6', 'mpls7',
		'mpls8', 'mpls9', 'mpls10', 'cl', 'sl', 'al', 'ra', 'eng', 'exid',
		'tr']
	
	idx2 = ['ts','te','td','pr','sa','da','sp','dp','sas','pas','ipkt','opkt','ibyt','obyt','flg','dir','bps','pps','bpp','cl','sl','al']
	dups_stable_fields = ['ts', 'pr', 'sa', 'da', 'sp', 'dp', 'flg', 'bpp']
	
	bidir_flows_stable_fields = ['ts', 'pr', 'sa', 'da', 'sp', 'dp']

	print('############################################')
	print('########## ~ MERGING DATAFRAMES ~ ##########')
	print('############################################')

	print('INITIAL SHAPE')
	print(pd_csv_to_label.shape)
	#print('INITIAL HEAD')
	#print(pd_csv_to_label.head(5))

	print(pd_csv_labelled.shape)
	
	pd_csv_to_label.join(pd_csv_labelled.set_index(bidir_flows_stable_fields), on=bidir_flows_stable_fields, lsuffix='_original', rsuffix='_joined')
	# @ https://stackoverflow.com/questions/44781633/join-pandas-dataframes-based-on-column-values
	df = pd.merge(pd_csv_to_label, pd_csv_labelled, how='left', on=bidir_flows_stable_fields)

	print(df.shape)
	# Labels in MALICIOUS_y, ATK_TYPE_y
	print(df.columns)

	# Clean headers
	for col in df.columns:
		if not (col == 'MALICIOUS_y' or col == 'ATK_TYPE_y') and col.endswith('_y'):
			df = df.drop(col, axis=1)

	df = df.drop(['MALICIOUS_x', 'ATK_TYPE_x'], axis=1)
	df = df.drop([c for c in df.columns if not (col == 'MALICIOUS_y' or col == 'ATK_TYPE_y') and col.endswith('_y')])
	new_cols = [c.rsplit('_', 1)[0] for c in df.columns if (c.endswith('_x') or c.endswith('_y')) or c != 'ATK_TYPE_y']
	df.columns = new_cols
	
	#print(df.columns)

	df['MALICIOUS'] = df['MALICIOUS'].fillna(0)
	df['ATK_TYPE'] = df['ATK_TYPE'].fillna('unknown')

	df = to_consistent_float_fields_ieee(df)
	
	#print(df.sample(30)['ATK_TYPE'])

	print('############################################')
	print('######## ~ END MERGING DATAFRAMES ~ ########')
	print('############################################')

	#out_path = os.path.splitext(csv_to_label)[0]+'-ieee-lbls-FINAL.csv'

	df = remove_spaces_from_string_cols(df)

	out_path = os.path.splitext(csv_to_label)[0]+'-LABELLED-FINAL.csv'
	df.to_csv(out_path, float_format='%.3f', index=False)
	return out_path

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

def clean_duplicates(csv_file):
	df = pd.read_csv(csv_file)
	df = to_consistent_float_fields_ieee(df)

	print(df.head(5))

	dups_stable_fields = ['ts', 'pr', 'sa', 'da', 'sp', 'dp', 'flg', 'bpp']
	df = df.drop_duplicates(dups_stable_fields, keep='last').sort_values('ts')

	print(df.head(5))

	out_path = os.path.splitext(csv_file)[0]+'-CLN.csv'
	df.to_csv(out_path, sep=',', float_format='%.3f', index=False)
	print('DF SHAPE AFTER REMOVING DUPS: {}'.format(df.shape))

	print(df.sample(10))

	return out_path


############################################################################################################
################### >>> DIRECTORY CLEANING
############################################################################################################

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





if __name__ == '__main__':
	"""
	dir = get_args()
	print(dir)

	pcaps_to_flows(dir)
	
	all_csvs_dir, all_csvs_file = flows_to_aggregated_csvs(dir)
	print(all_csvs_dir)

	all_csvs_file = change_all_csv_header_to_custom(all_csvs_dir)
	print(all_csvs_file)

	def_labels_csv = assign_default_labels(all_csvs_file)
	print(def_labels_csv)

	all_csvs_file = clean_duplicates(def_labels_csv)
	print('ALL CSVS FILE: {}'.format(all_csvs_file))

	final_file = assign_ieee_labels(def_labels_csv, IEEE_EZVIZ_GT_CSV)
	print(final_file)
	
	clean_up_flow_folders(dir)
	"""
	# Tests
	#add_geo_data_m2('./outputs/ieee-ezviz-complete/ieee-ezviz-complete-all-flows-bidir-csv-custom-fromat-LABELLED-FINAL.csv')
	geo_df = pd.read_csv('geo_df_csv.csv')
	geo_df = geo_df.drop(['da_asname', 'sa_asname'], axis=1)
	geo_df = geo_df.replace(np.nan, 'unresolved')
	print(geo_df.loc[122])
	geo_df.to_csv('geo_df_csv_clean.csv', sep=',', float_format='%.3f', index=False)
	sys.exit(0)