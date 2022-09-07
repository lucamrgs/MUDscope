
from multiprocessing.sharedctypes import Value
import re
import sys
import argparse
import os
import json
from pathlib import Path
from datetime import datetime

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

import pandas as pd

from mudscope import PcapUtils
from mudscope import MUDGenUtils
#from Analyses import *
from mudscope.Constants import *
from mudscope.MRTFeed import MRTFeed
from mudscope.MRTADashboard import MRTADashboard
from mudscope.VMUDEnforcer import Virtual_MUD_enforcer
from mudscope.MRTACharacterizator import MRTACharacterizator
from mudscope.MRTAPairClustersProcessor import MRTAPairClustersProcessor
import mudscope.device_mrt_pcaps_to_csv as mrttocsv
from typing import Iterable, Union

################################################################################
#                               Argument parsing                               #
################################################################################

def parse_args(arguments=None) -> argparse.Namespace:
	"""Parse arguments for running MUDscope.
	
		Returns
		-------
		args : argparse.Namespace
			Parsed arguments.
		"""
	# Create argument parser
	parser = argparse.ArgumentParser(
		description = "MUDscope - Stepping out of the MUD: Contextual threat "
		              "information for IoT devices with manufacturer-provided "
					  "behaviour profiles."
	)

	########################################################################
	#                       Chose mode of operation                        #
	########################################################################

	# Mode can be "mudgen", "reject", "analyze"
	modes_list = [MODE_MUDGEN, MODE_REJECT, MODE_FLOWS_GENERATION, MODE_ANALYZE]
	parser.add_argument(
		'--mode',
		metavar  = '<mode of program execution>',
		choices  = modes_list,
		help     = f"One of: [ {modes_list} ] .\n Consult documentation on github for detailed usage explanation!",
		required = True,
	)

	########################################################################
	#                            Mode = mudgen                             #
	########################################################################

	# If mode is "mudgen", a MUD config file to feed MUDgee is needed
	group_mudgen = parser.add_argument_group(
		title       = 'Mode: mudgen',
		description = 'For creating MUD files from benign network traces. '
		              'Required arguments when --mode mudgen is set.',
	)
	group_mudgen.add_argument(
		'--mudgen_config',
		metavar  = '<JSON file for mudgee MUD generation>',
		help     = 'name of JSON file for mudgee MUD generation',
		required = False,
	)

	########################################################################
	#                            Mode = reject                             #
	########################################################################

	# If mode is "reject", 
	#   - the config file for the referred device and gateway information, and
	#   - the relative path to MUD (OpenFLow) rules in CSV
	# must be specified
	group_reject = parser.add_argument_group(
		title       = 'Mode: reject',
		description = 'For filtering MUD rejected traffic from pcap files. '
		              'Required arguments when --mode reject is set.',
	)
	group_reject.add_argument(
		'--reject_config',
		metavar  = '<JSON file of MUD config for filtering data>',
		nargs    = '+',
		help     = 'name of MUD config JSON for specified MUD to enforce.\nRequired if mode is "reject"',
		required = False,
	)
	group_reject.add_argument(
		'--reject_mud_rules',
		metavar  = '<Relative-path of CSV file of filtering rules (only OpenFlow standard supported ATM)>',
		help     = 'CSV rules file generated by MUDgee, for specific device MUD to enforce.\nRequired if mode is "reject"',
		required = False,
	)
	group_reject.add_argument(
		'--reject_to_named_dir',
		metavar  = '<String>',
		help     = 'Name of directory that will be generated in outputs/<device>/ where the results of the "reject" operation will be stored.\nThis parameter is optional',
		required = False,
	)
	# Optional, if set, limits the number of packets that are processed when rejecting traffic
	group_reject.add_argument(
		'--pcap_limit',
		metavar  = '<integer>',
		type     = int,
		help     = 'Number to indicate how many packets will be processed by either functionality',
		required = False,
	)

	########################################################################
	#                           Mode = flows_gen                           #
	########################################################################

	group_flows_gen = parser.add_argument_group(
		title       = 'Mode: flows_gen',
		description = 'For transforming MRT pcap files to NetFlows. '
		              'Required arguments when --mode flows_gen is set.',
	)
	group_flows_gen.add_argument(
		'--flowsgen_tgt_dir',
		metavar  = '<String>',
		help     = 'Full or relative path to directory containing MUD-rejected pcap files',
		required = False,
	)
	group_flows_gen.add_argument(
		'--flowsgen_outdir',
		metavar  = '<String>',
		help     = 'Full or relative path to output directory in which to store NetFlows',
		required = False,
	)


	########################################################################
	#                           Generic settings                           #
	########################################################################

	# Not udsed at the moment
	parser.add_argument('--reject_online_interface', metavar='<String>', help='Name of the local interface on which to listen to device traffic."', required=False)	

	analysis_actions_list = [ANALYSIS_ACTION_IPS_FLOWS_GRAPHS, ANALYSIS_ACTION_PORTS_FLOWS_GRAPHS, ANALYSIS_ACTION_PKTS_CSV, ANALYSIS_ACTION_IPS_MAP, ANALYSIS_ACTION_FILTER_KNOWN_PROVIDERS, ANALYSIS_ACTION_MRTA_CHARACTERIZE, ANALYSIS_ACTION_DEVICE_MRT_EVOLUTION_DATAGEN]
	parser.add_argument('--analysis_action', metavar='<string to perform>', help='Indicates what action to perform in analysis, related to analysis pcap.\nSupported actions are \n{}.'.format(analysis_actions_list), required=False)

	parser.add_argument('--analysis_tgt', metavar='<pcap/csv file path>', help='path to file containing MRT-related information. Consult documentation for exhaustive explanation.', required=False)
	parser.add_argument('--analysis_capture_metadata', metavar='<file path to json object/dict>', help='Metadata dictionary object describing the capture to analyse. \nIt shall contain at least "device_id" (string), and "deployment_info" (any type as of now) that describes the setting where the device is (e.g., lon, lat, industry_type, ...)', required=False)
	parser.add_argument('--analysis_devname', metavar='<name of device>', help='name of the device to which the filtering refers. It is needed to output the analysis results to the right folder [outputs/<devname>].', required=False)
	
	parser.add_argument('--dsr_path', help='Dataset Scaler Reference path. Must be specified to set global scaling parameters when processing MRT flows, for --analysisi_action={}'.format(ANALYSIS_ACTION_MRTA_CHARACTERIZE), required=False)

	parser.add_argument('--mrtfeeds_config', metavar='file path', help=f'To use with --mode {MODE_MONITOR}.\nSpecify the configuration monitor file from which mrt feeds to compare (JSON list of dev_metadata + csv feed) are taken.', required=False)
	parser.add_argument('--monitor_features', help=f'To use with --mode {MODE_MONITOR}.\nSpecify the MRT feed features to cross-compare on the MRT feeds list specified in --mrtfeeds_config.\nUse format feature1,feature2,... See documentation for the list of supported MRT feed features.', required=False)
	#parser.add_argument('--monitor_output', help=f'To use with --mode {MODE_MONITOR}.\nSpecify the path to which the monitor plots output will be exported.', required=False)

	parser.add_argument('--session_name')


	# Return parsed arguments
	return parser.parse_args(arguments)

################################################################################
#                                    Modes                                     #
################################################################################

def mode_mudgen(config: Union[str, Path]) -> None:
	"""Run MUDscope in mudgen mode.

		Generates a MUD profile from a given configuration.
		See example config files for required format.
	
		Parameters
		----------
		config : Union[str, Path]
			Path to config file from which to generate MUD profile.
		"""
	# Ensure we are given a config file
	if config is None:
		raise ValueError(
			"Please specify a path to a config file using --mudgen_config "
			"<path>."
		)

	# Get info from MUD config file
	print('>>> MUDGEN CONFIG FILE: {}'.format(config))
	with open(config) as mg_cf:
		mg_data = json.load(mg_cf)
	device_name = mg_data['deviceConfig']['deviceName']
	# Run mudgee
	mudgee_gen_outcome = MUDGenUtils.run_mudgee(config)
	print(f'>>> MUD data to generate with MUDgee from info in config file {config}') 

	if mudgee_gen_outcome == 0:
		print(f'>>> MUD data output in result/{device_name}')
	else:
		print('>>> ERROR: Some error occurred in generating MUD data.')


def mode_reject(
		mud_rules    : Union[str, Path],
		reject_config: Iterable[Union[str, Path]],
		outdir       : Union[str, Path],
		pcap_limit   : Optional[int] = None,
	) -> None:
	"""Run MUDscope in reject mode.
	
		Applies MUD profile as a filter on given pcap files to create a new
		pcap file with MUD-rejected traffic.
		
		Parameters
		----------
		mud_rules : Union[str, Path]
			Path to csv file containing MUD rules.
			Usually this is generated as an output of the mode_mudgen function.

		reject_config : Iterable[Union[str, Path]]
			Path to json file containing reject configuration.

		outdir : Union[str, Path]
			Path to output directory in which to store output files

		pcap_limit : Optional[int], default = None
			Optional limit on number of flows to read from given pcap file.
		"""
	########################################################################
	#                                Checks                                #
	########################################################################

	# Check all parameters entered
	if mud_rules is None:
		raise ValueError("Please specify --reject_mud_rules <path>")

	# Check if MUD rules exist
	if not os.path.isfile(mud_rules):
		raise ValueError(
			f'MUD-derived (OpenFlow) rules CSV file <{mud_rules}> not found.'
		)

	# Check if filter is specified
	if reject_config is None:
		raise ValueError('Please specify --reject_config <path>')

	# Check if output dir is set
	if outdir is None:
		raise ValueError('Please specify --reject_to_named_dir <path>')

	########################################################################
	#                                 Run                                  #
	########################################################################

	# Loop over all specified config files
	for config in reject_config:
		# Check if file exists
		if not os.path.isfile(config):
			raise ValueError(f"Unknown config file: '{config}'")

		# Read reject configuration
		with open(config) as mc_data:
			data = json.load(mc_data)

		# Get PCAP location
		reject_pcap = data['filterPcapLocation']

		# Check if pcap to process exists
		if reject_pcap is not None and not os.path.isfile(reject_pcap):
			raise ValueError(
				f'"{reject_pcap}" does not exist. '
				f'Check --reject_config file key-values {json.dumps(data, indent=4)}'
				f'\n(if null: are you trying to use a MUDgee config file?)'
			)

		# Create MUD enforcer
		v_mud_enf = Virtual_MUD_enforcer(
			device_mac   = data['deviceConfig']['device'],
			device_name  = data['deviceConfig']['deviceName'] ,
			gateway_mac  = data['defaultGatewayConfig']['macAddress'],
			filter_rules = mud_rules,
		)

		# Run virtual MUD enforcer on pcap, for given
		v_mud_enf.enforce_in_pcap(
			pcap_file  = reject_pcap,
			pcap_limit = pcap_limit,
			save_json  = True,
			named_dir  = outdir,
		)


def mode_flow_file_gen(
		pcap_dir: Union[str, Path],
		outdir  : Union[str, Path],
	) -> None:
	"""Run MUDscope in flow_file_gen mode.
	
		Transforms pcap files of MUD-rejected traffic into NetFlows.
		
		Parameters
		----------
		pcap_dir : Union[str, Path]
			Directory containing pcap files of MUD-rejected traffic.

		outdir : Union[str, Path]
			Output directory in which to store NetFlows.
		"""
	# Check if pcap_dir exists
	if pcap_dir is None or not os.path.isdir(pcap_dir):
		raise ValueError(
			f"Null or invalid --flowsgen_tgt_dir argument for mode "
			f"{MODE_FLOWS_GENERATION}. Please enter a valid path to folder "
			"containing pcaps to convert to flows CSV file."
		)

	# Check if outdir is valid
	if outdir is None:
		raise ValueError(
			"Unspecified --flowsgen_outdir, please set parameter."
		)

	# Transform MRT to CSV files
	mrttocsv.module_each_pcap_to_complete_csv(
		pcaps_dir = pcap_dir,
		outdir    = outdir,
	)


def mode_analyze(args: argparse.Namespace) -> None:
	"""Run MUDscope in analyze mode."""
	...
	

def mode_monitor(args: argparse.Namespace) -> None:
	"""Run MUDscope in monitor mode."""
	...




def main(arguments=None) -> None:
	"""Run MUDscope, see individual modes for usage."""
	# Parse arguments
	args = parse_args(arguments)

	# Run in given mode
	if args.mode == MODE_MUDGEN:
		return mode_mudgen(
			config = args.mudgen_config,
		)
	elif args.mode == MODE_REJECT:
		return mode_reject(
			mud_rules     = args.reject_mud_rules,
			reject_config = args.reject_config,
			outdir        = args.reject_to_named_dir,
			pcap_limit    = args.pcap_limit,
		)
	elif args.mode == MODE_FLOWS_GENERATION:
		return mode_flow_file_gen(
			pcap_dir = args.flowsgen_tgt_dir,
			outdir   = args.flowsgen_outdir,
		)
	elif args.mode == MODE_ANALYZE:
		return mode_analyze(args)
	elif args.mode == MODE_MONITOR:
		return mode_monitor(args)
	else:
		...
		# raise ValueError(f"Unknown mode: {args.mode}")

	# Run given mode

	mode = args.mode

	session_name = args.session_name if args.session_name is not None else None

	# NOTE: All parameters default to None values if not specified

	analysis_action = args.analysis_action if args.analysis_action is not None else None
	analysis_capture_metadata = CHATACTERIZATION_METADATA_FOLDER + args.analysis_capture_metadata if args.analysis_capture_metadata is not None else None
	analysis_tgt = args.analysis_tgt if args.analysis_tgt is not None else None
	analysis_devname = args.analysis_devname if args.analysis_devname is not None else None
	
	dsr_path = args.dsr_path if args.dsr_path is not None else None

	mrtfeeds_config = args.mrtfeeds_config if args.mrtfeeds_config is not None else None


	################################################################################################
	# Preliminary files existence checks
	################################################################################################

	# # Manage case if files do not exist
	# if mudgen_config is not None and not os.path.isfile(mudgen_config):
	# 	print('>>> ERROR: Mudgen config [ {} ] does not exist'.format(mudgen_config), file=sys.stderr)
	# 	sys.exit(-1)
	# if reject_config is not None and not (os.path.isfile(reject_config) or os.path.isdir(reject_config)):
	# 	print('>>> ERROR: Reject config [ {} ] does not exist'.format(reject_config), file=sys.stderr)
	# 	sys.exit(-1)
	# if analysis_capture_metadata is not None and not os.path.isfile(analysis_capture_metadata):
	# 	print('>>> ERROR: Analysis characterization metadata [ {} ] does not exist'.format(analysis_capture_metadata), file=sys.stderr)
	# 	sys.exit(-1)
	# if reject_mud_rules is not None and not os.path.isfile(reject_mud_rules):
	# 	print('>>> ERROR: Mud filtering rules [ {} ] does not exist'.format(reject_mud_rules), file=sys.stderr)
	# 	sys.exit(-1)
	# if analysis_tgt is not None and not (os.path.isfile(analysis_tgt) or os.path.isdir(analysis_tgt)):
	# 	print('>>> ERROR: File/directory to analyse [ {} ] does not exist'.format(analysis_tgt), file=sys.stderr)
	# 	sys.exit(-1)
	# if dsr_path is not None and not os.path.isfile(dsr_path):
	# 	print('>>> ERROR: Dataset scaler reference does not exist at [ {} ]'.format(dsr_path), file=sys.stderr)
	# 	sys.exit(-1)
	# if mrtfeeds_config is not None and not os.path.isfile(mrtfeeds_config):
	# 	print('>>> ERROR: MRT feeds config [ {} ] does not exist'.format(mrtfeeds_config), file=sys.stderr)
	# 	sys.exit(-1)



	################################################################################################
	# MODE ANALYZE
	################################################################################################

	if mode == MODE_ANALYZE:

		if analysis_tgt is None or analysis_devname is None:
			print('>>> Make sure to provide path to pcap/csv/directory to analyse, via the parameter --analysis_tgt\n>>> Also please specify device name with parameter --analysis_devname, needed to reference output folder for analysis actions.')
			sys.exit(-1)
		
		output_folder = OUTPUTS_FOLDER + analysis_devname + '/'

		"""
		NOTE: Discontinued
		if analysis_action == ANALYSIS_ACTION_PKTS_CSV:
			csv_gen_res = PcapUtils.get_pcap_csv(analysis_tgt, analysis_devname)
			if csv_gen_res != -1:
				print('>>> {} has been generated. Please analyse it on Kibana'.format(csv_gen_res))
			else:
				print('>>> An error occurred trying to generate CSV from pcap file {}'.format(analysis_tgt))
				sys.exit(-1)
		if analysis_action == ANALYSIS_ACTION_IPS_FLOWS_GRAPHS:
			# Analyses functions
			display_flows_ips_description_info_graph(analysis_tgt)
		if analysis_action == ANALYSIS_ACTION_PORTS_FLOWS_GRAPHS:
			display_flows_ports_description_info_graph(analysis_tgt)
		if analysis_action == ANALYSIS_ACTION_IPS_MAP:
			folium_map(analysis_tgt, analysis_devname)
		if analysis_action == ANALYSIS_ACTION_FILTER_KNOWN_PROVIDERS:
			ti_register = TIRegister(analysis_tgt, analysis_devname)
			ti_register.filter_out_known_backends_pkts_from_pcap()
		"""
		############################################################################### MRTA CHARACTERIZE
		if analysis_action == ANALYSIS_ACTION_MRTA_CHARACTERIZE:
			###### Checks
			if analysis_capture_metadata is None:
				raise ValueError('>>> ERROR: analysis_capture_metadata parameter unspecified. Exiting'.format(mode))
			if dsr_path is None:
				raise ValueError('>>> ERROR: Dataset Scaler_generator Reference is unspecified. Exiting'.format(mode))

			metadata = {}
			try:
				with open(analysis_capture_metadata) as md:
					metadata = json.load(md)
			except Exception as e:
				print(e)
				print('>>> Unable to get analysis capture metadata. A JSON-consistency issue?')
				sys.exit(-1)
			if metadata['device_id'] is None or metadata['deployment_info'] is None:
				print('>>> device_id or deployment_info entries missing in analysis_capture_metadata [ {} ]. Exiting.'.format(analysis_capture_metadata))
				sys.exit(-1)

			##### Operations
			if os.path.isdir(analysis_tgt):
				dir = os.fsencode(analysis_tgt)
				for data in os.listdir(dir):
					data_name = os.fsdecode(data)
					if data_name.endswith(CSV_CLEAN_LABEL): # RUNS ON ALL PER-PCAP CSVs, OUTPUTS CORRESPONDING AMOUNT OF CHARACTERIZATION FILES

						path_to_file = analysis_tgt + '/' + data_name

						mrta_characterizator = MRTACharacterizator(metadata, path_to_file, dsr_path)
						mrta_characterizator.input_to_characterization_data()

						# Output name, default or specified
						now = datetime.now()
						dt_string = now.strftime("%Y%m%d_%H-%M-%S")
						characterization_name = 'ch_' + dt_string + '_' + analysis_devname + data_name + '.json'

						output_path = output_folder + analysis_devname + '_mrt_characterizations/'
						if session_name is not None:
							output_path = f'{output_folder}{analysis_devname}_{session_name}/{analysis_devname}_{session_name}_mrt_characterizations/'
						Path(output_path).mkdir(parents=True, exist_ok=True)
						mrta_characterizator.save_characterization(output_path + characterization_name)
			else:
				mrta_characterizator = MRTACharacterizator(metadata, analysis_tgt, dsr_path)
				mrta_characterizator.input_to_characterization_data()

				# Output name, default or specified
				now = datetime.now()
				dt_string = now.strftime("%Y%m%d_%H-%M-%S")
				characterization_name = 'ch_' + dt_string + '_' + analysis_devname + os.path.splitext(analysis_tgt)[0] + '.json'

				output_path = output_folder + analysis_devname + '_mrt_characterizations/'
				if session_name is not None:
					output_path = f'{output_folder}{analysis_devname}_{session_name}/{analysis_devname}_{session_name}_mrt_characterizations/'
				Path(output_path).mkdir(parents=True, exist_ok=True)
				mrta_characterizator.save_characterization(output_path + characterization_name)


		############################################################################### MRT EVOLUTION DATAGEN

		# Given array of characterization file paths, compute two-by-two sequences of transition characterization, and output (produced dataset) to specific folder
		if analysis_action == ANALYSIS_ACTION_DEVICE_MRT_EVOLUTION_DATAGEN:

			if not os.path.isdir(analysis_tgt):
				raise ValueError(f">>> ERROR: In order to run action [ {ANALYSIS_ACTION_DEVICE_MRT_EVOLUTION_DATAGEN} ] --analysis_tgt must be a directory, containing characterization files for a specific device. Exiting.")
			analysis_tgt = os.path.abspath(analysis_tgt)

			"""
			*****************************************************************************************************
        	* TODO: Move to deticated class/file function
        	*****************************************************************************************************
			"""
			# Order files chronologically wrt start date of each characterization, to be then analyzed two-by-two
			ordered_characterizations = {}
			tgt_dir = os.fsencode(analysis_tgt)
			for file in os.listdir(tgt_dir):
				filename = os.fsdecode(file)
				filename = os.fsdecode(tgt_dir) + filename if os.fsdecode(tgt_dir).endswith('/') else os.fsdecode(tgt_dir) + '/' + filename
				if filename.endswith('.json'):
					with open(filename, 'r') as file:
						try:
							f = json.load(file)
							start_timestamp = f['metadata']['time_window'][0]
						except KeyError as e:
							raise ValueError(f">>> ERROR: Unable to fetch time information from characterization file {filename}. Is the JSON format valid?. Exiting.")

					start_timestamp = float(datetime.timestamp(datetime.strptime(start_timestamp, STRFTIME_READABLE_FORMAT)))
					ordered_characterizations[filename] = start_timestamp
			
			ordered_characterizations = dict(sorted(ordered_characterizations.items(), key=lambda item: item[1]))
			#print(ordered_characterizations)
			
			"""
				FEDLAB
				NOTE : LEGIT ORDER : chrono_ch_files = [k for k in ordered_characterizations.keys()]

				NOTE - CURRENTLY TESTING WITH ALPHABETICAL ORDER : `same attacks' scenario
					[k for k in sorted(ordered_characterizations.keys(), key=lambda s:s.rsplit('_')[-1])]
				NOTE - CURRENTLY TESTING WITH SHUFFLED ORDER : `different attacks' scenario
					[k for k in random.sample(ordered_characterizations.keys(), len(ordered_characterizations.keys()))]
			"""
			chrono_ch_files = [k for k in ordered_characterizations.keys()]
			#chrono_ch_files = [k for k in random.sample(ordered_characterizations.keys(), len(ordered_characterizations.keys()))]
			for f in chrono_ch_files:
				print(f)
			
			#print(chrono_ch_files)
			# Produce two-by-two MRT clusters transition data entries
			entries_list = []
			
			for ch1, ch2 in zip(chrono_ch_files, chrono_ch_files[1:]):
				mrta_pcp = MRTAPairClustersProcessor(ch1, ch2)
				mrta_pcp.populate_clusters_shifts_data()
				mrta_pcp.set_transition_characterization_data()

				transition_df = mrta_pcp.get_transition_characterization_data_df_entry()
				mrta_pcp.print_distance_matrix(readable_only=False)
				entries_list.append(transition_df)
			
			df = pd.concat(entries_list, ignore_index=True)
			#print('CREATED DATASET')
			#print(df)

			now = datetime.now()
			dt_string = now.strftime("%Y%m%d_%H-%M-%S")
			clusters_evol_df_name = 'clusters_evols_' + dt_string + '_' + analysis_devname + '.csv'
			if session_name is not None:
					clusters_evol_df_name = f'clusters_evols_{session_name}_{analysis_devname}.csv'

			output_path = output_folder + analysis_devname + '_mrt_transitions_dfs/'
			Path(output_path).mkdir(parents=True, exist_ok=True)
			df.to_csv(output_path + clusters_evol_df_name)
			
	################################################################################################
	# MODE MONITOR
	################################################################################################

	elif mode == MODE_MONITOR:
		""" Generate fluctuation graphs """
		# See MRTADashboard:
		# 	Generate MRTFeed objects [CSV feed + metadata per device]
		#	MRTFeed metric(s) to display
		#	Save location for graphs and overall data
		#	TODO/Future work: Specify time window section
		
		# MRT Feeds information and building
		if mrtfeeds_config is None:
			raise ValueError(f'>>> ERROR: Attempting monitor options without having specified the mrtfeeds_config file. A valid mrtfeeds_config file must be specified in order to compare mrt feeds. Exiting.')

		with open(mrtfeeds_config) as mrtf_conf:
			mrtf_data = json.load(mrtf_conf)
		mrtf_data_list = mrtf_data['mrtfeeds']
		monitor_features = mrtf_data['features_watch']
		transition_window = mrtf_data['transition_window']
		
		mrt_feeds_list = []
		for l in mrtf_data_list:
			mrt_feeds_list.append(MRTFeed(l['device_metadata'], l['csv_mrt_feed']))

		mrtadb = MRTADashboard()
		mrtadb.setup(mrt_feeds_list, monitor_features, transition_window)
		mrtadb.detect_anomalies()
		mrtadb.find_matching_anomalies()
		#mrtadb.generate_report_from_matched_anomalies()
		#mrtadb.generate_feeds_signatures_set()
		#mrtadb.generate_feeds_signatures_comparison_matrix()
		#mrtadb.populate_feeds_signatures_comparison_matrix_over_watch_features_correlation()

		mrtadb.generate_report()
		#mrtadb.generate_report(report_name='comprehensive_report.txt', plots=False)

		
	else:
		print('>>> --mode argument "{}" is invalid. Exiting.'.format(mode))
		sys.exit(-1)

"""
python run.py --mode analyze --analysis_tgt ./outputs/ieee-ezviz-complete/mirai-httpflooding-all-ezviz-rejected.json --analysis_action ips_flows_graphs --analysis_devname ieee-ezviz
"""


if __name__ == '__main__':
	main()
	sys.exit(0)

"""


**** DEMO COMMANDS FOR SINGLE-DEVICE FUNCTIONS ****

# Generate MUD profile
$> python3 run.py --mode mudgen --mudgen_config ieee-ezviz-demo-1.json

# Generate reject configs
$> python3 generate_rjt_configs.py --devname [] --dev_mac [] --gw_mac []  --gw_ip4 [] --gw_ip6 [] --tgt_dir []
	/Users/lucamrgs/Big_Data/FederatedLab/UT/Malign

# Filter traffic off a pcap
$> python3 run.py --mode reject --reject_mud_rules result/ieee-ezviz-demo-1/ieee-ezviz-demo-1rule.csv --reject_config configs/reject_configs/ieee-ezviz-demo-1-A-floods --reject_to_named_dir time_1
$> python3 run.py --mode reject --reject_mud_rules result/ieee-ezviz-demo-1/ieee-ezviz-demo-1rule.csv --reject_config configs/reject_configs/ieee-ezviz-demo-1-B-scans --reject_to_named_dir time_2

# Generate NetFlow CSV
$> python3 run.py --mode flows_gen --flowsgen_tgt_dir outputs/ieee-ezviz-demo-1/ieee-ezviz-demo-1_time_1
$> python3 run.py --mode flows_gen --flowsgen_tgt_dir outputs/ieee-ezviz-demo-1/ieee-ezviz-demo-1_time_2

# Cluster flows in CSV and generate characterization file
$> python3 run.py --mode analyze --analysis_devname ieee-ezviz-demo-1 --analysis_action mrta_characterize --analysis_capture_metadata characterization_test.json --analysis_tgt outputs/ieee-ezviz-demo-1/ieee-ezviz-demo-1_time_1/ieee-ezviz-demo-1_time_1-all-flows-csv/*-CLN.csv 
[ieee-ezviz-demo-1_time_1-all-flows-gen-custom-format-CLN.csv]
$> python3 run.py --mode analyze --analysis_devname ieee-ezviz-demo-1 --analysis_action mrta_characterize --analysis_capture_metadata characterization_test.json --analysis_tgt outputs/ieee-ezviz-demo-1/ieee-ezviz-demo-1_time_2/ieee-ezviz-demo-1_time_2-all-flows-csv/*-CLN.csv 
[ieee-ezviz-demo-1_time_2-all-flows-gen-custom-format-CLN.csv]

# Generate the traffic evolution dataframe based on sequential pairwise traffic characterization files
$> python3 run.py --mode analyze --analysis_devname ieee-ezviz-demo-1 --analysis_action device_mrt_evolution_datagen --analysis_tgt outputs/ieee-ezviz-demo-1/ieee-ezviz-demo-1_mrt_characterizations



**** MACROs reject traffic to characterization file ****

python3 MACRO_rjt_to_ch.py --devname ieee-ezviz-demo-1 --reject_config configs/reject_configs/ieee-ezviz-demo-1-A-mirai-floods --reject_to_named_dir time_1 --flowsgen_tgt_dir outputs/ieee-ezviz-demo-1/ieee-ezviz-demo-1_time_1 --analysis_capture_metadata characterization_test.json

python3 MACRO_rjt_to_ch.py --devname ieee-ezviz-demo-1 --reject_config configs/reject_configs/ieee-ezviz-demo-1-B-scans --reject_to_named_dir time_2 --flowsgen_tgt_dir outputs/ieee-ezviz-demo-1/ieee-ezviz-demo-1_time_2 --analysis_capture_metadata characterization_test.json

"""


"""
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*
# 			TODO - CHANGE TO CSV-PER-PCAP APPROACH!!!!!!!!
#			DONE >>> IT LOOKS LIKE IT WORKS!!
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*

SPLIT PCAP FILES ON SECONDS: editpcap -i 60 input.pcap output.pcap
https://serverfault.com/questions/131872/how-to-split-a-pcap-file-into-a-set-of-smaller-ones
https://www.wireshark.org/docs/man-pages/editcap.html

DSR PATH EZVIZ: '/Users/lucamrgs/Big_Data/IEEE-Huy-Kang/dataset_scaler_gen_reference.csv'

$> python3 run.py --mode mudgen --mudgen_config <file>.json

$> python3 src/generate_rjt_configs.py --tgt_dir <full path to dir with pcaps to reject from> --devname <devname> --dev_mac <dev mac> --gw_mac <> --gw_ip4 <> [--gw_ip6 <>]

$> python3 run.py --mode reject --reject_mud_rules result/<device-id>/<device-id>rule.csv --reject_config path/to/<name of generated rjt folder>

$> python3 run.py --mode flows_gen --flowsgen_tgt_dir outputs/<device-id>[/rjt pcaps folder]

$> python3 run.py --mode analyze --analysis_devname <device-id> --analysis_action mrta_characterize --dsr_path <path to dataset scaling generation reference csv> --analysis_capture_metadata <metadata-filename>.json --analysis_tgt outputs/<device-id>/<flows CSV folder>

$> python3 run.py --mode analyze --analysis_devname <device-id> --analysis_action device_mrt_evolution_datagen --analysis_tgt outputs/<device-id>/<mrt characterizations folder>

"""

