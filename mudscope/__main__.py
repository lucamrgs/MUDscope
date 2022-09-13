# Imports
import argparse
import json
import logging
import os
import pandas as pd
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from collections import OrderedDict
from datetime import datetime
from mudscope import MUDGenUtils
from mudscope.Constants import *
from mudscope.MRTFeed import MRTFeed
from mudscope.MRTADashboard import MRTADashboard
from mudscope.VMUDEnforcer import Virtual_MUD_enforcer
from mudscope.MRTACharacterizator import MRTACharacterizator
from mudscope.MRTAPairClustersProcessor import MRTAPairClustersProcessor
from mudscope import device_mrt_pcaps_to_csv as mrttocsv
from pathlib import Path
from scapy.all import *
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
	#                       Choose mode of operation                       #
	########################################################################

	subparsers = parser.add_subparsers(
		title = 'mode',
		description = 'Mode in which to run MUDscope.',
		dest = 'mode',
	)

	########################################################################
	#                            Mode = mudgen                             #
	########################################################################

	parser_mudgen = subparsers.add_parser(
		MODE_MUDGEN,
		description = 'Create MUD files from benign network traces.',
		help        = 'Create MUD files from benign network traces.',
	)
	parser_mudgen.add_argument(
		'--config',
		metavar  = '<path>',
		help     = 'path to JSON config file for mudgee MUD generation',
		required = True,
	)

	########################################################################
	#                            Mode = reject                             #
	########################################################################

	parser_reject = subparsers.add_parser(
		MODE_REJECT,
		description = 'Filter MUD rejected traffic from pcap files.',
		help        = 'Filter MUD rejected traffic from pcap files.',
	)
	parser_reject.add_argument(
		'--config',
		metavar  = '<path>',# '<JSON file of MUD config for filtering data>',
		nargs    = '+',
		help     = 'path(s) to JSON config file(s) for MUD enforcement',
		required = True,
	)
	parser_reject.add_argument(
		'--rules',
		metavar  = '<path>',
		help     = 'path to MUD rules CSV file generated by MUDgee',
		required = True,
	)
	parser_reject.add_argument(
		'--output',
		metavar  = '<path>',
		help     = 'path to output directory in which to store results',
		required = True,
	)
	# Optional, if set, limits the number of packets that are processed when rejecting traffic
	parser_reject.add_argument(
		'--limit',
		metavar  = '<int>',
		type     = int,
		help     = 'optional, limits the number of packets processed when rejecting traffic',
		required = False,
	)

	########################################################################
	#                           Mode = flows_gen                           #
	########################################################################

	parser_flows_gen = subparsers.add_parser(
		MODE_FLOWS_GENERATION,
		description = 'Transforms MRT pcap files to NetFlows.',
		help        = 'Transforms MRT pcap files to NetFlows.',
	)
	parser_flows_gen.add_argument(
		'--input',
		metavar  = '<path>',
		help     = 'path to directory containing MUD-rejected pcap files',
		required = True,
	)
	parser_flows_gen.add_argument(
		'--output',
		metavar  = '<path>',
		help     = 'path to output directory in which to store NetFlows',
		required = True,
	)

	########################################################################
	#                            Mode = analyze                            #
	########################################################################

	parser_analyze = subparsers.add_parser(
		MODE_ANALYZE,
		description = 'Analyze NetFlows: characterization and evolution analysis.',
		help        = 'Analyze NetFlows: characterization and evolution analysis.',
	)
	# Set possible analysis actions
	action_list = [
		# ANALYSIS_ACTION_IPS_FLOWS_GRAPHS,
		# ANALYSIS_ACTION_PORTS_FLOWS_GRAPHS,
		# ANALYSIS_ACTION_PKTS_CSV,
		# ANALYSIS_ACTION_IPS_MAP,
		# ANALYSIS_ACTION_FILTER_KNOWN_PROVIDERS,
		ANALYSIS_ACTION_MRTA_CHARACTERIZE,
		ANALYSIS_ACTION_DEVICE_MRT_EVOLUTION_DATAGEN,
	]
	parser_analyze.add_argument(
		'--action',
		choices  = action_list,
		help     = 'action to perform in analysis',
		required = True,
	)

	parser_analyze.add_argument(
		'--input',
		nargs    = '+',
		metavar  = '<path>',
		help     = 'path(s) to file(s) containing MRT-related information',
		required = True,
	)
	parser_analyze.add_argument(
		'--metadata',
		metavar  = '<path>',
		help     = 'path to JSON file describing the capture to analyse.', # \nIt shall contain at least "device_id" (string), and "deployment_info" (any type as of now) that describes the setting where the device is (e.g., lon, lat, industry_type, ...)
	)

	parser_analyze.add_argument(
		'--dsr',
		metavar  = '<path>',
		help     = f'path to Dataset Scaler Reference (DSR) CSV file',
	)
	parser_analyze.add_argument(
		'--output',
		metavar  = '<path>',
		help     = "output directory/file for analyzed file(s).",
		required = True,
	)


	########################################################################
	#                             Monitor mode                             #
	########################################################################

	# Currently not supported

	# group_monitor = parser.add_argument_group(
	# 	title       = 'Mode: monitor',
	# 	description = 'Monitors changes in MRT feeds. '
	# 	              'Required arguments when mode is monitor.',
	# )
	
	# group_monitor.add_argument(
	# 	'--mrtfeeds_config',
	# 	metavar='<path>',
	# 	help=f'configuration monitor file specifying which mrt feeds to compare (JSON list of dev_metadata + csv feed) are taken.',
	# )
	# group_monitor.add_argument(
	# 	'--monitor_features',
	# 	help=f'MRT feed features to cross-compare on the MRT feeds list specified in --mrtfeeds_config.', #'\nUse format feature1,feature2,...',
	# )
	# # group_monitor.add_argument(
	# # 	'--monitor_output',
	# # 	help=f'path to which the monitor plots output will be exported.',
	# # )

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
			"Please specify a path to a config file using --config "
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
		raise ValueError("Please specify --rules <path>")

	# Check if MUD rules exist
	if not os.path.isfile(mud_rules):
		raise ValueError(
			f'MUD-derived (OpenFlow) rules CSV file <{mud_rules}> not found.'
		)

	# Check if filter is specified
	if reject_config is None:
		raise ValueError('Please specify --config <path>')

	# Check if output dir is set
	if outdir is None:
		raise ValueError('Please specify --output <path>')

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
				f'Check --config file key-values {json.dumps(data, indent=4)}'
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
			f"Null or invalid --input argument for mode "
			f"{MODE_FLOWS_GENERATION}. Please enter a valid path to folder "
			"containing pcaps to convert to flows CSV file."
		)

	# Check if outdir is valid
	if outdir is None:
		raise ValueError(
			"Unspecified --output, please set parameter."
		)

	# Transform MRT to CSV files
	mrttocsv.module_each_pcap_to_complete_csv(
		pcaps_dir = pcap_dir,
		outdir    = outdir,
	)


def mode_analyze(
		mode   : str,
		targets: Iterable[Union[str, Path]],
		config : Union[str, Path],
		dsr    : Union[str, Path],
		output : Union[str, Path],
	) -> None:
	"""Run MUDscope in analyze mode.
	
		TODO
		"""
	# Check if target is given
	if targets is None:
		raise ValueError(
			"Unspecified parameter --input, please set parameter."
		)

	# Operate in 
	if mode == ANALYSIS_ACTION_MRTA_CHARACTERIZE:
		return mode_characterize(
			targets = targets,
			config  = config,
			dsr     = dsr,
			outdir  = output,
		)
	elif mode == ANALYSIS_ACTION_DEVICE_MRT_EVOLUTION_DATAGEN:
		return mode_evolution(
			characterizations = targets,
			outfile           = output,
		)
	else:
		raise ValueError(
			f"Unknown --action: '{mode}'"
			f" . Should be one of '{ANALYSIS_ACTION_MRTA_CHARACTERIZE}', "
			f"'{ANALYSIS_ACTION_DEVICE_MRT_EVOLUTION_DATAGEN}'."
		)


def mode_characterize(
		targets: Iterable[Union[str, Path]],
		config : Union[str, Path],
		dsr    : Union[str, Path],
		outdir : Union[str, Path],
	) -> None:
	"""Run MUDscope in characterize mode.

		Creates characterization files for given NetFlow files.

		Parameters
		----------
		targets : Iterable[Union[str, Path]]
			Paths to NetFlow files from which to generate characterization
			files.

		config : Union[str, Path]
			Path to characterization configuration file.

		dsr : Union[str, Path]
			Path to dataset scaling reference (DSR) file.

		outdir : Union[str, Path]
			Path to output directory in which to store processed
			characterization files.
		"""
	###### Checks
	if config is None:
		raise ValueError('metadata parameter unspecified.')
	if dsr is None:
		raise ValueError('Dataset Scaler_generator Reference is unspecified.')

	# Load metadata
	with open(config) as md:
		metadata = json.load(md)

	# Check if metadata is set
	if metadata.get('device_id') is None or metadata.get('deployment_info') is None:
		raise ValueError(
			f"device_id or deployment_info entries missing in "
			f"metadata [ {config} ]"
		)

	# Loop over all given targets
	for target in targets:
		# Initialise characterization constructor
		mrta_characterizator = MRTACharacterizator(
			capture_data = metadata,
			csv_file = target,
			dataset_scaler_gen_reference_path = dsr,
		)
		# Perform characterization
		mrta_characterizator.input_to_characterization_data()

		# Prepare output file
		outfile = Path(outdir) / (Path(target).stem + '.json')
		# Make directory
		outfile.parent.mkdir(parents=True, exist_ok=True)
		# Save to outfile
		mrta_characterizator.save_characterization(outfile)


def mode_evolution(
		characterizations: Iterable[Union[str, Path]],
		outfile: Union[str, Path],
	) -> None:
	"""Run MUDscope in evolution mode.
	
		Generates MRT feeds from given characterization files.

		Parameters
		----------
		characterizations : Iterable[Union[str, Path]]
			Paths to characterization files from which to generate MRT feeds.

		outfile : Union[str, Path]
			Path to output file in which to store MRT feed.
		"""
	# Initialise characterizations
	ordered_characterizations = {}

	# Loop over all files
	for filename in characterizations:
		# Load file as json
		with open(filename, 'r') as file:
			data = json.load(file)
		# Extract timestamp
		start_timestamp = data.get('metadata', {}).get('time_window', [None])[0]

		# Print error if any
		if start_timestamp is None:
			raise ValueError(
				f"Unable to fetch time information from characterization file "
				f"{filename}. Is the JSON format valid?."
			)

		# Convert date to timestamp and store
		ordered_characterizations[filename] = float(
			datetime.timestamp(
			datetime.strptime(start_timestamp, STRFTIME_READABLE_FORMAT)
		))
	
	# Sort dictionary
	ordered_characterizations = OrderedDict(
		sorted(ordered_characterizations.items(), key=lambda item: item[1])
	)
	
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

	# Prepare output file
	outfile = Path(outfile)
	# Make directory
	outfile.parent.mkdir(parents=True, exist_ok=True)
	# Save to outfile
	df.to_csv(outfile)
	

def mode_monitor(config: Union[str, Path]) -> None:
	"""Run MUDscope in monitor mode.

		Generate fluctuation graphs in MRT feeds.
	
		Parameters
		----------
		config : Union[str, Path]
			Path to config file for generating fluctuation graphs.
		"""

	""" Generate fluctuation graphs """
	# See MRTADashboard:
	# 	Generate MRTFeed objects [CSV feed + metadata per device]
	#	MRTFeed metric(s) to display
	#	Save location for graphs and overall data
	#	TODO/Future work: Specify time window section
	
	# MRT Feeds information and building
	if config is None:
		raise ValueError(
			'Attempting monitor options without having specified the '
			'mrtfeeds_config file. A valid mrtfeeds_config file must be '
			'specified in order to compare mrt feeds.'
		)

	with open(config) as mrtf_conf:
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




def main(arguments=None) -> None:
	"""Run MUDscope, see individual modes for usage."""
	# Parse arguments
	args = parse_args(arguments)

	# Run in given mode
	# --mode mudgen
	if args.mode == MODE_MUDGEN:
		return mode_mudgen(
			config = args.config,
		)
	# --mode reject
	elif args.mode == MODE_REJECT:
		return mode_reject(
			mud_rules     = args.rules,
			reject_config = args.config,
			outdir        = args.output,
			pcap_limit    = args.limit,
		)
	# --mode flows_gen
	elif args.mode == MODE_FLOWS_GENERATION:
		return mode_flow_file_gen(
			pcap_dir = args.input,
			outdir   = args.output,
		)
	# --mode analyze
	elif args.mode == MODE_ANALYZE:
		return mode_analyze(
			mode    = args.action,
			targets = args.input,
			config  = args.metadata,
			dsr     = args.dsr,
			output  = args.output,
		)
	# --mode monitor
	elif args.mode == MODE_MONITOR:
		return mode_monitor(
			config = args.mrtfeeds_config,
		)
	else:
		raise ValueError(f"Unknown mode: {args.mode}")

	
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

