
"""
	Class with the purpose of analysing the variations between two (2) characterization files, referring to the same device.
	It processes information to output 'transaction data' that logs the evolution of the MRT for the specific device.

	The logic is wrapped in a class for attributes persistence, and compactness.
"""



"""
	NOTE s : Explanation
	*   At a clusters level, the access to shared information only partly is in the description of points in the 
		cluster itself, for matching clusters may be relatively different amongst devices - depending on their MUDs. Rather, it's a more scalable and
		generalized approach to study the evolution of the clusters across time, and compare the behaviours.

		A hypothetical dashboard will then 'fire up' when deviations in the clusters evolution are observed on a single device.
		If through the same time window, deviations in clusters evolution are observed in other devices as well, then
		this represents a hint of a coordinated activity - as would be detecting it through network telescopes.

		On the other side, if just one single devices registers deviations in clusters evolutions across a time span, 
		that shall suggest that only the single device is being targeted by anomalous interest.

		Furthermore, isolating the detection to the evolution of clusters for single devices, abstracts the 'normal behaviour' of rejected traffic,
		and scales across multiple devices. In short, it does not bind the analysis to 'linear' correlations.

		Consequently, if a malicious activity is novel altogether, it will be recorded as novel (~new cluster generation) across devices.

	* 	Indeed, the tentative of classifying attack flows from a different device on clusters of one reference device, yielded very low likelihood of
		correct classification (see colab, 'strengths' vector of hdbscan predict).


	NOTE s : Procedure
	>	NOTE: DO NOT CHECK NUMBER OF FLOWS, FOR IT IS NOT NECESSARILY REPRESENTATIVE OF DYNAMIC TIME/EVOLUTION		
	>	NOTE NOT NEEDED TO DETERMINE MERGES, SPLITS, NEW (as of now). INSTEAD >
	
	>	Focus on overall description of proximity movements:
		>	Clusters' number variation
		>	Collect all proximity transition vectors based on 'closest centers':
			> Over matching RC distance matrix (mutual proximity mapping, should be: same clusters)
			> Over non-matching rows: Row cluster -> column cluster at closest
			> 'INVERSE TIME MOVEMENTS' over columns: Column cluster -> closest to ex-cluster at row
		> NUMBER OF CONVERGENCES: i.e.: how many rows go in single column cluster
		> NUMBER OF DIVERGENCES: i.e.: how many columns are closest to single row cluster
	
	> Per each vector category, compute fixed-number properties (e.g., deciles), that describe high level characterization of movements
		in a replicable and fixed format.
	
	> EXPRESS HIGH AND STRONG CORRELATION OVER SUCH TRANSITION DESCRIPTIONS:
		> Include presence of outliers that may signify particularly anomalous behaviour
		> NOTE: Consider both SIMILARITY of distributions (correlation) and RANGE of variations (e.g., how many points are similar or diverge)
	
	> NOTE: IT IS CRUCIAL TO INCLUDE THE INFORMATION OF THE TIME ELAPSED BOTH WITHIN WINDOW OF CLUSTER CREATION, AND AS
			THE PERIOD OVER WHICH THE TRANSITION IS COMPUTED
		> Limitation? Do not address as of now.

	> NOTE: WHAT IF CLUSTERS OF ONE DEVICE ALREADY APPROXIMATE ANOMALOUS ACTIVITY, COMPARED TO THE OTHER DEVICE?
		> COMPARE BOTH the transaction data AND the pairwise distances
		> Assess if anomalous clusters on one device approximate 'normal' clusters in other device.

	
	NOTE s from Thijs
		What does a metric tells me about the actual evolution of incoming traffic that is rejected?
		
		> JUSTIFY precisely why I choose some metrics/approach, why we track the changes.
		
		Make explicit the information of interest of the observed variations of traffic

		For forward and backward clusterings, compute a KNNs within a threshold on the total distance observed.
		Explain WHAT the output data MEANS (e.g., very small std on forward matches?? Clusters balance??)


"""




"""

	TODO TODO TODO:
		- Include mut/fwd/bwd distances metrics!!

"""


import os
import sys
import json
import numpy as np
import datetime

from pprint import pprint

import pandas as pd

from mudscope.Constants import *

from scipy.spatial import distance_matrix

# TODO: Move class constants to original class, refer directly to class constant labels
METADATA_LBL = 'metadata'
CLUSTERS_LBL = 'clusters'
DEPLOYMENT_DATA_LBL = 'deployment_data'
DEPLOYMENT_INFO_LBL = 'deployment_info'
DEPLOYMENT_ID_LBL = 'deployment_id'
TIME_WINDOW_LBL = 'time_window'
SPATIAL_DATA_LBL = 'spatial_data'
CENTROID_LBL = 'centroid'
META_CENTROID_LBL = 'meta_centroid'
DEVICE_ID_LBL = 'device_id'
METADATA_TOT_FLOWS_LBL = 'total_flows'

NOISE_CLUSTER_LBL = '-1'

COMPLETE_CAPTURE_DATA_LBL = 'complete_capture_descriptor'

CLUSTERING_PARAMS_LBL = 'clustering_params'
SCALING_METHOD_LBL = 'scaling_method'

DISTANCE_SHIFT_PLACEHOLDER = -1

class MRTAPairClustersProcessor:

	"""
		# NOTE NOTE NOTE: All this below code is strinctly referred to the JSON formats and 'magic' labels used, as I did not
							set up a Constants structure to serve the purpose.
	"""

	def __init__(self, ch_1, ch_2, centers_type='metacenter'):
		"""
			ch_1 and 2 are JSON characterization files. The referred device must be the same, and the first file must capture a time 
			window that starts eariler than the one of the second file. Time windows may intersect.
		"""

		self.centers_type = centers_type

		####################################################################################
		# Support data
		####################################################################################	

		self.ch1_abspath = ''
		self.ch2_abspath = ''

		self.ch1_t_start = None
		self.ch1_t_end = None

		self.ch2_t_start = None
		self.ch2_t_end = None

		self.ch1_metadata = {}
		self.ch1_clusters = {}
		
		self.ch2_metadata = {}
		self.ch2_clusters = {}

		self.dimension = 0

		self.dist_matrix_centers = pd.DataFrame()

		self.centers_distances_shift_matrix = pd.DataFrame()
		self.centers_distances_shift_matrix_readable = pd.DataFrame()

		# NOTE: No need to understand born, deat, merged, and split clusters ATM
		
		# NOTE: HERE BELOW IS COMPUTED ON METACENTERS

		self.mutual_matching_clusters_centers_vectors = []
		self.forward_matching_clusters_centers_vectors = []
		self.backward_matching_clusters_centers_vectors = []
		
		####################################################################################
		# Shifts data
		####################################################################################
		
		self.all_distances_average = 0
		self.all_distances_std = 0
		self.all_distances_deciles = []

		self.transition_clusters_balance = 0
		self.ch1_clusters_n = 0
		self.ch2_clusters_n = 0

		# Important: records the variation of the percentage of noise over all capture flows. A spike increase of noise may
		# signify the presence of a network event.
		self.noise_percent_balance = 0

		# Mutual matches metrics
		self.shift_mutual_matches_n = 0
		self.shift_mutual_matches_percentage = 0

		self.mutual_matching_clusters_shift_vectors_avg = 0
		self.mutual_matching_clusters_shift_vectors_std = 0
		self.mutual_matching_clusters_shift_vectors_deciles = []

		# Forward matches metrics - agglomeration + agglomeration percentage indicates wether there is a convergence in matches type over one cluster
		self.shift_forward_matches_n = 0
		self.shift_forward_matches_percentage = 0
		self.shift_fwd_agglomeration_avg = 0
		self.shift_fwd_agglomeration_std = 0
		self.shift_fwd_agglomeration_highest = 0
		self.shift_fwd_agglomeration_highest_percentage = 0
		self.shift_fwd_agglomeration_highest_col_cluster = 0
		self.shift_fwd_agglomeration_highest_cluster_centroid = []

		self.forward_matching_clusters_shift_vectors_avg = 0
		self.forward_matching_clusters_shift_vectors_std = 0
		self.forward_matching_clusters_shift_vectors_deciles = []

		# Backward matches metrics
		self.shift_backward_matches_n = 0
		self.shift_backward_matches_percentage = 0
		self.shift_bwd_agglomeration_avg = 0
		self.shift_bwd_agglomeration_std = 0
		self.shift_bwd_agglomeration_highest = 0
		self.shift_bwd_agglomeration_highest_percentage = 0
		self.shift_bwd_agglomeration_highest_row_cluster = 0
		self.shift_bwd_agglomeration_highest_cluster_centroid = []
		
		self.backward_matching_clusters_shift_vectors_avg = 0
		self.backward_matching_clusters_shift_vectors_std = 0
		self.backward_matching_clusters_shift_vectors_deciles = []

		# Output data wrapper
		self.output_data = {}
	

		self.populate_support_data(ch_1, ch_2)


	def populate_support_data(self, ch_1, ch_2):
		# Files existence and format
		if not os.path.isfile(ch_1) or not ch_1.endswith('.json'):
			raise ValueError(f">>> ERROR: File {ch_1} does not exist, or is not in json format")
		if not os.path.isfile(ch_2) or not ch_2.endswith('.json'):
			raise ValueError(f">>> ERROR: File {ch_2} does not exist, or is not in json format")

		self.ch1_abspath = os.path.abspath(ch_1)
		self.ch2_abspath = os.path.abspath(ch_2)

		# JSON Consistency checks. Could be implemented with jsonschema.validate (@ https://stackoverflow.com/questions/54491156/validate-json-data-using-python)
		try:
			with open(ch_1, 'r') as file:
				ch_1_file = json.load(file)
			self.ch1_metadata = ch_1_file[METADATA_LBL]
			self.ch1_clusters = ch_1_file[CLUSTERS_LBL]
		except Exception as e:
			raise ValueError(f">>> ERROR: Could not gather [metadata] and [clusters] MRTA-characterization data from file {ch_1}")
		try:
			with open(ch_2, 'r') as file:
				ch_2_file = json.load(file)
			self.ch2_metadata = ch_2_file[METADATA_LBL]
			self.ch2_clusters = ch_2_file[CLUSTERS_LBL]
		except Exception as e:
			raise ValueError(f">>> ERROR: Could not gather [metadata] and [clusters] MRTA-characterization data from file {ch_2}")

		try:
			ch1_noise_pts = 0
			if NOISE_CLUSTER_LBL in self.ch1_clusters.keys():
				ch1_noise_pts = self.ch1_clusters[NOISE_CLUSTER_LBL][SPATIAL_DATA_LBL]['num_pts']
			ch1_total_pts = ch_1_file[COMPLETE_CAPTURE_DATA_LBL]['total_flows']
			ch1_noise_perc = float(int(ch1_noise_pts) / int(ch1_total_pts))

			ch2_noise_pts = 0
			if NOISE_CLUSTER_LBL in self.ch2_clusters.keys():
				ch2_noise_pts = self.ch2_clusters[NOISE_CLUSTER_LBL][SPATIAL_DATA_LBL]['num_pts']
			ch2_total_pts = ch_2_file[COMPLETE_CAPTURE_DATA_LBL]['total_flows']
			ch2_noise_perc = float(int(ch2_noise_pts) / int(ch2_total_pts))

			self.noise_percent_balance = ch2_noise_perc - ch1_noise_perc
		except KeyError as e:
			raise ValueError(f">>> ERROR: DATA NOT FOUND: Could not access [{NOISE_CLUSTER_LBL} > {SPATIAL_DATA_LBL}] or [{COMPLETE_CAPTURE_DATA_LBL}] data from either \n>>> {ch_1} \n>>> or \n>>> {ch_2}.")

		# Clustering parameters
		try:
			ch1_scaling_method = self.ch1_metadata[CLUSTERING_PARAMS_LBL][SCALING_METHOD_LBL]
			ch2_scaling_method = self.ch2_metadata[CLUSTERING_PARAMS_LBL][SCALING_METHOD_LBL]

			# TODO: Add checks on algorithm and features set. (NOTE: NOT PARAMETERS! They shall be diverse on different instances according to best results)

			if ch1_scaling_method != ch2_scaling_method:
				raise ValueError(f">>> ERROR: DIFFERENT SCALING METHOD: The clusters in the two characterization files were obtained with data scaled in different ways: \
				{ch1_scaling_method}, {ch2_scaling_method}.\n>>> Output bound to be inconsistent. Exiting.")
		except KeyError as e:
			raise ValueError(f">>> ERROR: DATA NOT FOUND: Could not access {CLUSTERING_PARAMS_LBL} > {SCALING_METHOD_LBL} metadata from either \n>>> {ch_1} \n>>> or \n>>> {ch_2}.")

		# Logical consistency checks: same devices, deployments, time windows
		try:
			ch1_t_start = self.ch1_metadata[TIME_WINDOW_LBL][0]
			self.ch1_t_start = datetime.datetime.timestamp(datetime.datetime.strptime(ch1_t_start, STRFTIME_READABLE_FORMAT))
			ch2_t_start = self.ch2_metadata[TIME_WINDOW_LBL][0]
			self.ch2_t_start = datetime.datetime.timestamp(datetime.datetime.strptime(ch2_t_start, STRFTIME_READABLE_FORMAT))

			ch1_t_end = self.ch1_metadata[TIME_WINDOW_LBL][1]
			self.ch1_t_end = datetime.datetime.timestamp(datetime.datetime.strptime(ch1_t_end, STRFTIME_READABLE_FORMAT))
			ch2_t_end = self.ch2_metadata[TIME_WINDOW_LBL][1]
			self.ch2_t_end = datetime.datetime.timestamp(datetime.datetime.strptime(ch2_t_end, STRFTIME_READABLE_FORMAT))

			"""
				TODO: FEDLAB - READJUST TIME CHECKS
			"""
			if ch1_t_start == ch2_t_start:
				print(f">>> WARNING: SAME TIME WINDOW START: The first file shall contain traffic in a time window starting before that of the second file. \n>>> File 1: \n>>> {ch_1}, File 2: \n>>> {ch_2}")
			if ch1_t_end == ch2_t_end:
				print(f">>> WARNING: SAME TIME WINDOW END: The first file shall contain traffic in a time window ending before that of the second file. \n>>> File 1: \n>>> {ch_1}, File 2: \n>>> {ch_2}")
			if ch1_t_start > ch2_t_start:
				raise ValueError(f">>> ERROR: INCONSISTENT TIME ORDER: First file contains traffic from a time window starting after that of the secon file. \n>>> File 1: \n>>> {ch_1}, File 2: \n>>> {ch_2}")
			if ch1_t_end > ch2_t_end:
				raise ValueError(f">>> ERROR: INCONSISTENT TIME ORDER: First file contains traffic from a time window ending after that of the secon file. \n>>> File 1: \n>>> {ch_1}, File 2: \n>>> {ch_2}")
		except KeyError as e:
			raise ValueError(f">>> ERROR: DATA NOT FOUND: Could not access 'time_window' metadata from either {ch_1} or {ch_2}.")

		
		try:
			ch1_device = self.ch1_metadata[DEPLOYMENT_DATA_LBL][DEVICE_ID_LBL]
			ch2_device = self.ch2_metadata[DEPLOYMENT_DATA_LBL][DEVICE_ID_LBL]
			if ch1_device != ch2_device:
				#raise ValueError(f">>> ERROR: DIFFERENT DEVICES: device in characterization 1: {ch1_device}, device in characterization 2: {ch2_device}.\n>>> This class compares pairs of MRT in sequence for the same device")
				print('>>> TEST: devices are different')
		except KeyError as e:
			raise ValueError(f">>> ERROR: DATA NOT FOUND: Could not access '{DEPLOYMENT_INFO_LBL} > {DEVICE_ID_LBL}' metadata from either {ch_1} or {ch_2}.")

		try:
			ch1_deployment_id = self.ch1_metadata[DEPLOYMENT_DATA_LBL][DEPLOYMENT_INFO_LBL][DEPLOYMENT_ID_LBL]
			ch2_deployment_id = self.ch2_metadata[DEPLOYMENT_DATA_LBL][DEPLOYMENT_INFO_LBL][DEPLOYMENT_ID_LBL]
			if ch1_deployment_id != ch2_deployment_id:
				print(f">>> WARNING: DIFFERENT DEPLOYMENTS: deployment in characterization 1: {ch1_deployment_id}, deployment in characterization 2: {ch2_deployment_id}.\n>>> This class is built to operate for a single device in one specific deplyment")
		except KeyError as e:
			raise ValueError(f">>> ERROR: DATA NOT FOUND: Could not access {DEPLOYMENT_INFO_LBL} > {DEPLOYMENT_ID_LBL} metadata from either {ch_1} or {ch_2}.")

		# Dimension of reference
		center_label = CENTROID_LBL if self.centers_type == 'centers' else META_CENTROID_LBL
		self.dimension = len(self.ch1_clusters['0'][SPATIAL_DATA_LBL][center_label])

		self.dist_matrix_centers = self.get_clusters_dist_matrix(centers=self.centers_type)
		self.centers_distances_shift_matrix, self.centers_distances_shift_matrix_readable = self.get_clusters_shifts_matrix(centers=self.centers_type)


	def get_clusters_dist_matrix(self, centers):       
		center_label = META_CENTROID_LBL if centers == 'metacenters' else CENTROID_LBL

		try: 
			ch1_clusters_centers = dict(sorted({int(c) : self.get_cluster_centroid('1', c) for c in self.ch1_clusters.keys()}.items()))
			ch2_clusters_centers = dict(sorted({int(c) : self.get_cluster_centroid('2', c) for c in self.ch2_clusters.keys()}.items()))
		except KeyError as e:
			raise ValueError(f"Could not get data from {CLUSTERS_LBL} > {SPATIAL_DATA_LBL} > {center_label}")

		clusters_distance_matrix = pd.DataFrame()
		try:
			clusters_distance_matrix = pd.DataFrame(data=distance_matrix([ctr for ctr in ch1_clusters_centers.values()], [ctr for ctr in ch2_clusters_centers.values()]),
															index=[idx for idx in ch1_clusters_centers.keys()], # rows index correspond to 'first' capture
															columns=[col for col in ch2_clusters_centers.keys()]) # columns index correspond to 'second' capture
		except ValueError as e:
			print(e)
			print('>>> Check AMI-selected features class varuable in MRTACharacterizator!! -> Re-generate characterization files.')
			sys.exit(-1)

		# Drop noise clusters
		if -1 in clusters_distance_matrix.index:
			clusters_distance_matrix = clusters_distance_matrix.drop(-1, axis=0)
		if -1 in clusters_distance_matrix.columns:
			clusters_distance_matrix = clusters_distance_matrix.drop(-1, axis=1)
		#print(clusters_distance_matrix)
		return clusters_distance_matrix


	def get_clusters_shifts_matrix(self, centers):
		"""
			Returns matrix with cells in the form [v1, v2] where

				if v1 != DISTANCE_SHIFT_PLACEHOLDER
					=> the row cluster is closest by v1 to the cluster of column

				if v2 != DISTANCE_SHIFT_PLACEHOLDER
					=> the column cluster is closest by v1 to the cluster of row
		"""

		centers_match_mask = pd.DataFrame(index=self.dist_matrix_centers.index, columns=self.dist_matrix_centers.columns)

		centers_match_mask_readable = pd.DataFrame(index=self.dist_matrix_centers.index, columns=self.dist_matrix_centers.columns)

		for col in centers_match_mask.columns:
			centers_match_mask[col] = pd.Series([[DISTANCE_SHIFT_PLACEHOLDER, DISTANCE_SHIFT_PLACEHOLDER]] * len(centers_match_mask.index))
			centers_match_mask_readable[col] = pd.Series([[' ', ' ']] * len(centers_match_mask_readable.index))

		#print(centers_match_mask)
		
		matrix_copy = self.dist_matrix_centers.copy()
		
		# ALL MINIMUMS OVER COLUMNS - FORWARD MATCH
		all_cols_min_coords = matrix_copy.idxmin()
		for col, idx in all_cols_min_coords.items(): # NOTE: idx, col is switched because of idxmin() default return format
			column_val = matrix_copy.iloc[idx, col]
											# 	[min_row                             , min_col]
			centers_match_mask.iloc[idx, col] = [centers_match_mask.iloc[idx, col][0], column_val]
			centers_match_mask_readable.iloc[idx, col] = [centers_match_mask_readable.iloc[idx, col][0], 'B']
			
		# ALL MINIMUMS OVER ROWS - BACKWARD MATCH
		all_rows_min_coords = matrix_copy.idxmin(axis='columns')
		for idx, col in all_rows_min_coords.items():
			row_val = matrix_copy.iloc[idx, col]
											# 	[min_row                   , min_col]
			centers_match_mask.iloc[idx, col] = [row_val, centers_match_mask.iloc[idx, col][1]]
			centers_match_mask_readable.iloc[idx, col] = ['F', centers_match_mask_readable.iloc[idx, col][1]]


		return centers_match_mask, centers_match_mask_readable

	def print_distance_matrix(self, readable_only=False):
		if readable_only:
			print(self.centers_distances_shift_matrix_readable)
		else:
			print(self.dist_matrix_centers)
			print(self.centers_distances_shift_matrix)
			print(self.centers_distances_shift_matrix_readable)

		
	def populate_clusters_shifts_data(self):
		"""
			Scans through clusters shifts matrix, gather respective clusters data, and populate shift vectors accordingly.
		"""

		# As ch1, ch2 are in chronological order, the difference between the number of clusters from the second to the first corresponds to 'lost' and 'gained' balance
		self.ch1_clusters_n = len(self.ch1_clusters.keys())
		self.ch2_clusters_n = len(self.ch2_clusters.keys())
		self.transition_clusters_balance = self.ch2_clusters_n - self.ch1_clusters_n
		
		deciles_splits = [.1, .2, .3, .4, .5, .6, .7, .8, .9, 1]
		# Reference for deciles on multi-dimensional points at https://numpy.org/doc/stable/reference/generated/numpy.quantile.html

		all_distances_avg = np.average(self.dist_matrix_centers.to_numpy())
		all_distances_std = np.std(self.dist_matrix_centers.to_numpy())
		all_distances_deciles = np.quantile(self.dist_matrix_centers.to_numpy(), deciles_splits)

		self.all_distances_average = all_distances_avg
		self.all_distances_std = all_distances_std
		self.all_distances_deciles = all_distances_deciles

		print(self.all_distances_average)
		print(self.all_distances_std)
		print(self.all_distances_deciles)

		n_mutual_matches = 0
		n_forward_matches = 0
		n_backward_matches = 0
		
		# For a given row in the list, for each column, a match for row only ([match, - ]) is a forward match
		# Each element at cluster i corresponds to the number of forward matches present in the column
		fwd_agglomeration_values = [0] * len(self.centers_distances_shift_matrix.columns)

		# For a given column in the list, for each row, a match for column only ([ - , match ]) is a backward match
		# Each element at cluster i corresponds to the number of backward matches present in the row
		bwd_agglomeration_values = [0] * len(self.centers_distances_shift_matrix.index)

		# Naif iteration method, but the most flexible I have found...
		for row in self.centers_distances_shift_matrix.index:
			for col in self.centers_distances_shift_matrix.columns:
				val = self.centers_distances_shift_matrix.iloc[row, col]
				
				# NOTE: Computations in conditions as most frequent case would be no matches
				# Mutual matching clusters: source and destination clusters centers match as the closest
				if val[0] != -1 and val[0] == val[1]:
					center1 = self.ch1_clusters[str(row)][SPATIAL_DATA_LBL][META_CENTROID_LBL]
					center2 = self.ch2_clusters[str(col)][SPATIAL_DATA_LBL][META_CENTROID_LBL]
					dist_vector = np.subtract(center2, center1).tolist()
					data_tuple = ('mutual', row, col, dist_vector)
					self.mutual_matching_clusters_centers_vectors.append(data_tuple)
					n_mutual_matches += 1

				# Forward matching clusters: source clusters that match a destination cluster, without the destination cluster matching back
				if val[0] != -1 and val[1] == -1:
					# Cluster of the row has cluster of col as the closest, without col cluster matching closeness back
					center1 = self.ch1_clusters[str(row)][SPATIAL_DATA_LBL][META_CENTROID_LBL]
					center2 = self.ch2_clusters[str(col)][SPATIAL_DATA_LBL][META_CENTROID_LBL]
					dist_vector = np.subtract(center2, center1).tolist()
					data_tuple = ('forward', row, col, dist_vector)
					self.forward_matching_clusters_centers_vectors.append(data_tuple)
					n_forward_matches += 1
					# The cluster at column is a forward match for the cluster at row
					fwd_agglomeration_values[col] += 1


				# Backward matching clusters: destination cluster is closest to source cluster, while source cluster actually maps to other destination clusters
				if val[0] == -1 and val[1] != -1:
					# Cluster of the row has cluster of col as the closest, without col cluster matching closeness back
					center1 = self.ch1_clusters[str(row)][SPATIAL_DATA_LBL][META_CENTROID_LBL]
					center2 = self.ch2_clusters[str(col)][SPATIAL_DATA_LBL][META_CENTROID_LBL]
					dist_vector = np.subtract(center2, center1).tolist()
					data_tuple = ('backward', row, col, dist_vector)
					self.backward_matching_clusters_centers_vectors.append(data_tuple)
					n_backward_matches += 1
					# The cluster at row is a forward match for the cluster at column
					bwd_agglomeration_values[row] += 1

		"""
			TODO?? Use Descriptors.VolumesDescriptor??
		"""
		# Empty values for non-present forward or backward matches
		empty_shift_vectors_avg = np.zeros(self.dimension)
		empty_shift_vectors_std = np.zeros(self.dimension)
		empty_shift_vectors_deciles = np.zeros((10, self.dimension))

		# Total matches cases
		n_total_matches = n_mutual_matches + n_forward_matches + n_backward_matches

		# Mutual matching clusters
		raw_mutual_centers = [val[-1] for val in self.mutual_matching_clusters_centers_vectors]
		self.shift_mutual_matches_n = n_mutual_matches
		self.shift_mutual_matches_percentage = float(n_mutual_matches / n_total_matches)
		self.mutual_matching_clusters_shift_vectors_avg = np.average(raw_mutual_centers, axis=0)
		self.mutual_matching_clusters_shift_vectors_std = np.std(raw_mutual_centers, axis=0)
		self.mutual_matching_clusters_shift_vectors_deciles = np.quantile(raw_mutual_centers, deciles_splits, axis=0)

		# Forward matching clusters
		raw_forward_centers = [val[-1] for val in self.forward_matching_clusters_centers_vectors]
		self.shift_forward_matches_n = n_forward_matches
		self.shift_forward_matches_percentage = float(n_forward_matches / n_total_matches)
		self.forward_matching_clusters_shift_vectors_avg = np.average(raw_forward_centers, axis=0) if self.shift_forward_matches_n > 0 else empty_shift_vectors_avg
		self.forward_matching_clusters_shift_vectors_std = np.std(raw_forward_centers, axis=0) if self.shift_forward_matches_n > 0 else empty_shift_vectors_std
		self.forward_matching_clusters_shift_vectors_deciles = np.quantile(raw_forward_centers, deciles_splits, axis=0) if self.shift_forward_matches_n > 0 else empty_shift_vectors_deciles

		# Forward agglomeration data
		self.shift_fwd_agglomeration_avg = np.average(fwd_agglomeration_values)
		self.shift_fwd_agglomeration_std = np.std(fwd_agglomeration_values)
		self.shift_fwd_agglomeration_highest = np.max(fwd_agglomeration_values)
		self.shift_fwd_agglomeration_highest_col_cluster = np.argmax(fwd_agglomeration_values)
		self.shift_fwd_agglomeration_highest_percentage = float(self.shift_fwd_agglomeration_highest / n_forward_matches) if n_forward_matches > 0 else 0

		# Backward matching clusters
		raw_backward_centers = [val[-1] for val in self.backward_matching_clusters_centers_vectors] 
		self.shift_backward_matches_n = n_backward_matches
		self.shift_backward_matches_percentage = float(n_backward_matches / n_total_matches)
		self.backward_matching_clusters_shift_vectors_avg = np.average(raw_backward_centers, axis=0) if self.shift_backward_matches_n > 0 else empty_shift_vectors_avg
		self.backward_matching_clusters_shift_vectors_std = np.std(raw_backward_centers, axis=0) if self.shift_backward_matches_n > 0 else empty_shift_vectors_std
		self.backward_matching_clusters_shift_vectors_deciles = np.quantile(raw_backward_centers, deciles_splits, axis=0) if self.shift_backward_matches_n > 0 else empty_shift_vectors_deciles

		# Backward agglomeration data
		self.shift_bwd_agglomeration_avg = np.average(bwd_agglomeration_values)
		self.shift_bwd_agglomeration_std = np.std(bwd_agglomeration_values)
		self.shift_bwd_agglomeration_highest = np.max(bwd_agglomeration_values)
		self.shift_bwd_agglomeration_highest_row_cluster = np.argmax(bwd_agglomeration_values)
		self.shift_bwd_agglomeration_highest_percentage = float(self.shift_bwd_agglomeration_highest / n_backward_matches) if n_backward_matches > 0 else 0


	def set_transition_characterization_data(self):
		
		data = {
			'metadata': {
				'ch1_file' : self.ch1_abspath, # Debugging purposes
				'ch2_file' : self.ch2_abspath, # Debugging purposes
				'ch1_metadata' : self.ch1_metadata,
				'ch2_metadata' : self.ch2_metadata,
				'clusters_shifts_additional_data' : {
					'mutual_matches_data' : self.mutual_matching_clusters_centers_vectors,
					'forward_matches_data' : self.forward_matching_clusters_centers_vectors,
					'backward_matches_data' : self.backward_matching_clusters_centers_vectors
				}
			},
			# NOTE: Below amount of information is and shall be constant across any instance
			'transition_characterization_dataset_data' : {
				'util_data' : {
					'centroids_dimension' : self.dimension
				},
				'time_values' : {
					#'compressed_time_windows_data' : [self.ch1_t_start, self.ch1_t_end, self.ch2_t_start, self.ch1_t_end],
					'ch1_t_start' : self.ch1_t_start,
					'ch1_t_end' : self.ch1_t_end,
					'ch2_t_start' : self.ch2_t_start,
					'ch2_t_end' : self.ch2_t_end,
					'elapsed_transition_time' : self.ch2_t_start - self.ch1_t_end
				},
				'balance_values' : {
					'ch1_tot_flows' : int(self.ch1_metadata[METADATA_TOT_FLOWS_LBL]),
					'ch2_tot_flows' : int(self.ch2_metadata[METADATA_TOT_FLOWS_LBL]),
					'tot_flows_balance' : int(self.ch2_metadata[METADATA_TOT_FLOWS_LBL]) - int(self.ch1_metadata[METADATA_TOT_FLOWS_LBL]),
					'ch1_clusters_n' : self.ch1_clusters_n,
					'ch2_clusters_n' : self.ch2_clusters_n,
					'clusters_balance' : self.transition_clusters_balance,
					'noise_balance' : self.noise_percent_balance
				},
				'all_distances' : {
					'all_dists_avg' : self.all_distances_average.item(),
					'all_dists_std' : self.all_distances_std.item(),
					'all_dists_deciles' : self.all_distances_deciles.tolist()
				},
				'mutual_matches' : {
					'mutual_matches_n' : self.shift_mutual_matches_n,
					'mutual_matches_percentage' : self.shift_mutual_matches_percentage,
					'mutual_vects_avg' : self.mutual_matching_clusters_shift_vectors_avg.tolist(),
					'mutual_vects_std' : self.mutual_matching_clusters_shift_vectors_std.tolist(),
					'mutual_vects_deciles' : self.mutual_matching_clusters_shift_vectors_deciles.tolist()
				},
				'forward_matches' : {
					'fwd_matches_n' : self.shift_forward_matches_n,
					'fwd_matches_percentage' : self.shift_forward_matches_percentage,
					'fwd_matches_agglomeration_avg' : self.shift_fwd_agglomeration_avg.item(),
					'fwd_matches_agglomeration_std' : self.shift_fwd_agglomeration_std.item(),
					'fwd_matches_agglomeration_max' : self.shift_fwd_agglomeration_highest.item(),
					'fwd_matches_agglomeration_max_percentage' : self.shift_fwd_agglomeration_highest_percentage,
					'fwd_matches_agglomeration_max_col_cluster' : self.shift_fwd_agglomeration_highest_col_cluster.item(),
					'fwd_vects_avg' : self.forward_matching_clusters_shift_vectors_avg.tolist(),
					'fwd_vects_std' : self.forward_matching_clusters_shift_vectors_std.tolist(),
					'fwd_vects_deciles' : self.forward_matching_clusters_shift_vectors_deciles.tolist()
				},
				'backward_matches' : {
					'bwd_matches_n' : self.shift_backward_matches_n,
					'bwd_matches_percentage' : self.shift_backward_matches_percentage,
					'bwd_matches_agglomeration_avg' : self.shift_bwd_agglomeration_avg.item(),
					'bwd_matches_agglomeration_std' : self.shift_bwd_agglomeration_std.item(),
					'bwd_matches_agglomeration_max' : self.shift_bwd_agglomeration_highest.item(),
					'bwd_matches_agglomeration_max_percentage' : self.shift_bwd_agglomeration_highest_percentage,
					'bwd_matches_agglomeration_max_row_cluster' : self.shift_bwd_agglomeration_highest_row_cluster.item(),
					'bwd_vects_avg' : self.backward_matching_clusters_shift_vectors_avg.tolist(),
					'bwd_vects_std' : self.backward_matching_clusters_shift_vectors_std.tolist(),
					'bwd_vects_deciles' : self.backward_matching_clusters_shift_vectors_deciles.tolist()
				}
			}
		}

		self.output_data = data

	def save_data_to_json(self, output_path):
		#print(type(self.output_data))
		#print(json.dumps(self.output_data, indent=4))
		with open(output_path, 'w') as f:
			json.dump(self.output_data, f, ensure_ascii=False, indent=4)

	def get_transition_characterization_data_df_entry(self, output_path=None, to_csv=False):
		# NOTE:
		# All below magic value referncers refer to the structure of the self.output_data, described above.

		dataset_data_dict = {}

		dataset_data_dict.update(self.output_data['transition_characterization_dataset_data']['util_data'])
		dataset_data_dict.update(self.output_data['transition_characterization_dataset_data']['time_values'])
		dataset_data_dict.update(self.output_data['transition_characterization_dataset_data']['balance_values'])
		dataset_data_dict.update(self.output_data['transition_characterization_dataset_data']['all_distances'])
		dataset_data_dict.update(self.output_data['transition_characterization_dataset_data']['mutual_matches'])
		dataset_data_dict.update(self.output_data['transition_characterization_dataset_data']['forward_matches'])
		dataset_data_dict.update(self.output_data['transition_characterization_dataset_data']['backward_matches'])

		mut_m_v_deciles_cols = ['mutual_vects_decile_' + str(i+1) for i in range(len(dataset_data_dict['mutual_vects_deciles']))]
		fwd_m_v_deciles_cols = ['fwd_vects_decile_' + str(i+1) for i in range(len(dataset_data_dict['fwd_vects_deciles']))]
		bwd_m_v_deciles_cols = ['bwd_vects_decile_' + str(i+1) for i in range(len(dataset_data_dict['bwd_vects_deciles']))]
		
		flat_dataset_data_dict = {k : [v] for k, v in dataset_data_dict.items()}

		df_mut_vcts_deciles = pd.DataFrame()
		df_fwd_vcts_deciles = pd.DataFrame()
		df_bwd_vcts_deciles = pd.DataFrame()
		
		#df_all_deciles_cols = mut_m_v_deciles_cols + fwd_m_v_deciles_cols + bwd_m_v_deciles_cols

		df_mut_vcts_deciles[mut_m_v_deciles_cols] = pd.DataFrame(flat_dataset_data_dict['mutual_vects_deciles'], index=[0])
		df_fwd_vcts_deciles[fwd_m_v_deciles_cols] = pd.DataFrame(flat_dataset_data_dict['fwd_vects_deciles'], index=[0])
		df_bwd_vcts_deciles[bwd_m_v_deciles_cols] = pd.DataFrame(flat_dataset_data_dict['bwd_vects_deciles'], index=[0])


		df = pd.DataFrame.from_dict(flat_dataset_data_dict)

		# Ref https://stackoverflow.com/questions/41968732/set-order-of-columns-in-pandas-dataframe, https://stackoverflow.com/questions/7376019/list-extend-to-index-inserting-list-elements-not-only-to-the-end
		
		df[mut_m_v_deciles_cols] = df_mut_vcts_deciles
		df[fwd_m_v_deciles_cols] = df_fwd_vcts_deciles
		df[bwd_m_v_deciles_cols] = df_bwd_vcts_deciles
		
		idx_at = list(df.columns).index('mutual_vects_deciles') # Reorder self.dataset indexes ...
		df_new_index_order1 = list(df.columns)
		df_new_index_order1[idx_at+1:idx_at+1] = mut_m_v_deciles_cols
		df = df.reindex(columns=df_new_index_order1)
		df = df.loc[:,~df.columns.duplicated()]

		idx_at = list(df.columns).index('fwd_vects_deciles') # Reorder self.dataset indexes ...
		df_new_index_order2 = list(df.columns)
		df_new_index_order2[idx_at+1:idx_at+1] = fwd_m_v_deciles_cols
		df = df.reindex(columns=df_new_index_order2)
		df = df.loc[:,~df.columns.duplicated()]

		idx_at = list(df.columns).index('bwd_vects_deciles') # Reorder self.dataset indexes ...
		df_new_index_order3 = list(df.columns)
		df_new_index_order3[idx_at+1:idx_at+1] = bwd_m_v_deciles_cols
		df = df.reindex(columns=df_new_index_order3)
		df = df.loc[:,~df.columns.duplicated()]

		non_flattened_deciles_cols = ['mutual_vects_deciles', 'fwd_vects_deciles', 'bwd_vects_deciles']
		
		df = df.drop(columns=non_flattened_deciles_cols)
		
		#print(df.columns)
		#pprint(flat_dataset_data_dict)
		#print(df)
		
		if to_csv and output_path is not None:
			df.to_csv(output_path, sep=',', float_format='%.5f', index=False)
			print(f">>> MRT Clusters transition dataframe entry saved to CSV at {output_path}.")
		
		return df
	
	def get_cluster_centroid(self, ch_lbl, cluster_lbl):
		center_label = META_CENTROID_LBL if self.centers_type == 'metacenters' else CENTROID_LBL
		if ch_lbl == '1':
			return self.ch1_clusters[cluster_lbl][SPATIAL_DATA_LBL][center_label]
		elif ch_lbl == '2':
			return self.ch2_clusters[cluster_lbl][SPATIAL_DATA_LBL][center_label]
		else:
			raise ValueError(f">>> ERROR: INCORRECT CH_FILE LABEL: Unrecognised 'ch' label '{ch_lbl}' in self.get_cluster_centroid. Accepted ch labels are '1' or '2'. Exiting.")


if __name__ == '__main__':
	print('Testing!')
	#ch_f_ezviz_1 = './outputs/ieee-ezviz-pt/mrt_characterizations/ch_20210806_15-11-52_ieee-ezviz-pt.json'
	#'ch_20211020_15-35-24_ieee-ezviz-ptscan-hostport-all-ezviz-rejected-flows-custom-hdr-CLN.csv.json'
	ch_f_ezviz_1 = './outputs/ieee-ezviz-pt/ieee-ezviz-pt_mrt_characterizations/ch_20211020_15-35-23_ieee-ezviz-ptdos-synflooding-all-ezviz-rejected-flows-custom-hdr-CLN.csv.json'
	#ch_f_ezviz_2 = './outputs/ieee-ezviz-pt/mrt_characterizations/ch_20210806_15-13-19_ieee-ezviz-pt.json'
	ch_f_ezviz_2 = './outputs/ieee-ezviz-pt/ieee-ezviz-pt_mrt_characterizations/ch_20211020_15-35-24_ieee-ezviz-ptscan-hostport-all-ezviz-rejected-flows-custom-hdr-CLN.csv.json'

	ch_f_nugu = './outputs/ieee-nugu-pt/mrt_characterizations/ch_20210812_11-49-35_ieee-nugu-pt.json'
	mrta_pcp = MRTAPairClustersProcessor(ch_f_ezviz_1, ch_f_ezviz_2)
	print(mrta_pcp.centers_distances_shift_matrix)
	mrta_pcp.populate_clusters_shifts_data()
	mrta_pcp.set_transition_characterization_data()
	mrta_pcp.print_distance_matrix(readable_only=False)
	mrta_pcp.save_data_to_json('doesitworkfurter.json')
	mrta_pcp.get_transition_characterization_data_df_entry('a.csv', to_csv=True)
	
