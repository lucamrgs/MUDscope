
from audioop import avg
from distutils.log import debug
from lib2to3.pgen2.token import PERCENT
from multiprocessing.sharedctypes import Value
import os
from pyexpat import features
import sys
import ast
from itertools import combinations

from datetime import datetime
from tabulate import tabulate

import time

import json
import pprint

import seaborn as sns
import matplotlib.pyplot as plt

from Constants import MONITOR_OUTPUTS_FOLDER, MRT_SIGNATURES_COMBINED_CORRELATION_THESHOLD, MRT_WINDOW_SIGNATURE_DF_NAME_TAG, MRT_SIGNATURES_COMPARISON_MATRIX_PLACEHOLDER, MRT_SIGNATURES_CORRELATION_THRESHOLD, FEEDS_SIGNATURES_CORRELATION_DICTIONARIES_KEY_LINK
plt.rcParams.update({'font.size': 14})

import numpy as np
import pandas as pd
from pandas.plotting import parallel_coordinates
pd.set_option("display.precision", 16)

MY_SAVE_PATH_DEFAULT = MONITOR_OUTPUTS_FOLDER
#'/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/demo_results/'#pre-results-data/diff-attacks-monodim/'

from MRTFeed import MRTFeed

MRTFEEDS_TIME_OFFSET_TOLERANCE = 0.1
# To gather the name of the device from the feed name
# TODO: Set to -1 when device name is the last substrnig after the last '_'
LABEL_OFFSET = -1

# Either 'max' or 'avg'
ALERT_METHOD = 'max'

# Max allowed difference in transitions_width of signatures to trigger their comparison.
MAX_DIFF_SIGNATURES_SIZE = 2


def anonymise_string(string: str) -> str:
    #print(f'STRING!! = {string}')
    ret = string.replace('tue-', 'l1-')
    ret = ret.replace('ut-', 'l2-')
    ret = ret.replace('acsac', 'record')
    #print(f'RET!! = {ret}')
    return ret


class MRTADashboard:
    """
        Class that stores multiple MRT Feeds, and plots them, along group-wise metrics and information
        An MRT Feed is a pair of type <file.json, pandas.dataframe> 
    """
    def __init__(self):
        
        self.feeds = []
        self.signature_transitions_window_size = 0
        self.total_corr_significant_features = []
        self.features_watch_list = []
        self.feeds_signatures_set = {}
        self.feeds_signatures_comparison_matrix = pd.DataFrame()
        self.feeds_signatures_correlation_dictionary = {}


        self.signatures_correlation_report = []
        
        self.feeds_anomalies = {}
        self.feeds_unpacked_anomalies = {}
        self.pair_anomalies_correlation_log = {}
        
        self.anomalies_report = []
        self.better_anomalies_report = []

        print('>>> Dashboard generated')


    def setup(self, feeds_list, features_watch, signature_transitions_window_size):
        for mrt_feed in feeds_list:
            if not isinstance(mrt_feed, MRTFeed):
                raise ValueError(f">>> ERROR: feeds_list contain non MRTFeed-type values.")

        self.feeds = {anonymise_string(feed.id) : feed for feed in feeds_list}        
        self.signature_transitions_window_size = signature_transitions_window_size

        for feed, data in self.feeds.items():
            data.metadata['device_id'] = anonymise_string(data.metadata['device_id'])
            data.id = anonymise_string(data.id)

        #print(self.feeds[0].data.head())
        print(f'rolling window: {signature_transitions_window_size}')

        #self.align_feeds()
        mrt_feed_columns = [col for col in self.feeds[list(self.feeds.keys())[0]].data.columns]
        # SLICE AFTER METADATA
        self.total_corr_significant_features = mrt_feed_columns[mrt_feed_columns.index('clusters_balance'):]
        # REMOVE NOMINAL CLUSTER FEATURES
        self.total_corr_significant_features = [f for f in self.total_corr_significant_features if not (f.endswith('_col_cluster') or f.endswith('_row_cluster') or f.endswith('noise_balance')) ]
        self.features_watch_list = features_watch


    def detect_anomalies(self):
        """
            Base anomaly detection that considers any period of fluctuations between periods of flat behaviours as an anomaly.
            The markers for the period are two transitions where clusters_balance = 0, ch_2_clusters_n = 1
        """
        for feed in self.feeds.values():
            clusters_balances = feed.data['clusters_balance']
            clusters_numbers = feed.data['ch2_clusters_n']
            time_markers = feed.data['ch1_t_start']
            entry_windows = feed.data.index.tolist()
            device = feed.metadata['device_id']
            
            anomaly_markers = zip(clusters_balances, clusters_numbers, time_markers, entry_windows)
            anomalies_windows = {}
            anomaly_count = 0
            in_anomaly = False

            for marker in anomaly_markers:
                # If not baseline behaviour at transitions
                if not(marker[0] == 0 and marker[1] == 1):
                    # If not recording ongoing anomaly
                    if not in_anomaly:
                        # Log begin time of anomaly
                        anomalies_windows[f'{feed.id}_anomaly-{anomaly_count}'] = {'device_id' : device,'start' : marker[2], 'end' : 0, 'window_start': (marker[3] -1 if marker[3] > 0 else marker[3])  , 'window_end' : -1}
                        in_anomaly = True
                # If in baseline behaviour, we're not recording an anomaly
                elif marker[0] == 0 and marker[1] == 1:
                    if in_anomaly: # We were logging an anomaly, which stopped. Hence we log the end time
                        anomalies_windows[f'{feed.id}_anomaly-{anomaly_count}']['end'] = marker[2]
                        anomalies_windows[f'{feed.id}_anomaly-{anomaly_count}']['window_end'] = marker[3]
                        anomalies_windows[f'{feed.id}_anomaly-{anomaly_count}']['transitions_width'] = \
                                            anomalies_windows[f'{feed.id}_anomaly-{anomaly_count}']['window_end'] - \
                                            anomalies_windows[f'{feed.id}_anomaly-{anomaly_count}']['window_start'] + 1
                        # Get dataframe portion of anomaly
                        anomalies_windows[f'{feed.id}_anomaly-{anomaly_count}']['signature'] = feed.data.loc[
                                            anomalies_windows[f'{feed.id}_anomaly-{anomaly_count}']['window_start'] : \
                                            anomalies_windows[f'{feed.id}_anomaly-{anomaly_count}']['window_end']]
                        #print(anomalies_windows[anomaly_count]['signature'])
                        self.feeds_unpacked_anomalies[f'{feed.id}_anomaly-{anomaly_count}'] = anomalies_windows[f'{feed.id}_anomaly-{anomaly_count}']
                        anomaly_count = anomaly_count + 1
                    in_anomaly = False

            # Save only if an anomaly is detected at all
            if len(anomalies_windows.keys()) > 0:
                self.feeds_anomalies[feed.id] = anomalies_windows

        print(self.feeds_unpacked_anomalies)


    def find_matching_anomalies(self):

        num_correlated = 0
        processed_anomalies_pairs = set()
        for anomaly1 in self.feeds_unpacked_anomalies.keys():
            for anomaly2 in self.feeds_unpacked_anomalies.keys():
                
                check_entry = sorted([anomaly1, anomaly2])
                check_already_processed_key = '---'.join(check_entry)
                if check_already_processed_key in processed_anomalies_pairs:
                    continue
                else:
                    processed_anomalies_pairs.add(check_already_processed_key)
                if anomaly1 == anomaly2:
                    continue
                size_sig1 = self.feeds_unpacked_anomalies[anomaly1]['transitions_width']
                size_sig2 = self.feeds_unpacked_anomalies[anomaly2]['transitions_width']
                # Do not compare if difference in size is too big
                if abs(size_sig1 - size_sig2) > MAX_DIFF_SIGNATURES_SIZE:
                    continue
                
                # NOTE: Must roll the smaller signature on the bigger
                # let's say: only if the smaller signature is smaller by a maximum amount (not to test signatures of size 2 against those of size 15)

                corr_features_dict = {}

                for metric in self.features_watch_list:
                    signature1_metric_values = self.feeds_unpacked_anomalies[anomaly1]['signature'][metric].values.tolist()
                    signature2_metric_values = self.feeds_unpacked_anomalies[anomaly2]['signature'][metric].values.tolist()
                    
                    print(f'METRIC : {metric}')
                    corr_over_metric = self.correlate_lists_pair(signature1_metric_values, signature2_metric_values)
                    print(corr_over_metric)
                    corr_features_dict[metric] = corr_over_metric
                
                #print(corr_features_dict)

                corr_tot_max = np.max(list(corr_features_dict.values()))
                corr_tot_avg = np.mean(list(corr_features_dict.values()))

                #print(list(corr_features_dict.values()))
                #print(f'ITS MAX : {np.max(list(corr_features_dict.values()))}')

                #corr_features_dict = dict(sorted(corr_features_dict.items(), key=lambda item: item[1], reverse=True))
                anomaly1_info = {'device_id' : self.feeds_unpacked_anomalies[anomaly1]['device_id'], 'start' : self.feeds_unpacked_anomalies[anomaly1]['start'], 'end' : self.feeds_unpacked_anomalies[anomaly1]['end'], 'window_start' : self.feeds_unpacked_anomalies[anomaly1]['window_start'], 'window_end' : self.feeds_unpacked_anomalies[anomaly1]['window_end']}
                anomaly2_info = {'device_id' : self.feeds_unpacked_anomalies[anomaly2]['device_id'], 'start' : self.feeds_unpacked_anomalies[anomaly2]['start'], 'end' : self.feeds_unpacked_anomalies[anomaly2]['end'], 'window_start' : self.feeds_unpacked_anomalies[anomaly2]['window_start'], 'window_end' : self.feeds_unpacked_anomalies[anomaly2]['window_end']}
                self.pair_anomalies_correlation_log[num_correlated] = {'anomaly1' : anomaly1, 'anomaly1_info' : anomaly1_info, 'anomaly2' : anomaly2, 'anomaly2_info' : anomaly2_info, 'corr_max' : corr_tot_max, 'corr_avg' : corr_tot_avg, 'correlation_values' : corr_features_dict}

                #print(self.pair_anomalies_correlation_log[num_correlated])

                num_correlated = num_correlated + 1
                #print(f'Anomaly 1 : {anomaly1}')
                #print(f'Anomaly 2 : {anomaly2}')
        
        print(f'Correlation log : {len(self.pair_anomalies_correlation_log.values())}')


    def correlate_lists_pair(self, list1, list2):
        
        print(f'LIST 1: {list1}')
        print(f'LIST 2: {list2}')
        print('')
        
        equal_size = False
        if len(list1) > len(list2):
            wider_list = list1
            smaller_list = list2
        elif len(list2) > len(list1):
            wider_list = list2
            smaller_list = list1
        elif len(list1) == len(list2):
            equal_size = True
        
        
        if equal_size:
            cor = np.corrcoef(list1, list2)[0, 1]
            cor = np.nan_to_num(cor, copy=True, nan=0.0, posinf=None, neginf=None)
            return cor
        else:
            wider_sub_lists = []
            for i in range(len(wider_list) - len(smaller_list) + 1):
                wider_sub_lists.append(wider_list[i: i+len(smaller_list)])

            #print('')
            #print(f'smaller window list: {smaller_list}')
            #print(f'wider window list: {wider_list}')
            #print(f'wider window sub_lists: {wider_sub_lists}')
            #print('')
            corr_list = []
            for i, wider_sl in enumerate(wider_sub_lists):
                #print(smaller_list)
                #print(wider_sl)
                corr_val = np.corrcoef(smaller_list, wider_sl)[0, 1]
                corr_val = np.nan_to_num(corr_val, copy=True, nan=0.0, posinf=None, neginf=None)
                corr_list.append(corr_val)
            

            cor = np.max(corr_list)
            #print(f'correlation list: {corr_list}')
            #print(f'correlation max: {cor}')
            return cor
            
    def generate_report_from_matched_anomalies(self):
        now = datetime.now()
        date = now.strftime("%Y-%m-%d-%H-%M")
        self.better_anomalies_report.append(f'\n\n >>>>>>>>>>>> Report for MRT feeds of the {date} <<<<<<<<<<<<')
        
        tot_high_corr_matches = 0
        for key, entry in self.pair_anomalies_correlation_log.items():
            corr_max = entry['corr_max']
            corr_avg = entry['corr_avg']

            print(f'CORR AVG : {corr_avg}')
            print(f'CORR MAX : {corr_max}')

            combined_threshold_test = np.mean([corr_max, corr_avg])
            if not combined_threshold_test >= MRT_SIGNATURES_COMBINED_CORRELATION_THESHOLD:
                continue
            
            feed1 = '_'.join(entry['anomaly1'].split('_')[:-1])
            feed2 = '_'.join(entry['anomaly2'].split('_')[:-1])

            device1 = entry['anomaly1_info']['device_id']
            anomaly1_start_time = datetime.fromtimestamp(entry['anomaly1_info']['start'])
            anomaly1_end_time = datetime.fromtimestamp(entry['anomaly1_info']['end'])
            anomaly1_start_window = entry['anomaly1_info']['window_start']
            anomaly1_end_window = entry['anomaly1_info']['window_end']

            device2 = entry['anomaly2_info']['device_id']
            anomaly2_start_time = datetime.fromtimestamp(entry['anomaly2_info']['start'])
            anomaly2_end_time = datetime.fromtimestamp(entry['anomaly2_info']['end'])
            anomaly2_start_window = entry['anomaly2_info']['window_start']
            anomaly2_end_window = entry['anomaly2_info']['window_end']

            correlations = entry['correlation_values']
            
            report_entry_header = f'\n\n\n\n[ {tot_high_corr_matches} ]'
            header = ["Device ID", "Signature transitions window", "Signature time window", "MRT Feed"]
            table_entry1 = [device1, f'[{anomaly1_start_window} - {anomaly1_end_window}]', f'{anomaly1_start_time} - {anomaly1_end_time}', feed1]
            table_entry2 = [device2, f'[{anomaly2_start_window} - {anomaly2_end_window}]', f'{anomaly2_start_time} - {anomaly2_end_time}', feed2]
            entries = [table_entry1, table_entry2]
            table = tabulate(entries, headers=header)

            sorted_correlations = {k: v for k, v in sorted(correlations.items(), key=lambda item: item[1])}
            correlations_notes = f'\n\tCorrelation values for signature features:\n\t{sorted_correlations}'

            self.better_anomalies_report.append(report_entry_header)
            self.better_anomalies_report.append(table)
            self.better_anomalies_report.append(correlations_notes)

            tot_high_corr_matches = tot_high_corr_matches + 1

        for line in self.better_anomalies_report:
            print(line)



            

    ##################################################################################################################################
    # ROLLING WINDOW SIGNATURE CORRELATION
    ##################################################################################################################################
    """
        - For the MRTFeeds of the dashboard, split each in rolling sub-feeds of signature_transitions_window_size entries each
        - Build a 2D matrix with feed_#_window_#
        - compute average(/max?) correlation among selected features, for each pair of time windows from different feeds
        - Only compute triangular matrix
            - Util: https://stackoverflow.com/questions/34417685/melt-the-upper-triangular-matrix-of-a-pandas-dataframe
    """

    def get_mrt_feed_csv_rolling_windows(self, mrt_feed):
        #NOTE: mrt_feed.data is a pd dataframe
        # https://stackoverflow.com/questions/21303224/iterate-over-all-pairs-of-consecutive-items-in-a-list
        # Method 10 at https://towardsdatascience.com/23-efficient-ways-of-subsetting-a-pandas-dataframe-6264b8000a77
        # Rolling window: https://stackoverflow.com/questions/6822725/rolling-or-sliding-window-iterator
        
        sub_feeds = [] # Will be populated with all rolling signature_transitions_window_size feeds

        feed_rows_n = len(mrt_feed.data.index)
        if feed_rows_n < self.signature_transitions_window_size:
            raise ValueError(f">>> ERROR: MRT feed {mrt_feed.id} has less transition entries than the rolling window and cannot be compared. Aborting monitoring.")    

        print(f'Feed length: {feed_rows_n}')
        for i in range(feed_rows_n - self.signature_transitions_window_size + 1):
            sub_feeds.append(mrt_feed.data.iloc[mrt_feed.data.index[i: i+self.signature_transitions_window_size]])

        return sub_feeds

    def generate_feeds_signatures_set(self):
        """
        - Take each csv feed
        - divide in sub-csvs acc to time_window, label precisely
        - build a dataframe w/ index-columns all windows pointers
        - set triangular (default cell values/other smarter smethods)
        """
        self.feeds_signatures_set = {}
        for mrt_feed in list(self.feeds.values()):
            for idx, sf in enumerate(self.get_mrt_feed_csv_rolling_windows(mrt_feed)):
                sf.rename(columns={'Unnamed: 0' : 'window'}, inplace=True)
                self.feeds_signatures_set[f'{mrt_feed.id}{MRT_WINDOW_SIGNATURE_DF_NAME_TAG}{idx}'] = sf
                #print(self.feeds_signatures_set[f'{mrt_feed.id}{MRT_WINDOW_SIGNATURE_DF_NAME_TAG}{idx}'].head())
        
    
    def generate_feeds_signatures_comparison_matrix(self):
        # Comparison matrix with same index and columns for pairwise correlation over all possible sets
        self.feeds_signatures_comparison_matrix = pd.DataFrame(MRT_SIGNATURES_COMPARISON_MATRIX_PLACEHOLDER, index=self.feeds_signatures_set.keys(), columns=self.feeds_signatures_set.keys())
        upper_triangular_mask = np.triu(np.ones(self.feeds_signatures_comparison_matrix.shape)).astype(bool) # https://stackoverflow.com/questions/34417685/melt-the-upper-triangular-matrix-of-a-pandas-dataframe
        self.feeds_signatures_comparison_matrix = self.feeds_signatures_comparison_matrix.where(upper_triangular_mask)

    def populate_feeds_signatures_comparison_matrix_over_watch_features_correlation(self):
        """
            - Mind only upper triangular to avoid replicated correlation checks
                - https://stackoverflow.com/questions/36375939/how-to-get-row-column-indices-of-all-non-nan-items-in-pandas-dataframe
            - Select pairs of signatures from signature comparison matrix index and columns
            - Check that pair is not from same feed (feed.id)
        """
        # TODO: Find an efficient way to iterate over relevant coordinates. Tried some but couldn't find a go-to approach.
        for sig_col_id in self.feeds_signatures_comparison_matrix.columns:
            for sig_row_id in self.feeds_signatures_comparison_matrix.index:
                #print(f'\n\nITERATING ANOMALIES SIGNATURES AT \n \tCOL: {sig_col_id}\n \tROW: {sig_row_id}\n')
                # Check not same mrt feed of origin
                sig_row_origin_feed = sig_row_id.split(MRT_WINDOW_SIGNATURE_DF_NAME_TAG, 1)[0]
                sig_col_origin_feed = sig_col_id.split(MRT_WINDOW_SIGNATURE_DF_NAME_TAG, 1)[0]
                #print(f'\n\nORIGINS \n \tCOL: {sig_col_origin_feed}\n \tROW: {sig_row_origin_feed}\n')
                # If same origin, set value to NaN
                if sig_row_origin_feed == sig_col_origin_feed:
                    self.feeds_signatures_comparison_matrix.at[sig_row_id, sig_col_id] = np.nan
                else:
                    # If different, check that we're not in lower triangular (repeted checks), and that the value has not been computed yet (MRT_SIGNATURES_COMPARISON_MATRIX_PLACEHOLDER in Constants)
                    val = self.feeds_signatures_comparison_matrix.loc[sig_row_id, sig_col_id]
                    if not np.isnan(val) and val == MRT_SIGNATURES_COMPARISON_MATRIX_PLACEHOLDER:
                        corr_over_watch_features = {}
                        # Here, compute the correlations for each metric in the watchlist across the two fluctuation windows
                        for metric in self.features_watch_list:
                            metric_corr = self.corr_signatures_pair_monodim_metric(metric, sig_row_id, sig_col_id)
                            corr_over_watch_features[metric] = metric_corr
                        # get the max and average of the correlations
                        avg_corr_over_watch_features = np.mean(list(corr_over_watch_features.values()))
                        max_corr_over_watch_features = np.max(list(corr_over_watch_features.values()))

                        corr_over_watch_features = dict(sorted(corr_over_watch_features.items(), key=lambda item: item[1], reverse=True))
                        
                        val = 0
                        if ALERT_METHOD == 'max':
                            val = max_corr_over_watch_features
                        elif ALERT_METHOD == 'avg':
                            val = avg_corr_over_watch_features
                        self.feeds_signatures_comparison_matrix.at[sig_row_id, sig_col_id] = val

                        #print(f'CORRELATION VALUE OBTAINED: \t{avg_corr_over_watch_features}\n\n')
                        signatures_correlation_dictionary_key = str(sig_row_id + FEEDS_SIGNATURES_CORRELATION_DICTIONARIES_KEY_LINK + sig_col_id)
                        self.feeds_signatures_correlation_dictionary[signatures_correlation_dictionary_key] = {'avg' : avg_corr_over_watch_features, 'max' : max_corr_over_watch_features, 'metrics' : corr_over_watch_features}
                        #print(f'Signatures correlation key: \n>>>{signatures_correlation_dictionary_key}\n')
        #print(self.feeds_signatures_comparison_matrix)

    def generate_detected_anomalies_report(self, save_dir=MY_SAVE_PATH_DEFAULT, report_name='recorded_anomalies.txt'):
        self.anomalies_report.append('\n\n*~*~*~*~*~*~*~* Anomalies recorded for each MRT feed submitted *~*~*~*~*~*~*~*\n\n')
        for entry, val in self.feeds_anomalies.items():
            print(f'ENTRY: {entry}')
            print(val)
            feed_id = entry
            report_entry = f'{feed_id} :\n'
            # Iterate over time windows of anomalies
            for k, e in val.items():
                start = datetime.fromtimestamp(e['start']).time()
                end = datetime.fromtimestamp(e['end']).time()
                wstart = e['window_start']
                wend = e['window_end']
                date = datetime.fromtimestamp(e['end']).date()
                report_entry = report_entry + f'\t between: {start} and {end} on the {date} \t --- \t time windows [ {wstart} , {wend} ]\n'
            report_entry = report_entry + '\n'
            print(report_entry)
            self.anomalies_report.append(report_entry)

        
    def generate_signatures_correlation_report(self, save_dir=MY_SAVE_PATH_DEFAULT, report_name='matching_anomalies_report.txt'):
        
        self.signatures_correlation_report.append('\n\n*~*~*~*~*~*~*~* Similar anomalies observed for the selected devices *~*~*~*~*~*~*~*\n\n')
        corr_counter = 0
        
        # To collect all matching windows per device couples to produce aggregated alerts
        device_pairs_anomaly_pinpointer = {}
        for sig_col_id in self.feeds_signatures_comparison_matrix.columns:
            for sig_row_id in self.feeds_signatures_comparison_matrix.index:
                k1 = sig_row_id.split(MRT_WINDOW_SIGNATURE_DF_NAME_TAG, 1)[0]
                k2 = sig_col_id.split(MRT_WINDOW_SIGNATURE_DF_NAME_TAG, 1)[0]
                if (k1 != k2):
                    device_pairs_anomaly_pinpointer[k1 + FEEDS_SIGNATURES_CORRELATION_DICTIONARIES_KEY_LINK + k2] = []

        for sig_col_id in self.feeds_signatures_comparison_matrix.columns:
            for sig_row_id in self.feeds_signatures_comparison_matrix.index:
                signatures_correlation = self.feeds_signatures_comparison_matrix.loc[sig_row_id, sig_col_id]
                # Again, skip non-relevant cells
                if not np.isnan(signatures_correlation) and not (signatures_correlation == MRT_SIGNATURES_COMPARISON_MATRIX_PLACEHOLDER):

                    corr_dictionary_entry = self.feeds_signatures_correlation_dictionary[sig_row_id + FEEDS_SIGNATURES_CORRELATION_DICTIONARIES_KEY_LINK + sig_col_id]
                    features_correlation_list = corr_dictionary_entry['metrics']
                    
                    sig_row_origin_feed = sig_row_id.split(MRT_WINDOW_SIGNATURE_DF_NAME_TAG, 1)[0]
                    sig_col_origin_feed = sig_col_id.split(MRT_WINDOW_SIGNATURE_DF_NAME_TAG, 1)[0]
                    
                    if signatures_correlation > MRT_SIGNATURES_CORRELATION_THRESHOLD:
                        
                        # Device ids
                        device_row_sig = self.feeds[sig_row_origin_feed].metadata['device_id']
                        device_col_sig = self.feeds[sig_col_origin_feed].metadata['device_id']
                        
                        # Anomaly/attack time windows
                        row_signature_start_time = datetime.fromtimestamp(self.feeds_signatures_set[sig_row_id]['ch1_t_start'].iloc[0])
                        row_signature_end_time = datetime.fromtimestamp(self.feeds_signatures_set[sig_row_id]['ch2_t_end'].iloc[-1])
                        
                        row_signature_start_window = self.feeds_signatures_set[sig_row_id]['window'].iloc[0]
                        row_signature_end_window = self.feeds_signatures_set[sig_row_id]['window'].iloc[-1]

                        col_signature_start_time = datetime.fromtimestamp(self.feeds_signatures_set[sig_col_id]['ch1_t_start'].iloc[0])
                        col_signature_end_time = datetime.fromtimestamp(self.feeds_signatures_set[sig_col_id]['ch2_t_end'].iloc[-1])

                        col_signature_start_window = self.feeds_signatures_set[sig_col_id]['window'].iloc[0]
                        col_signature_end_window = self.feeds_signatures_set[sig_col_id]['window'].iloc[-1]

                        device_pairs_anomaly_pinpointer[sig_row_origin_feed + FEEDS_SIGNATURES_CORRELATION_DICTIONARIES_KEY_LINK + sig_col_origin_feed].append((row_signature_start_window, row_signature_end_window, col_signature_start_window, col_signature_end_window))
                        # Rerport entry
                        report_entry = f'\n\n[{corr_counter}] Similar anomalous activity was recorded for the following devices at these times:\n \
        * {device_row_sig} - between: {row_signature_start_time} and {row_signature_end_time} \t --- \t time windows [ {row_signature_start_window} , {row_signature_end_window} ]\n \
        * {device_col_sig} - between: {col_signature_start_time} and {col_signature_end_time} \t --- \t time windows [ {col_signature_start_window} , {col_signature_end_window} ]\n \
    Max correlation of watchlist features: {signatures_correlation} ) \n\n \
    Features and correlation: {features_correlation_list}. \n\n'

                        self.signatures_correlation_report.append(report_entry)
                        corr_counter = corr_counter+1
        
        self.signatures_correlation_report.append(f'Total of windows with similar anomalies observed: {corr_counter}.\n\n')

        print(f'FEATURES CORR LIST :{features_correlation_list}')

        # To take the margins of continuously-matching consecutive sliding windows
        device_pairs_agglomerated_match_windows = {}
        for devices_key, matches in device_pairs_anomaly_pinpointer.items():
            matches = sorted(matches, key=lambda x: x[0])
            aggl_windows = {}
            device_pairs_agglomerated_match_windows[devices_key] = aggl_windows
            
            aggl_windows_pre_dict = self.allgomerate_windows_list(matches)
            aggl_windows_pre_list = []
            for list in aggl_windows_pre_dict.values():
                aggl_windows_pre_list.append(list)

            #print(aggl_windows_pre_list)
            aggl_windows = self.allgomerate_windows_list(aggl_windows_pre_list)


            device_pairs_agglomerated_match_windows[devices_key] = aggl_windows
        
        self.signatures_correlation_report.append('\n\n*~*~*~*~*~*~*~* COMPACT COMMON ANOMALIES VIEW *~*~*~*~*~*~*~*\n\n')

        total_common_aggl_anomalies_counter = 0
        # Iterate over agglomerated windows. Get data from dictionary keys pointing to feeds rows, print entries
        for feeds_key, anomalies_windows in device_pairs_agglomerated_match_windows.items():
            
            feed1, feed2 = self.get_feeds_ids_from_pair_feeds_dict_key(feeds_key)
            device1_id = self.feeds[feed1].metadata['device_id']
            device2_id = self.feeds[feed2].metadata['device_id']

            for windows in anomalies_windows.values():
                # Get feed entry via iloc using the window values, get timings data
                if windows is not None:
                    sig1_row_start = windows[0]
                    sig1_row_end = windows[1]
                    sig2_row_start = windows[2]
                    sig2_row_end = windows[3]


                    feed1_row_start_time = datetime.fromtimestamp(self.feeds[feed1].data['ch1_t_start'].iloc[sig1_row_start])
                    feed1_row_end_time = datetime.fromtimestamp(self.feeds[feed1].data['ch2_t_end'].iloc[sig1_row_end])

                    feed2_row_start_time = datetime.fromtimestamp(self.feeds[feed2].data['ch1_t_start'].iloc[sig2_row_start])
                    feed2_row_end_time = datetime.fromtimestamp(self.feeds[feed2].data['ch2_t_end'].iloc[sig2_row_end])

                    report_entry_1 = f'\t[{total_common_aggl_anomalies_counter}] \n\t{device1_id : <32} : {feed1_row_start_time} - {feed1_row_end_time} \t --- \t [{sig1_row_start} - {sig1_row_end}] '
                    report_entry_2 = f'\t{device2_id : <32} : {feed2_row_start_time} - {feed2_row_end_time} \t --- \t [{sig2_row_start} - {sig2_row_end}]\n'

                    self.signatures_correlation_report.append(report_entry_1)
                    self.signatures_correlation_report.append(report_entry_2)
                    total_common_aggl_anomalies_counter = total_common_aggl_anomalies_counter + 1

        self.signatures_correlation_report.append(f'\nTotal of agglomerated windows with similar anomalies observed: {total_common_aggl_anomalies_counter}.\n\n')

        for entry in self.signatures_correlation_report:
            print(entry)

        #print(f'ALL AGGLOMERATED WINDOWS: {device_pairs_agglomerated_match_windows}')
        #print(f'AGGL ANOMALIES PINPOINTER: {device_pairs_anomaly_pinpointer}')
        #self.print_dict(device_pairs_anomaly_pinpointer)
        #self.print_dict(device_pairs_agglomerated_match_windows)

        # Output plots
        for feature in self.features_watch_list:
            self.plot_monodim_metric2(feature)


    def allgomerate_windows_list(self, windows_list) -> dict:
        last_s1 = -1
        last_e1 = -1
        last_s2 = -1
        last_e2 = -1
        agglomerated = None
        ongoing = False

        aggl_windows = {}
        aggregations = 0
        for windows in windows_list:
                s1 = windows[0]
                e1 = windows[1]
                s2 = windows[2]
                e2 = windows[3]
                
                #print(f'NEW ITERATION, ongoing = {ongoing}')
                if not ongoing:
                    agglomerated = [s1, e1, s2, e2]

                    last_s1 = s1
                    last_e1 = e1
                    last_s2 = s2
                    last_e2 = e2

                    #print(f'NOT ONGOING: agglomerated = {agglomerated}')
                    aggl_windows[aggregations] = agglomerated
                    ongoing = True

                elif ongoing:
                    print(f'ITERATION, ONGOING AGGL WINDOWS, LASTS = {last_s1}, {last_e1}, {last_s2}, {last_e2}')
                    print(f'ITERATION, ONGOING AGGL WINDOWS, CURRN = {s1}, {e1}, {s2}, {e2}')
                    print('')
                    
                    single_slide_dev1 = bool(s1 == last_s1 + 1 and e1 == last_e1 + 1)
                    print(bool(s1 == last_s1 + 1))
                    single_slide_dev2 = bool(s2 == last_s2 + 1 and e2 == last_e2 + 1)
                    remained_same_dev1 = bool(s1 == last_s1 and e1 == last_e1)
                    remained_same_dev2 = bool(s2 == last_s2 and e2 == last_e2)
                    print(f'ONGOING: agglomerated = {agglomerated}')
                    print(f'ITERATION, ONGOING AGGL WINDOWS, single_slide_dev1 = {single_slide_dev1}')
                    print(f'ITERATION, ONGOING AGGL WINDOWS, single_slide_dev2 = {single_slide_dev2}')
                    print(f'ITERATION, ONGOING AGGL WINDOWS, remained_same_dev1 = {remained_same_dev1}')
                    print(f'ITERATION, ONGOING AGGL WINDOWS, remained_same_dev2 = {remained_same_dev2}')
                    
                    if single_slide_dev1 and single_slide_dev2:
                        agglomerated[1] = e1
                        agglomerated[3] = e2
                        
                        last_s1 = s1
                        last_e1 = e1
                        last_s2 = s2
                        last_e2 = e2
                        #print(f'ONGOING AND SINGLE SLID: agglomerated = {agglomerated}')
                        # Update windows, overwrite last
                        aggl_windows[aggregations] = agglomerated
                    elif remained_same_dev1 and single_slide_dev2:
                        print(f'REMAINED SAME SINGLE SLIDE TRIGGERED')
                        agglomerated[3] = e2
                        last_s1 = s1
                        last_e1 = e1
                        last_s2 = s2
                        last_e2 = e2
                        aggl_windows[aggregations] = agglomerated
                    elif single_slide_dev1 and remained_same_dev2:
                        last_s1 = s1
                        last_e1 = e1
                        last_s2 = s2
                        last_e2 = e2
                        aggl_windows[aggregations] = agglomerated
                    else:
                        print('<<<<< DONE ONGOING')
                        #print(f'DONE ONGOING. AGGL WINDOWS: {aggl_windows}')
                        ongoing = False
                        aggregations = aggregations + 1
        return aggl_windows

    


    def print_dict(self, dict):
        for key, val in dict.items():
            print(f'{key}')
            print(f'\t{val}')

    
    def generate_report(self, report_name='report.txt'):
        self.generate_detected_anomalies_report()
        self.generate_report_from_matched_anomalies()
        
        # Output plots
        for feature in self.features_watch_list:
            self.plot_monodim_metric2(feature)

        now = datetime.now()
        date = now.strftime("%Y-%m-%d-%H-%M")
        save_fullpath = MY_SAVE_PATH_DEFAULT + date + '_' + report_name
        with open(save_fullpath, 'w') as output:
            for line in self.anomalies_report:
                output.write(line)
            for line in self.better_anomalies_report:
                output.write(line)
        print(f'>>> Report saved to {save_fullpath}.')

        

    ##################################################################################################################################
    # VISUALIZATION
    ##################################################################################################################################
    """
        *****************************************************************************************************
        # NOTE: It can be expected that the MRT feeds do not keep at the same time a huge number of entries.
                It could be therefore possible to plot these info in a resonably non-cluttered chart 
        *****************************************************************************************************
        MONO-DIMENSIONAL FEATURES:
            For each MRT feed, plot the pd series of the feature in one line graph. There will be as many lines as MRT feeds
    """

    def plot_monodim_metric(self, metric, save_dir=MY_SAVE_PATH_DEFAULT, show=False):
        if not self.metric_exists(metric):
            raise ValueError(f'>>> ERROR: Invalid metric queried on MRT feeds: [ {metric} ].')
        self.check_metric_monodim(metric)
        palette = sns.color_palette(None, len(list(self.feeds.items())))
        f_plt = []
        l_plt = []
        
        # TODO: Remove corr matrix sns plot
        fig, axs = plt.subplots(2,1, gridspec_kw={'height_ratios': [3, 1]}, constrained_layout=True)
        fig.set_figheight(5)
        fig.set_figwidth(12)
        
        #plt.figure(figsize=(12, 7))
        #fig.suptitle(f'All feeds, monodimensonal metric: {metric}')
        for i, feed in enumerate(list(self.feeds.values())):
            f, = axs[0].plot(feed.data[metric], color=palette[i], label=feed.id) # https://stackoverflow.com/questions/11983024/matplotlib-legends-not-working
            l_plt.append(anonymise_string(feed.id.split('_')[LABEL_OFFSET]))
            f_plt.append(f)

        axs[0].legend(f_plt, l_plt, loc='upper left')
        axs[0].set_xlabel('Transition entry')
        axs[0].set_ylabel(metric)
        axs[0].tick_params(axis='y', labelrotation=45)

        cor = self.corr_monodim_metric(metric)
        sns.heatmap(cor, ax=axs[1], annot=True, fmt='.3f', cmap=plt.cm.Blues, vmin=-1, vmax=1, yticklabels=True, xticklabels=True)
        axs[1].tick_params(axis='x', labelrotation=10)
        plt.savefig(MY_SAVE_PATH_DEFAULT + metric + '.pdf')
        
        if show:
            plt.show()
        
        print(f'>>> Output saved to {save_dir}.')

    def plot_monodim_metric2(self, metric, save_dir=MY_SAVE_PATH_DEFAULT, show=False):
        if not self.metric_exists(metric):
            raise ValueError(f'>>> ERROR: Invalid metric queried on MRT feeds: [ {metric} ].')
        self.check_metric_monodim(metric)
        palette = sns.color_palette(None, len(list(self.feeds.items())))
        f_plt = []
        l_plt = []
        
        n_lines = len(list(self.feeds.values()))

        # TODO: Remove corr matrix sns plot
        fig, axs = plt.subplots(n_lines,1, constrained_layout=True, sharex=True, sharey=True)
        fig.set_figheight(6)
        fig.set_figwidth(12)
        
        #plt.figure(figsize=(12, 7))
        #fig.suptitle(f'All feeds, monodimensonal metric: {metric}')
        for i, feed in enumerate(list(self.feeds.values())):
            f, = axs[i].plot(feed.data[metric], color=palette[i], label=feed.id) # https://stackoverflow.com/questions/11983024/matplotlib-legends-not-working
            tag = anonymise_string(feed.id.split('_')[LABEL_OFFSET])
            axs[i].legend([f], [tag], loc='upper left')
            axs[i].spines['top'].set_visible(False)
            axs[i].spines['right'].set_visible(False)
            axs[i].spines['left'].set_visible(False)
            axs[i].grid(axis='y')
        #plt.set_xlabel('Transition entry')
        #plt.tick_params(axis='y', labelrotation=45)
        #plt.set_ylabel(metric)
        plt.box(False)
        plt.savefig(MY_SAVE_PATH_DEFAULT + metric + '.pdf')
        
        if show:
            plt.show()
        
        print(f'>>> Output saved to {save_dir}.')


    def print_feeds(self):
        for info in self.feeds:
            print(info.metadata)
            print(info.data)


    ##################################################################################################################################
    # CORRELATION
    ##################################################################################################################################
    """
        TODO:
            A likely outcome is an ensemble of comparison matrices over all MRT Feeds of the object.
            
            Monodimensional metric:
                - One matrix is produced per each feature, listing pairwise correlation
            
            Multidimensional metric:
            ************************************************************************************************************************
            NOTE: Try investigating Canonical Correlation Analysis: https://towardsdatascience.com/canonical-correlation-analysis-b1a38847219d
            ************************************************************************************************************************
            Easy method:
                - How each metric dimension correlate -> n = dim correlation values FOR EACH PAIRWISE CORRELATION
                    > One matrix for average correlation across all sub-column
    """

    def corr_monodim_metric(self, metric):
        """ Generates dataframe with
            - MRTFeed IDs as columns
            - MRTFeed.#[metric][row_i] as rows
            Then applies corr() on dataset columns

            **************************
            M_monodim_metric[i, j] = corr(
                feed_i[metric],
                feed_j[metric]
            )
            **************************
        """    
        self.check_metric_monodim(metric)
        #NOTE: REAL CONSTRUCTOR: {feed.id : feed.data[metric].values.tolist() for feed in self.feeds}
        #      Used to test: {feed.id + str(i) : feed.data[metric].values.tolist() for i, feed in enumerate(self.feeds)}
        per_metric_dict = {anonymise_string(feed.id.split('_')[LABEL_OFFSET]) : feed.data[metric].values.tolist() for feed in list(self.feeds.values())}
        per_metric_feeds_df = pd.DataFrame.from_dict(per_metric_dict)
        cor = per_metric_feeds_df.corr().fillna(0)
        return cor

    def corr_signatures_pair_monodim_metric(self, metric, sig1_id, sig2_id):
        pair_signatures_metric_dict = {
            sig1_id+f'_{metric}' : self.feeds_signatures_set[sig1_id][metric].values.tolist(),
            sig2_id+f'_{metric}' : self.feeds_signatures_set[sig2_id][metric].values.tolist()
            }
        #print(pair_signatures_metric_dict)
        per_metric_feeds_df = pd.DataFrame.from_dict(pair_signatures_metric_dict)
        cor = per_metric_feeds_df.corr().fillna(0)
        correlation = cor.iloc[0, -1]
        return correlation

    def corr_multidim_metric(self, metric):

        self.check_metric_multidim(metric)
                                        # Feed-specific dataframe of multidim metric 
        metric_dfs_dict = {anonymise_string(feed.id.split('_')[LABEL_OFFSET]) : self.get_df_of_multidim_metric(feed, metric) for feed in self.feeds}
        #print(metric_dfs_dict)

        # Records lists each correlation value per dimension of the metric, over pairwise MRT feeds
        corr_matrix_all_values = pd.DataFrame(columns=metric_dfs_dict.keys(), index=metric_dfs_dict.keys()) 
        # Records the AVERAGE VALUE across each correlation value per each dimension of the metric, over pairwise MRT feeds
        corr_matrix_averages = pd.DataFrame(columns=metric_dfs_dict.keys(), index=metric_dfs_dict.keys())
        
        # For each dataframe pair
        #   For each dimension
        #       Correlate pairwise
        #       Put correlation to list
        #       Save correlation average over list
        dfs_pairs = list(combinations(metric_dfs_dict.keys(), 2)) # dfs ids
        for pair in dfs_pairs:
            corr_vals = np.array([])
            for c in metric_dfs_dict[pair[0]].columns: # Iterate over dimensions
                df1 = metric_dfs_dict[pair[0]]
                df2 = metric_dfs_dict[pair[1]]
                val = df1[c].corr(df2[c]) # Pearson is symmetric
                corr_vals = np.append(corr_vals, val)
            nan_mask = np.isnan(corr_vals)
            corr_vals[nan_mask] = 0
            #corr_vals = np.delete(corr_vals, nan_mask)
            corr_vals_avg = np.average(corr_vals).item()
            #print(corr_vals)
            #print(corr_vals_avg)

            #NOTE NOTE NOTE that the matrices are Symmetric, so only upper triangular is populated
            corr_matrix_all_values.loc[pair[0], pair[1]] = corr_vals
            corr_matrix_averages.loc[pair[0], pair[1]] = corr_vals_avg

        corr_matrix_all_values.fillna(0, inplace=True)
        corr_matrix_averages.fillna(0, inplace=True)

        return corr_matrix_averages, corr_matrix_all_values

    def total_avg_corr(self):
        """Computes correlation over all contributing features, returns descriptors"""
        monodim_features_correlation_arrays = []
        multidim_features_correlation_arrays = []
        for col in self.total_corr_significant_features:
            if self.is_monodim_metric(col):
                cor_matrix = self.corr_monodim_metric(col)
                cor_matrix = cor_matrix.to_numpy() # To numpy to use upper triangular selection
                cor_list = list(cor_matrix[np.triu_indices_from(cor_matrix, k=1)]) #np.triu(cor_matrix, k=1)
                monodim_features_correlation_arrays.append(cor_list)
                #print(col)
                #print(cor_list)
            elif self.is_multidim_metric(col):
                cor_matrix, _ = self.corr_multidim_metric(col)
                cor_matrix = cor_matrix.to_numpy()
                cor_list = list(cor_matrix[np.triu_indices_from(cor_matrix, k=1)]) #np.triu(cor_matrix, k=1)
                multidim_features_correlation_arrays.append(cor_list)
            else:
                raise ValueError(f'>>> ERROR: Unable to parse column value {col}.')

        monodim_corrs_flat = [val for sublist in monodim_features_correlation_arrays for val in sublist]
        multidim_corrs_flat = [val for sublist in multidim_features_correlation_arrays for val in sublist]

        avg_corr_monodim = np.average(monodim_corrs_flat).item()
        std_corr_monodim = np.std(monodim_corrs_flat).item()
        corr_monodim_min = np.min(monodim_corrs_flat).item()
        corr_monodim_max = np.max(monodim_corrs_flat).item()

        avg_corr_multidim = np.average(multidim_corrs_flat).item()
        std_corr_multidim = np.std(multidim_corrs_flat).item()
        corr_multidim_min = np.min(multidim_corrs_flat).item()
        corr_multidim_max = np.max(multidim_corrs_flat).item()

        print()
        print()
        print('~~~~~~ Mono-dimensional features results ~~~~~~')
        print(f'>>> Average correlation :\t{avg_corr_monodim}')
        print(f'>>> Std correlation :\t\t{std_corr_monodim}')
        print(f'>>> Minimum value :\t\t{corr_monodim_min}')
        print(f'>>> Maximum value :\t\t{corr_monodim_max}')
        print()
        print('~~~~~~ Multi-dimensional features results ~~~~~~')
        print(f'>>> Average correlation :\t{avg_corr_multidim}')
        print(f'>>> Std correlation :\t\t{std_corr_multidim}')
        print(f'>>> Minimum value :\t\t{corr_multidim_min}')
        print(f'>>> Maximum value :\t\t{corr_multidim_max}')
        print()
        print()

        with open(MY_SAVE_PATH_DEFAULT + 'all_avgs_summary.txt', 'w') as txt:
            txt.write('~~~~~~ Mono-dimensional features results ~~~~~~\n')
            txt.write(f'>>> Average correlation :\t{avg_corr_monodim}\n')
            txt.write(f'>>> Std correlation :\t\t{std_corr_monodim}\n')
            txt.write(f'>>> Minimum value :\t\t{corr_monodim_min}\n')
            txt.write(f'>>> Maximum value :\t\t{corr_monodim_max}\n')
            txt.write('\n')
            txt.write('~~~~~~ Multi-dimensional features results ~~~~~~\n')
            txt.write(f'>>> Average correlation :\t{avg_corr_multidim}\n')
            txt.write(f'>>> Std correlation :\t\t{std_corr_multidim}\n')
            txt.write(f'>>> Minimum value :\t\t{corr_multidim_min}\n')
            txt.write(f'>>> Maximum value :\t\t{corr_multidim_max}\n')
            txt.write('\n')

        return avg_corr_monodim, avg_corr_multidim


    ##################################################################################################
    # UTILITY
    ##################################################################################################

    def get_feeds_ids_from_pair_feeds_dict_key(self, key):
        feed1 = key.split(FEEDS_SIGNATURES_CORRELATION_DICTIONARIES_KEY_LINK)[0]
        feed2 = key.split(FEEDS_SIGNATURES_CORRELATION_DICTIONARIES_KEY_LINK)[1]

        return feed1, feed2

    def metric_exists(self, metric):
        try:
            # TODO: Test
            probe = list(self.feeds.values())[0].data[metric].iloc[0]
            return True
        except Exception as e:
            return False

    def align_feeds(self):
        """
        OBSOLETE
        Normalizes feeds lists according to number of transitions recorded, and timings
        """
        min_transitions = min([f.len for f in self.feeds])

        avg_feed_duration = np.average([f.duration for f in self.feeds]).item()
        min_start = min([f.starts for f in self.feeds])
        max_start = max([f.starts for f in self.feeds])
        min_end = min([f.ends for f in self.feeds])
        max_end = max([f.ends for f in self.feeds])

        start_offset = max_start - min_start
        end_offset = max_end - min_end

        tolerance = avg_feed_duration * MRTFEEDS_TIME_OFFSET_TOLERANCE
        print(f'>>> DEBUG: Avg duration: {avg_feed_duration}')
        print(f'>>> DEBUG: Start offset: {start_offset}')
        print(f'>>> DEBUG: End offset: {end_offset}')
        print(f'>>> DEBUG: Tolerance: {tolerance}')
        # Abort if start and end intervals are too much offset with respect to average captured time
        """TODO NOTE TODO RE SET TOLERANCE CHECKS"""
        #if start_offset > tolerance or end_offset > tolerance:
        #    raise ValueError(f'>>> ERROR: Feeds to process appear to be too much offset with respect to the transition timings. Aborting operations.')

        cropped = False
        for i, feed in enumerate(self.feeds):
            if feed.len > min_transitions: # Cannot correlate MRT feeds with different number of transition entries
                self.feeds[i].data = feed.data.truncate(after=min_transitions)
                cropped = True
        if cropped:
            print(f'>>> WARNING: MRT Feeds in MRTADashboard have been cropped to [ {min_transitions} ] to be of equal size.')
    
    def is_monodim_metric(self, metric):
        probe = list(self.feeds.values())[0].data[metric].iloc[0]
        try:
            a = ast.literal_eval(probe)
        except Exception as e:
            #print(e)
            return True
        return False
    def is_multidim_metric(self, metric):
        probe = list(self.feeds.values())[0].data[metric].iloc[0]
        try:
            a = ast.literal_eval(probe)
        except Exception as e:
            #print(e)
            return False
        return True
    
    def check_metric_monodim(self, metric):
        if not self.is_monodim_metric(metric):
            raise ValueError(f'>>> ERROR: Trying MONOdimensional function on MULTIdimensional feature {metric}. Exiting.')

    def check_metric_multidim(self, metric):
        if not self.is_multidim_metric(metric):
            raise ValueError(f'>>> ERROR: Trying MULTIdimensional plotting on MONOidimensional feature {metric}. Exiting.')

    def get_df_of_multidim_metric(self, feed, metric):
        """Returns a dataframe of 
            - columns = series of transition entries from df
            - rows = dimensions of metric"""
        pts = [e for e in feed.data[metric]]
        points = pts
        try:
            points = [ast.literal_eval(p) for p in pts] # NOTE Number list of points per entry
        except Exception as e:
            print(e)
            raise ValueError('>>> ERROR: Exception in parsing multi-dimensional points. Make sure to be passing a multi-dimensional column. Exiting.')
        
        point_len = len(points[0])
        cols = ['dim_'+str(i) for i in range(point_len)]
        # Selecetd multidimensional metric transformed to dataframe
        df = pd.DataFrame(data=points, columns=cols)

        # Ref: https://pandas.pydata.org/docs/reference/api/pandas.plotting.parallel_coordinates.html
        df_T = df.T # Transposed metric dataframe
        #df_T.rename({i : 'tr_'+str(i) for i in df_T.columns}, axis='columns', inplace=True)
        #df_T['Index'] = df_T.index

        return df_T



if __name__ == '__main__':
    """
    MRTADashboard.py
    argv1 : 
        - 'demo' backdoor for demo run
        - dim: 'monodim', 'multi', 'mono'. 'monodim' is backdoor for higher-correlation features
    """

    print('>>> Testing MRTADashboard!')

    """
        NOTE: Test different setups from available configs, or define new ones with configs
    """
    config_file = 'nonrandomized_attacks_preliminary.json'
    with open('/Users/lucamrgs/mudscope/configs/monitor_configs/' + config_file) as mrtf_conf:
        mrtf_data = json.load(mrtf_conf)
    mrtf_data_list = mrtf_data['mrtfeeds']
    monitor_features = mrtf_data['features_watch']
    signature_transitions_window_size = mrtf_data['transition_window']
        
    mrt_feeds_list = []
    for l in mrtf_data_list:
        mrt_feeds_list.append(MRTFeed(l['device_metadata'], l['csv_mrt_feed']))

    mrta_test = MRTADashboard()
    mrta_test.setup(mrt_feeds_list, monitor_features, signature_transitions_window_size)

    #print(f'>>> DEBUG: Test mrt_csv_rolling_windows')
    #subfeeds_test = mrta_test.get_mrt_feed_csv_rolling_windows(mrta_test.feeds[0])
    #for f in subfeeds_test:
    #    print(f)

    mrta_test.generate_feeds_signatures_set()
    print(f'############################################################################################################')
    print(f'>>> DEBUG: Test generated feeds signatures set')
    #print(mrta_test.feeds_signatures_set)
    
    mrta_test.generate_feeds_signatures_comparison_matrix()
    print(f'############################################################################################################')
    print(f'>>> DEBUG: Test generated signatures comparison matrix')
    #print(mrta_test.feeds_signatures_comparison_matrix)

    mrta_test.populate_feeds_signatures_comparison_matrix_over_watch_features_correlation()
    print(f'############################################################################################################')
    print(f'>>> DEBUG: Test generated signatures comparison matrix after population')
    #print(mrta_test.feeds_signatures_comparison_matrix.to_string())
    #print(mrta_test.feeds_signatures_correlation_dictionary)

    print(f'############################################################################################################')
    print(f'>>> DEBUG: Test generated signatures correlation report')
    mrta_test.generate_signatures_correlation_report()


    # Below code is debug for testing
    if sys.argv[1] == 'demo':
        try:
            monitor_features = sys.argv[2].split(',')
        except Exception as e:
            raise ValueError(f'>>> ERROR: Testing MRTDashboard code without monitor features specified. Exiting.')
        
        ut_csv_path = '/Users/lucamrgs/mudscope/outputs/ut-tplink-demo/ut-tplink-demo_mrt_transitions_dfs'
        tue_csv_path = '/Users/lucamrgs/mudscope/outputs/tue-tplink-demo/tue-tplink-demo_mrt_transitions_dfs'

        ut_tplink_demo_metadata = '/Users/lucamrgs/mudscope/configs/characterization_datas/ch_fedlab_ut_tplink.json'
        ut_tplink_demo_csv = os.path.abspath(os.path.join(ut_csv_path, os.listdir(ut_csv_path)[0]))
        print(ut_tplink_demo_csv)

        tue_tplink_demo_metadata = '/Users/lucamrgs/mudscope/configs/characterization_datas/ch_fedlab_tue_tplink.json'
        tue_tplink_demo_csv = os.path.abspath(os.path.join(tue_csv_path, os.listdir(tue_csv_path)[0]))
        print(tue_tplink_demo_csv)

        mrtf_ut_tplink_demo = MRTFeed(ut_tplink_demo_metadata, ut_tplink_demo_csv)
        mrtf_tue_tplink_demo = MRTFeed(tue_tplink_demo_metadata, tue_tplink_demo_csv)

        mrta_d = MRTADashboard()
        mrta_d.setup([mrtf_ut_tplink_demo, mrtf_tue_tplink_demo], 1)

        mrta_d.total_avg_corr()
        
        for feature in monitor_features:
            mrta_d.plot_monodim_metric(feature)
        
        sys.exit(1)