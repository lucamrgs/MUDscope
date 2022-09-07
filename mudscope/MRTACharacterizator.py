"""
    Takes bi-dir flows CSV (not necessarily labelled) as dumped by the pcap-to-csv tool.
    Logic from https://colab.research.google.com/drive/1tLYoY6I0XJq5vSUoMhRG-UuT0J8HVe9a?usp=sharing
    (Colab notebook morgese-master-thesis-main.ipynb)
"""

"""
NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE
EVALUATE FLAT NUMBER OF CLUSTERS, AT
    > https://stackoverflow.com/questions/48269092/hdbscan-python-choose-number-of-clusters
NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE
"""



import numpy as np

from pandas.util import hash_pandas_object
import pandas as pd

from sklearn.preprocessing import RobustScaler, StandardScaler
from sklearn.metrics.cluster import adjusted_mutual_info_score
from sklearn.feature_extraction.text import CountVectorizer
from sklearn import preprocessing
import hdbscan

# spatial data computations
from scipy.spatial.distance import pdist, squareform
from scipy import ndimage

from pprint import pprint
import heapq
import json
import sys
import os

from datetime import datetime
from IPy import IP
from Constants import STRFTIME_READABLE_FORMAT

from Descriptors import ClusterDescriptor, FlowsDescriptor

"""
    - TODO: Move pre-processing logic to a prev module so that it only takes a CSV, checks the format, and that's it
"""

class MRTACharacterizator:

    # To check if headers are all _contained_ in provided CSV
    accepted_csv_format = ['ts','te','td','pr','sa','da','sp','dp','ipkt','opkt','ibyt','obyt',
    'flg', 'flgs_int', 'flg_cwr', 'flg_ece', 'flg_urg', 'flg_ack', 'flg_psh', 'flg_rst', 'flg_syn', 'flg_fin',
    'dir','bps','pps','bpp','cl','sl','al']

    #EZVIZ_DATASET_SCALER_GEN_REFERENCE_PATH = '/Users/lucamrgs/Big_Data/IEEE-Huy-Kang/dataset_scaler_gen_reference.csv'
    #EZVIZ_DATASET_SCALER_GEN_REFERENCE = pd.read_csv(EZVIZ_DATASET_SCALER_GEN_REFERENCE_PATH)
    #EZVIZ_MRT_SCALER = StandardScaler().fit(EZVIZ_DATASET_SCALER_GEN_REFERENCE)

    ##########################################################################################
    #   NOTE:   SELECTED_AMI_FEATURES DETERMINES CLUSTERS CENTROIDS DIMENSIONS,
    #           THEN USED IN THE MRT EVOLUTION FEEDS
    ##########################################################################################
    #['flgs_int', 'bpp', 'obyt', 'ibyt', 'sa', 'dp', 'da', 'bps', 'td']
    #['flgs_int', 'bpp', 'sa', 'obyt', 'ibyt', 'dp', 'bps', 'td'] 
    selected_ami_features = ['bpp', 'flgs_int', 'sa', 'obyt', 'ibyt', 'dp']#, 'pps']

    def __init__(self, capture_data, csv_file, dataset_scaler_gen_reference_path):
        
        ################################################## DATASET SCALING REFERENCE SETUP
        self.dataset_scaler_gen_reference = pd.DataFrame()
        try:
            self.dataset_scaler_gen_reference = pd.read_csv(dataset_scaler_gen_reference_path)        
            print('>>> DEBUG: Dropping unsupported columns from scaling ref dataset: {}'.format([col for col in self.dataset_scaler_gen_reference.columns if col not in MRTACharacterizator.accepted_csv_format]))
            self.dataset_scaler_gen_reference = self.dataset_scaler_gen_reference[MRTACharacterizator.accepted_csv_format]
            self.mrt_scaler = StandardScaler().fit(self.dataset_scaler_gen_reference)
            print(f'>>> DEBUG: Scaling ref dataset columns: {self.dataset_scaler_gen_reference.columns}')
            print(f'>>> DEBUG: Scaling ref dataset shape: {self.dataset_scaler_gen_reference.shape}')
        except Exception as e:
            print(e)
            raise ValueError(f'>>> ERROR: Something went wrong in trying to obtain the StandardScaler on dataset at [ {dataset_scaler_gen_reference_path} ]. Exiting.')

        #print('DSGR SHAPE: ', self.dataset_scaler_gen_reference.shape)
        #print(self.dataset_scaler_gen_reference.columns)
        
        ################################################## DATASET SCALING REFERENCE SETUP
        print(f">>> Instantiating characterizator for file : {csv_file}")

        self.capture_data = capture_data
        self.csv_file = csv_file
        self.dataset = self.check_csv_format(self.csv_file) # TODO: check CSV format
        
        self.datasets_versions = {} # TODO/NOTE: note memory-wise persistency of dataframe versions.

        self.ops = {'dataset_preset' : False, 'preprocessed' : False, 'numerized' : False, 'scaled' : False, 'reduced' : False, 'clusterer_run' : False}

        self.clusterer = hdbscan.HDBSCAN()
        self.clusters_dataframes = {}

        self.clusters_points = {} # spatial 'slices' of entries in processed (scaled, AMI-reduced) dataframe
        self.clusters_spatial_data = {}

        # Characterization object instanciated in MRTACharacterizator().run_characterization()
        self.characterization = dict()

    @staticmethod
    def add_quasi_copy_row_to_dataset(dataframe):
        """Used when dataset has only one entry, which creates issues with hdbscan"""
            # same entry with switched values
        quasi_copy = dataframe.iloc[0]
        quasi_copy['td'] = (dataframe.iloc[0]['td']) + (dataframe.iloc[0]['td'] / 1000)
        dataframe = dataframe.append(quasi_copy, ignore_index=True)
        print(dataframe)
        return dataframe


    def check_csv_format(self, csv_file):
        dataframe = pd.read_csv(csv_file)
        in_df_cols = dataframe.columns
        print('>>> INPUT DATASET HEADER FORMAT: {}'.format(in_df_cols))
        print('>>> INPUT DATASET SHAPE: {}'.format(dataframe.shape))

        is_consistent_format = all(item in in_df_cols for item in MRTACharacterizator.accepted_csv_format)
        if not is_consistent_format:
            print('>>> WARNING: Input CSV headers format is different from the one handled by default.')
            print('>>> Execution MAY CRASH, or produce unexpected results.')
            print('>>> Handled format: {}'.format(MRTACharacterizator.accepted_csv_format))
            print('>>> Input CSV Headers: {}'.format(in_df_cols))
        
        print('>>> DEBUG: Dropping unsupported columns for processing: {}'.format([col for col in in_df_cols if col not in MRTACharacterizator.accepted_csv_format]))
        # Subsetting dataframe to supported columns
        dataframe = dataframe[MRTACharacterizator.accepted_csv_format]
        print('>>> Input csv shape: {}'.format(dataframe.shape))

        # Add quasi-identical copy (so that it's not removed in drop_duplicates) of flow if #flows = 1:
        """ NOTE: hdbscan has a debated hard-coded setting that does not allow to have min_c_size = 1 (so at least 2), 
            and when the capture only has one flow, it breaks (of course, since there would be no need to clustering)
        """
        if dataframe.shape[0] == 1:
            print(f'>>> DEBUG: Dataframe has only one row, which causes issues with hdbscan. Adding one quasi-copy of the row to the dataframe so that it has 2 entries.')
            dataframe = MRTACharacterizator.add_quasi_copy_row_to_dataset(dataframe)

        return dataframe


    def preset_dataset(self):
        if self.ops['dataset_preset'] :
            print('>>> Dataset already preset for MRTACharacterizator instance, skipping operations.')
            return

        # Drop obsolete/unused data
        if 'ATK_TYPE' in self.dataset.columns:
            self.dataset = self.dataset[self.dataset['ATK_TYPE'] != 'MITM-ARPSPOOFING']
            self.dataset = self.dataset.drop('ATK_TYPE', axis=1)
        if 'MALICIOUS' in self.dataset.columns:
            self.dataset = self.dataset.drop('MALICIOUS', axis=1)
        
        #print('>>> >>> Dataset shape before removing 0 cols: {}'.format(self.dataset.shape))
        #self.dataset = self.dataset.loc[:, (self.dataset != 0).any(axis=0)] # https://stackoverflow.com/questions/21164910/how-do-i-delete-a-column-that-contains-only-zeros-in-pandas
        #self.dataset = self.dataset.replace("", np.nan)
        #self.dataset = self.dataset.dropna()
        #self.dataset.reset_index(drop=True, inplace=True)
        #print('>>> >>> Dataset shape after removing 0 cols: {}'.format(self.dataset.shape))

        h = hash_pandas_object(self.dataset).sum()
        print('>>> Dataframe hash: {}'.format(h))

        # NOTE: Dataset version added
        self.datasets_versions['original_dataset'] = self.dataset.copy
        self.ops['dataset_preset'] = True


    ################################################################################################
    # Temporary pre-processing functions - TO BE REMOVED
    ################################################################################################

    def dataset_consistent_string_addresses(self):
        for col in ['sa', 'da']:
            self.dataset[col].apply(lambda x: x.replace(' ', '') if isinstance(x, str) else x)

    def dataset_dates_to_timestamps(self):
        self.dataset['ts'] = pd.to_datetime(self.dataset['ts']).apply(lambda d:d.timestamp())
        self.dataset['te'] = pd.to_datetime(self.dataset['te']).apply(lambda d:d.timestamp())
    
    """
    def dataset_to_consistent_floats(self):
        float_cols = ['td', 'ipkt','opkt','ibyt','obyt', 'flg_cwr', 'flg_ece', 'flg_urg', 'flg_ack', 'flg_psh', 'flg_rst', 'flg_syn', 'flg_fin', 'bps','pps','bpp']
        def map_floats(val):
            if isinstance(val, float) or isinstance(val, int):
                if np.isnan(val):
                    return 0
                else:
                    return val
            elif isinstance(val, str):
                try:
                    return float(val)
                except Exception as e:
                    print(val)
                    if val.endswith('M'): # Manual 'Million' value from nfdump parsing
                        num = val.split()[0]
                        return float(num) * 1000000
                    else:
                        return 0
            else:
                return 0
        for col in float_cols:
            try:
                self.dataset[col] = self.dataset[col].map(lambda v:map_floats(v))
            except Exception as e:
                pass
    
    def dataset_add_flags_cols(self):
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
        def flags_col_to_onehot(df):
            # Ref https://stackoverflow.com/questions/48168348/pandas-replace-a-column-within-a-data-frame-by-two-columns
            flags_df = df['flg'].apply(flag_tag_to_binary_array) # new df encoding flags
            flags_int_val = df['flg'].apply(flag_tag_to_binary_int_representation)
            flags_df = pd.DataFrame(flags_df.values.tolist()) # explode to self.dataset cols
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

        self.dataset = flags_col_to_onehot(self.dataset)
    """
    def dataset_replace_infs(self):
        self.dataset = self.dataset.replace([np.inf, -np.inf], 0)


    """
    ################################################################################################
    # Scaling reference pre-processing
    ################################################################################################

    @staticmethod
    def remove_outliers(df, float_cols):       
        for col in float_cols:              # 5 STD DEV distance from median value to remove high-outliers
            df[col] = df[col].mask((df[col] - df[col].mean()).abs() > 5 * df[col].std())
        df = df.dropna()
        return df
    @staticmethod
    def map_addresses(addr):
        try:
            ret = IP(addr).iptype()
            return ret
        except Exception as e:
            return addr

    @staticmethod
    def to_numerical_wrapper(dataset):
        def transform_addresses(df):
            transformer = preprocessing.OrdinalEncoder()
            df['sa'] = transformer.fit_transform(df[['sa']])
            df['da'] = transformer.fit_transform(df[['da']])
            return df, transformer

        ## sp and dp : ordinally encoded as they correspond to 'services'. One-hot-encoding to take into consideration, though would introduce highly sparse arrays
        import socket
        def transform_ports(df):
            transformer = preprocessing.OrdinalEncoder()
            df['sp'] = transformer.fit_transform(df[['sp']])
            df['dp'] = transformer.fit_transform(df[['dp']])
            return df, transformer

        ## dir : direction of connection, binary category, ordinal-encoded
        def transform_direction(df):
            transformer = preprocessing.OrdinalEncoder()
            df['dir'] = transformer.fit_transform(df[['dir']])
            return df, transformer

        ## pr : protocol, category, ordinal-encoded
        def transform_proto(df):
            transformer = preprocessing.OrdinalEncoder()
            df['pr'] = transformer.fit_transform(df[['pr']])
            return df, transformer

        ## flg : flags, one-hot encoded above with custom function, just dropping old value

        def transform_flags(df):
            transformer = preprocessing.OrdinalEncoder()
            df['flg'] = transformer.fit_transform(df[['flg']])
            return df, transformer

        def transform_cols(df):
            df, addr_tfm = transform_addresses(df)
            #print(df.shape)
            df, proto_tfm = transform_proto(df)
            #print(df.shape)
            df, ports_tfm = transform_ports(df)
            #print(df.shape)
            df, flgs_tfm = transform_flags(df)
            #print(df.shape)
            df, dir_tfm = transform_direction(df)
            #print(df.shape)
            return df

        return transform_cols(dataset)

    def scaling_ref_preprocess(self):
        print('I get here')
        outliers_wise_cols = ['td', 'bps','pps','bpp']
        sr_cols = self.dataset_scaler_gen_reference.columns
        self.dataset_scaler_gen_reference = self.dataset_scaler_gen_reference.drop_duplicates(sr_cols, keep='last').reset_index(drop=True)
        self.dataset_scaler_gen_reference = MRTACharacterizator.remove_outliers(self.dataset_scaler_gen_reference, outliers_wise_cols)
    def scaling_ref_ips_to_cagegories(self):
        print('I also get here')
        self.dataset_scaler_gen_reference['sa'] = self.dataset_scaler_gen_reference['sa'].map(lambda a:MRTACharacterizator.map_addresses(a))
        self.dataset_scaler_gen_reference['da'] = self.dataset_scaler_gen_reference['da'].map(lambda a:MRTACharacterizator.map_addresses(a))
    def scaling_ref_to_numerical_vals(self):
        print('and here as well')
        self.dataset_scaler_gen_reference = MRTACharacterizator.to_numerical_wrapper(self.dataset_scaler_gen_reference)
    """

    ################################################################################################
    # Features transformations
    ################################################################################################

    def dataset_preprocess(self):
        if self.ops['preprocessed']:
            print('>>> Dataframe already pre-processed, skipping operations.')
            return

        # Removing duplicates
        cols = self.dataset.columns
        print('>>> Dataset shape before dropping dups: {}'.format(self.dataset.shape))
        print(self.dataset.columns)
        self.dataset = self.dataset.drop_duplicates(cols, keep='last').reset_index(drop=True)
        print('>>> Dataset shape after dropping dups: {}'.format(self.dataset.shape))

        # Removing outliers
        """
            TODO: RECONSIDER REMOVING OUTLIERS FOR BETTER REPRESENTABILITY OF DATA
            FIXED NORMAL MIN MAX GATHERED FROM HISTORIC DATA (?)
        """
        print('>>> Dataset shape before outliers: {}'.format(self.dataset.shape))
        def remove_outliers(df, float_cols):       
            for col in float_cols:              # 5 STD DEV distance from median value to remove high-outliers
                df[col] = df[col].mask((df[col] - df[col].mean()).abs() > 5 * df[col].std())
            df = df.dropna()
            return df

        outliers_wise_cols = ['td', 'bps','pps','bpp']
        self.dataset = remove_outliers(self.dataset, outliers_wise_cols)
        print('>>> Dataset shape after outliers: {}'.format(self.dataset.shape))

        if self.dataset.shape[0] == 1:
            print(f'>>> DEBUG: Dataframe has only one row, which causes issues with hdbscan. Adding one quasi-copy of the row to the dataframe so that it has 2 entries.')
            self.dataset = MRTACharacterizator.add_quasi_copy_row_to_dataset(self.dataset)

        # Saving original clean dataset
        self.datasets_versions['original_clean'] = self.dataset.copy()
        self.ops['preprocessed'] = True


    def dataset_ips_to_categories(self):
        def map_addresses(addr):
            try:
                ret = IP(addr).iptype()
                return ret
            except Exception as e:
                return addr
        self.dataset['sa'] = self.dataset['sa'].map(lambda a:map_addresses(a))
        self.dataset['da'] = self.dataset['da'].map(lambda a:map_addresses(a))

    def dataset_to_numerical_vals(self):
        if self.ops['numerized']:
            print('>>> Dataframe features already made numeric, skipping operations.')
            return
        
        def transform_addresses(df):
            transformer = preprocessing.OrdinalEncoder()
            df['sa'] = transformer.fit_transform(df[['sa']])
            df['da'] = transformer.fit_transform(df[['da']])
            return df, transformer

        ## sp and dp : ordinally encoded as they correspond to 'services'. One-hot-encoding to take into consideration, though would introduce highly sparse arrays
        import socket
        def transform_ports(df):
            transformer = preprocessing.OrdinalEncoder()
            df['sp'] = transformer.fit_transform(df[['sp']])
            df['dp'] = transformer.fit_transform(df[['dp']])
            return df, transformer

        ## dir : direction of connection, binary category, ordinal-encoded
        def transform_direction(df):
            transformer = preprocessing.OrdinalEncoder()
            df['dir'] = transformer.fit_transform(df[['dir']])
            return df, transformer

        ## pr : protocol, category, ordinal-encoded
        def transform_proto(df):
            transformer = preprocessing.OrdinalEncoder()
            df['pr'] = transformer.fit_transform(df[['pr']])
            return df, transformer

        ## flg : flags, one-hot encoded above with custom function, just dropping old value

        def transform_flags(df):
            transformer = preprocessing.OrdinalEncoder()
            df['flg'] = transformer.fit_transform(df[['flg']])
            return df, transformer

        def transform_cols(df):
            df, addr_tfm = transform_addresses(df)
            #print(df.shape)
            df, proto_tfm = transform_proto(df)
            #print(df.shape)
            df, ports_tfm = transform_ports(df)
            #print(df.shape)
            df, flgs_tfm = transform_flags(df)
            #print(df.shape)
            df, dir_tfm = transform_direction(df)
            #print(df.shape)
            return df

        if self.ops['preprocessed']:
            self.dataset = transform_cols(self.dataset)
            self.ops['numerized'] = True
        else:
            print('>>> Trying ordinal encoding without dataset being preprocessed. Exiting.')
            sys.exit(0)

    def dataset_scale(self):
        if self.ops['scaled']:
            print('>>> Dataframe features already scaled, skipping operations.')
            return
        #print(self.dataset.sample(10))
        if not self.ops['numerized']:
            print('>>> Trying scaling dataset without features being numerized first. Exiting.')
            sys.exit(0)

        ft_list = list(self.dataset.columns)
        # Scaler transformers

        """
        **********************************************************************************************
            TODO: ROBUST AND CONSISTENT SCALING ACROSS ALL DEPLOYMENTS!!!
            TODO: FIX SCALING RANGE WITH MINMAX AND APPLY TO ALL CHARACTERIZATIONS
        **********************************************************************************************
        """
        dataset_scaler = StandardScaler().fit(self.dataset)
        #   TODO CHANGE TO PER-MODEL REFERENCE CAPTURE DATASET > later comment: I knew already!
        #       >>> Added as init parameter.
        self.dataset = pd.DataFrame(self.mrt_scaler.transform(self.dataset), columns=ft_list, index=self.dataset.index)
        #self.dataset = pd.DataFrame(dataset_scaler.transform(self.dataset), columns=ft_list, index=self.dataset.index)
        
        self.ops['scaled'] = True
        #print(hash_pandas_object(self.dataset).sum())

            

    def dataset_reduce_to_AMI_selected_features(self):
        if self.ops['reduced']:
            print('>>> Dataframe features already reduced to selected ones, skipping operations.')
            return
        
        if not self.ops['scaled']:
            print('>>> Trying reducing dataset for clustering without features being scaled first. Exiting.')
            sys.exit(0)
        
        print('>>> SELF DATASET COLS AT dataset_reduce_to_AMI_selected_features: {}'.format(self.dataset.columns))

        self.dataset = self.dataset[MRTACharacterizator.selected_ami_features]
        self.ops['reduced'] = True
        
        h = hash_pandas_object(self.dataset).sum()
        print('scaled_features_dataset hash: {}'.format(h))    

    ################################################################################################
    # Density Clustering with HDBSCAN
    ################################################################################################

    # NOTE s
    # hdbscan docs (very nice ones!) @ https://hdbscan.readthedocs.io/en/latest/advanced_hdbscan.html

    ########################
    # NOISE-AMI-CLUSTERS OPTIMAL PARAMS FROM GRID SEARCH:
    #   min_cluster_size ~~ 1.4% ~~ (of flows in capture),
    #   min_samples (core neighbourhood) ~~ 0.2% ~~ (of min_cluster_size)
    ########################

    def run_clusterer(self, perc_cluster_size=1.2, perc_min_core_point_nbs_over_cluster_size=0.2):

        if self.ops['clusterer_run']:
            print('>>> Dataframe already clustered, skipping operations.')
            return

        #print(self.dataset.sample(10))

        if not self.ops['reduced']:
            print('>>> Trying to perform clustering without features preprocessing first. Exiting.')
            sys.exit(0)
        
        min_c_size = int(len(self.dataset) / 100 * perc_cluster_size)
        min_s = int(min_c_size * perc_min_core_point_nbs_over_cluster_size)

        print('min_c_size: {}'.format(min_c_size))
        print('min_s: {}'.format(min_s))

        if min_c_size < 2:
            min_c_size = 2
        if min_s < 2:
            min_s = 2

        print('min_c_size: {}'.format(min_c_size))
        print('min_s: {}'.format(min_s))

        self.clusterer = hdbscan.HDBSCAN(min_cluster_size=min_c_size, min_samples=min_s, allow_single_cluster=True).fit(self.dataset)
        #ami_precision = adjusted_mutual_info_score(self.datasets_versions['original_clean']['ATK_TYPE'], self.clusterer.labels_)
        #completeness = completeness_score(self.datasets_versions['original_clean']['ATK_TYPE'], self.clusterer.labels_)

        self.ops['clusterer_run'] = True

        self.dataset['cluster'] = self.clusterer.labels_
        self.clusters_points = {str(val) : self.dataset[self.dataset['cluster'] == val] for val in set(list(self.clusterer.labels_))}

        # Remap processed flows to actual groups of flows data
        self.datasets_versions['original_clean']['cluster'] = self.clusterer.labels_        
        self.clusters_dataframes = {str(val) : self.datasets_versions['original_clean'][self.datasets_versions['original_clean']['cluster'] == val] for val in set(list(self.clusterer.labels_))}
        #print(self.datasets_versions['original_clean'].sample(3))


        #print('AMI precision: {}'.format(ami_precision))
        #print('Completeness score: {}'.format(completeness))
        print('Num clusters: {}'.format(len(set(self.clusterer.labels_))))
        print('Clusters: '.format(set(self.clusterer.labels_)))
        noise_pts_num = len(([v for v in self.clusterer.labels_ if v == -1]))
        noise_pts_perc = noise_pts_num / self.dataset.shape[0]
        print('Noise points: {} (%{})'.format(noise_pts_num, noise_pts_perc))


    def run_characterization(self):
        if not self.ops['clusterer_run']:
            print('>>> Trying to perform characterization without having run clustering first. Exiting.')
            sys.exit(0)
        
        # NOTE: original_clean dataframe has timestamps as time values - taken min-max and converted to datetimes
        init_capture_time = datetime.fromtimestamp(float(self.datasets_versions['original_clean']['ts'].min()))
        end_capture_time = datetime.fromtimestamp(float(self.datasets_versions['original_clean']['ts'].max()))

        init_capture_time = init_capture_time.strftime(STRFTIME_READABLE_FORMAT)
        end_capture_time = end_capture_time.strftime(STRFTIME_READABLE_FORMAT)

        # datetime object containing current date and time
        now = datetime.now()
        dt_string = now.strftime(STRFTIME_READABLE_FORMAT)

        # Metadata
        self.characterization['metadata'] = {
            'date_added' : dt_string,
            'time_window' : (init_capture_time, end_capture_time),
            'deployment_data' : {
                'device_id' : self.capture_data['device_id'],
                'deployment_info' : self.capture_data['deployment_info']
            },
            'total_flows' : int(self.datasets_versions['original_clean'].shape[0]),
            'clustering_params' : {
                'alg' : 'hdbscan',
                'min_cluster_size' : 1.4,
                'min_core_points' : 0.2,
                'cluster_features' : MRTACharacterizator.selected_ami_features,
                'scaling_method' : 'sklearn.preprocessing.StandardScaler'
            }
        }
        
        # Whole capture descriptor
        self.characterization['complete_capture_descriptor'] = FlowsDescriptor(self.datasets_versions['original_clean']).get_data()

        # Init Clusters data
        self.characterization['clusters'] = {c : {'spatial_data' : {}, 'descriptors' : {}} for c in self.clusters_dataframes.keys()}

        # MRT CORE CHARACTERIZATION INFORMATION
        
        # Clusters spatial data
        for c, df in self.clusters_points.items():            
            c_desc = ClusterDescriptor(df).get_data()
            self.characterization['clusters'][c]['spatial_data'] = c_desc
        # Clusters descriptors
        self.characterization['num_clusters'] = len(self.clusters_dataframes.keys())
        self.characterization['num_total_flows'] = self.dataset.shape[0]
        for c, df in self.clusters_dataframes.items():
            f_desc = FlowsDescriptor(df).get_data()
            self.characterization['clusters'][c]['descriptors'] = f_desc
        

    def save_characterization(self, output_path):
        print(type(self.characterization))
        with open(output_path, 'w') as f:
            json.dump(self.characterization, f, ensure_ascii=False, indent=4)


    def print_clusters_statistical_descriptions(self):
        for c, df in self.clusters_dataframes.items():
            print('Cluster label: {}'.format(c))
            desc = FlowsDescriptor(df)
            desc.printJSON()
    

    def input_to_characterization_data(self):
        # TODO: Remove temporary pre-processing functions
        #print('>>> Dataset shape before preset: {}'.format(self.dataset.shape))
        self.preset_dataset()
        #print('>>> Dataset shape after preset: {}'.format(self.dataset.shape))

        #print('>>> Dataset shape before string addrs: {}'.format(self.dataset.shape))
        self.dataset_consistent_string_addresses()
        #print('>>> Dataset shape after string addrs: {}'.format(self.dataset.shape))
        
        #print('>>> Dataset shape before dates-timestp: {}'.format(self.dataset.shape))
        self.dataset_dates_to_timestamps()
        #print('>>> Dataset shape after dates-timestp: {}'.format(self.dataset.shape))
        
        #self.dataset_to_consistent_floats()
        #self.dataset_add_flags_cols()

        #print('>>> Dataset shape before replace infs: {}'.format(self.dataset.shape))
        self.dataset_replace_infs()
        #print('>>> Dataset shape after replace infs: {}'.format(self.dataset.shape))

        self.dataset_preprocess()
        
        self.dataset_ips_to_categories()
        self.dataset_to_numerical_vals()

        self.dataset_scale()
        self.dataset_reduce_to_AMI_selected_features()

        self.run_clusterer()

        self.run_characterization()

        


if __name__ == '__main__':
    print('Testing!')
    
    """
    capture_data_sample = {'device_id' : 'ezviz_test', 'deployment_info' : {'lat_lon' : (0, 0), 'country' : 'Test', 'industry_sector' : 'Test'}}
    reference_csv_dataset = './outputs/ieee-ezviz-complete/ieee-ezviz-complete-all-flows-csv-custom-fromat-CLN-UNLABELLED.csv'
    mrta_clusterer = MRTACharacterizator(capture_data_sample, reference_csv_dataset)
    """
    
    test_rnd = {'device_id' : 'phillips-hue', 'deployment_info' : 'test'}
    # './outputs/phillips-hue/phillips-hue-all-flows-csv/phillips-hue-all-flows-csv-custom-fromat-CLN.csv'
    #test_rnd_csv = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ezviz-dashboard-tests/ezviz-dashboard-tests-all-flows-csv/output_00007_20190527041113-flows-custom-hdr-CLN.csv'
    test_rnd_csv = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/temp-tests/temp-tests-all-flows-csv/scan-portos-all-ezviz-flows-custom-hdr-CLN.csv'
    mrta_clusterer = MRTACharacterizator(test_rnd, test_rnd_csv, '/Users/lucamrgs/Big_Data/IEEE-Huy-Kang/dataset_scaler_gen_reference.csv')

    mrta_clusterer.input_to_characterization_data()

    #print(mrta_clusterer.dataset.shape)

    mrta_clusterer.save_characterization('doesitwork.json')
    #mrta_clusterer.print_clusters_statistical_descriptions()

    #MRTACharacterizator.get_characterization_dataframe('doesitwork.json')


