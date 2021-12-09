"""
Just a dirty quick script to scale a reference dataset. Deeply project-specific!!
"""


import sys
import os

import numpy as np

import pandas as pd

from sklearn.preprocessing import RobustScaler, StandardScaler
from sklearn import preprocessing

from datetime import datetime
from IPy import IP



################################################################################################
# Scaling reference pre-processing
################################################################################################

def remove_outliers(df, float_cols):       
    for col in float_cols:              # 5 STD DEV distance from median value to remove high-outliers
        df[col] = df[col].mask((df[col] - df[col].mean()).abs() > 5 * df[col].std())
    df = df.dropna()
    return df
def map_addresses(addr):
    try:
        ret = IP(addr).iptype()
        return ret
    except Exception as e:
        return addr
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

def scaling_ref_preprocess(df):
    outliers_wise_cols = ['td', 'bps','pps','bpp']
    sr_cols = df.columns
    dataset_scaler_gen_reference = df.drop_duplicates(sr_cols, keep='last').reset_index(drop=True)
    dataset_scaler_gen_reference = remove_outliers(dataset_scaler_gen_reference, outliers_wise_cols)
    return dataset_scaler_gen_reference

def scaling_ref_ips_to_cagegories(df):
    df['sa'] = df['sa'].map(lambda a:map_addresses(a))
    df['da'] = df['da'].map(lambda a:map_addresses(a))
    return df
def scaling_ref_to_numerical_vals(df):
    return to_numerical_wrapper(df)


"""
TODO: save to CSV
"""

if __name__ == '__main__':
    dataset_scaler_gen_reference_path = sys.argv[1]
    dataset_scaler_gen_reference = pd.read_csv(dataset_scaler_gen_reference_path)

    save_path = os.path.splitext(dataset_scaler_gen_reference_path)[0] + '-SCALED.csv'

    # Early addresses consistency and dates to timestamps
    for col in ['sa', 'da']:
        dataset_scaler_gen_reference[col].apply(lambda x: x.replace(' ', '') if isinstance(x, str) else x)
    dataset_scaler_gen_reference['ts'] = pd.to_datetime(dataset_scaler_gen_reference['ts']).apply(lambda d:d.timestamp())
    dataset_scaler_gen_reference['te'] = pd.to_datetime(dataset_scaler_gen_reference['te']).apply(lambda d:d.timestamp())
    # scaling ref preprocessing
    dataset_scaler_gen_reference = scaling_ref_preprocess(dataset_scaler_gen_reference)
    dataset_scaler_gen_reference = scaling_ref_ips_to_cagegories(dataset_scaler_gen_reference)
    dataset_scaler_gen_reference = scaling_ref_to_numerical_vals(dataset_scaler_gen_reference)
    
    dataset_scaler_gen_reference.to_csv(save_path, index=False)
    