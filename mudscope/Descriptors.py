# Imports
from collections import Counter
from datetime import datetime
from scipy.spatial.distance import pdist, squareform
import numpy as np

class ClusterDescriptor:
    """
        Class that describes the spatial features of a pandas dataframe (generated according to code in this project).
        Though it works with any dataframe, it shall be fed with dataframes that represent the selection of flows belonging to a cluster,
        hence why it's cluster-oriented.
    """

    def __init__(self, cluster_dataframe):
        
        # Remove cluster label from dataframe
        if 'cluster' not in cluster_dataframe.columns:
            self.cluster_df = cluster_dataframe.reset_index(drop=True)
        else:
            self.cluster_df = cluster_dataframe.drop(['cluster'], axis=1).reset_index(drop=True)

        num_pts = self.cluster_df.shape[0]

        # Compute spatial distance between flow values
        # Ref @ https://stackoverflow.com/questions/60574862/calculating-pairwise-euclidean-distance-between-all-the-rows-of-a-dataframe
        c_distances = np.zeros(1)
        if num_pts > 2:
            c_distances = pdist(self.cluster_df.values, metric='euclidean') # euclidean as used by default in HDBSCAN. pdist doc @ https://docs.scipy.org/doc/scipy-0.17.1/reference/generated/scipy.spatial.distance.pdist.html#scipy.spatial.distance.pdist

        # Width of cluster, expressed as cordinate a, b, of most distant points
        c_dist_matrix = squareform(c_distances)
        width_coords = np.unravel_index(np.argmax(c_dist_matrix), c_dist_matrix.shape)
        wp_a = self.cluster_df.iloc[width_coords[0]].values.tolist()
        wp_b = self.cluster_df.iloc[width_coords[1]].values.tolist()

        # NOTE: wcd stands for within-clusters distances, referred to spatial points
        c_wcd_avg = np.mean(c_distances).item()
        c_wcd_std = np.std(c_distances).item()
        np.fill_diagonal(c_dist_matrix, np.inf)
        # heapq.nsmallest(2, set(c_distances.tolist()))[-1] # get the second smallest distance (not same point)
        c_wcd_min = np.min(c_dist_matrix).item()
        c_wcd_max = np.max(c_distances).item()
        c_centroid = np.average(self.cluster_df.values, axis=0).tolist()
        descr_list = c_centroid.copy()
        descr_list.extend([c_wcd_avg, c_wcd_std])

        self.data = {
            'num_pts' : num_pts,
            'wcd_avg' : c_wcd_avg,
            'wcd_std' : c_wcd_std,
            'wcd_max' : c_wcd_max,
            'wcd_min' : c_wcd_min,
            'width_point_a' : wp_a,
            'widht_point_b' : wp_b,
            'centroid' : c_centroid, # a list corresponding to the len(ami-features)-dimensional center
            'meta_centroid' : descr_list # all descriptors as higher dimensional point
        }

    def get_data(self):
        return self.data
    



class FlowsDescriptor:
    # Using pre-processed dataframe. If way to go, to scale to be initialized with Flows CSV
    def __init__(self, flows_dataframe):
        self.flows_dataframe = flows_dataframe

        time_start = datetime.fromtimestamp(float(self.flows_dataframe['ts'].min())).timestamp()
        time_end = datetime.fromtimestamp(float(self.flows_dataframe['ts'].max())).timestamp()

        self.data = {
            #NOTE .item() converts np types to native python, allowing JSON parsing
            'time_span' : [time_start, time_end],
            'total_flows' : int(self.flows_dataframe.shape[0]),
            'src_countries' : dict(), #VolumeDescriptor('source_countries', self.flows_dataframe['sa_country'], data_type='category').get_data(),
            'dst_countries' : dict(), #VolumeDescriptor('destination_countries', self.flows_dataframe['da_country'], data_type='category').get_data(),
            'primary_features' : {
                #    Selected AMI features as of 3 Aug 2021:
                #    'flgs_int', 'bpp', 'ibyt', 'obyt', 'sa', 'dp', 'da', 'bps', 'td'
                'tcp_flags_val' : VolumeDescriptor(self.flows_dataframe['flgs_int']).get_data(),
                'bytes_per_packet' : VolumeDescriptor(self.flows_dataframe['bpp']).get_data(),
                'input_bytes' : VolumeDescriptor(self.flows_dataframe['ibyt']).get_data(),
                'output_bytes' : VolumeDescriptor(self.flows_dataframe['obyt']).get_data(),
                #'source_addresses' : VolumeDescriptor(self.flows_dataframe['sa'], data_type='category').get_data(),
                #'destination_addresses' : VolumeDescriptor(self.flows_dataframe['da'], data_type='category').get_data(),
                'bytes_per_second' : VolumeDescriptor(self.flows_dataframe['bps']).get_data(),
                'time_duration' : VolumeDescriptor(self.flows_dataframe['td']).get_data()
            },
            'secondary_features' : {
                #'d#' : VolumeDescriptor('destination_ports', self.flows_dataframe['dp'], data_type='category').get_data(),
                #'d1' : VolumeDescriptor('packets_per_second', self.flows_dataframe['pps']).get_data()
                #'d6' : VolumeDescriptor('input_packets', self.flows_dataframe['ipkt']).get_data(),
                #'d7' : VolumeDescriptor('output_packets', self.flows_dataframe['opkt']).get_data()
            }
        }

    def printJSON(self):
        print(self.data)
        #print(json.dumps(self.data, indent=4))

    def get_data(self):
        return self.data


class VolumeDescriptor:
        def __init__(self, values, data_type='float'):
            if data_type != 'category' and data_type != 'float':
                raise ValueError('>>> ERROR: Data type parameter [{}] not recognised. VolumeDescriptor class accepts data_type parameter [float] or [category].'.format(data_type))
            
            self.data = {
                # *.item() used to convert Numpy types to Python types, to allow JSON parsing
                'min' : values.min().item(),
                'max' : values.max().item(),
                'avg' : np.average(values).item(),
                'std' : np.std(values).item(),
                'med' : np.median(values).item(),
                'decile_size' : int(len(values) / 10),
                'deciles' : self.get_deciles_data(values)
            # Line below discerns descriptors above from counter dictionary for categorical data
            } if data_type == 'float' else dict(Counter(values)) if data_type == 'category' else None
        
        def get_deciles_data(self, values):
            d = [.1, .2, .3, .4, .5, .6, .7, .8, .9, 1]
            dec_vals = np.quantile(values, d)
            dec_widths = np.diff(dec_vals)
            # *.tolist() again converts Numpy types to Python's, for JSON parsing
            return {'values' : dec_vals.tolist(), 'widths' : dec_widths.tolist()}

        def get_data(self):
            return self.data


if __name__ == '__main__':
    print('Testing!')