
import os
import sys
import ast
from itertools import combinations

import seaborn as sns
import matplotlib.pyplot as plt

from Constants import MONITOR_OUTPUTS_FOLDER
plt.rcParams.update({'font.size': 11})

import numpy as np
import pandas as pd
from pandas.plotting import parallel_coordinates
pd.set_option("display.precision", 16)

MY_SAVE_PATH_DEFAULT = MONITOR_OUTPUTS_FOLDER
#'/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/demo_results/'#pre-results-data/diff-attacks-monodim/'

from MRTAFeed import MRTFeed

"""
    TODO TODO TODO
        - CHECK time window over all MRT Feed files: start and end must be reasonably overlayed through all feeds
        - CHECK each feed has same number of transitions (or cut to minimum number of transitions over correct period)
"""

MRTFEEDS_TIME_OFFSET_TOLERANCE = 0.1

class MRTADashboard:
    """
        Class that stores multiple (N) MRT Feeds, and plots them, along group-wise metrics and information
        An MRT Feed is a pair of type <file.json, pandas.dataframe> 
    """
    def __init__(self):
        print('>>> Dashboard generated')
        self.feeds = []
    
    def populate(self, feeds_list):
        for mrt_feed in feeds_list:
            if not isinstance(mrt_feed, MRTFeed):
                raise ValueError(f">>> ERROR: feeds_list contain non MRTFeed-type values.")
            
        self.feeds = feeds_list
        self.align_feeds()
        mrt_feed_columns = [col for col in self.feeds[0].data.columns]
        self.significant_features = mrt_feed_columns[mrt_feed_columns.index('clusters_balance'):] # SLICE AFTER METADATA
        self.significant_features = [f for f in self.significant_features if not (f.endswith('_col_cluster') or f.endswith('_row_cluster') or f.endswith('noise_balance')) ] # REMOVE NOMINAL CLUSTER FEATURES


    """
    ****************************************************************************************************************
    TODO:
        - Produce 'generic visualization' panel plotting the most relevant and generalized metrics
            * clusters balance
            * all dists average
            * all dists std
            * all dists deciles

            * mutual matches n + percentage
            * mutual vects average

            * fwd matches n + percentage
            * fwd vects agglomeration average
            * fwd vects average

            * bwd matches n + percentage
            * bwd vects agglomeration average
            * bwd vects average
        
            ....FOR EACH FEED

    ****************************************************************************************************************
    """

    ##################################################################################################################################
    # VISUALIZATION
    ##################################################################################################################################
    """
        *****************************************************************************************************
        # NOTE: It can be expected that the MRT feeds do not keep at the same time a huge number of entries.
                It could be therefore possible to plot these info in a resonably non-cluttered chart (!??!?)
        *****************************************************************************************************
        MONO-DIMENSIONAL FEATURES:
            For each MRT feed, plot the pd series of the feature in one line graph. There will be as many lines as MRT feeds
        HIGHER-DIMENSIONAL FEATURES:
            Option 1: PCA to 2 or 3 dimensions:
                X, Y, Z axes are value ranges of PCA-ed N-dimensional cell value
                Colours of points indicate the MRT feed
        CHOSEN OPTION >>> Option 2: Parallel coordinates chart
                Y axis is value range of coordinates
                X axis is the N-dimensions
                Colours of lines indicate the MRT feed
            Option 3: Radar plot
                Quadrant dividers are the N cooridnates of points
                Each polygon represents one entry cell point (must be very thin!)
                Colour of polygon indicates the MRT feed
            Some references:
                - https://stackoverflow.com/questions/27930413/how-to-plot-a-multi-dimensional-data-point-in-python
                - https://www.python-graph-gallery.com/parallel-plot/
                - https://pandas.pydata.org/docs/getting_started/intro_tutorials/04_plotting.html
    """

    def plot_monodim_metric(self, metric, save_dir=MY_SAVE_PATH_DEFAULT, show=False):
        if not self.metric_exists(metric):
            raise ValueError(f'>>> ERROR: Invalid metric queried on MRT feeds: [ {metric} ].')
        self.check_metric_monodim(metric)
        palette = sns.color_palette(None, len(self.feeds))
        f_plt = []
        l_plt = []
        
        fig, axs = plt.subplots(2,1, gridspec_kw={'height_ratios': [3, 1]}, constrained_layout=True)
        fig.set_figheight(5)
        fig.set_figwidth(12)


        
        #plt.figure(figsize=(12, 7))
        fig.suptitle(f'All feeds, monodimensonal metric: {metric}')
        for i, feed in enumerate(self.feeds):
            f, = axs[0].plot(feed.data[metric], color=palette[i], label=feed.id) # https://stackoverflow.com/questions/11983024/matplotlib-legends-not-working
            l_plt.append(feed.id.split('_')[-1])
            f_plt.append(f)

        axs[0].legend(f_plt, l_plt, loc='upper left')
        axs[0].set(xlabel='Transition entry')

        cor = self.corr_monodim_metric(metric)
        axs[1].tick_params(labelrotation=60)
        sns.heatmap(cor, ax=axs[1], annot=True, fmt='.2f', cmap=plt.cm.Blues, vmin=-1, vmax=1, yticklabels=True, xticklabels=True)
        plt.savefig(MY_SAVE_PATH_DEFAULT + metric + '.png')
        
        if show:
            plt.show()
        
        print(f'>>> Output saved to {save_dir}.')
    
    def plot_multidim_metric(self, metric, save_dir=MY_SAVE_PATH_DEFAULT, show=False):
        if not self.metric_exists(metric):
            raise ValueError(f'>>> ERROR: Invalid metric queried on MRT feeds: [ {metric} ].')
        self.check_metric_multidim(metric)

        fig, axs = plt.subplots(len(self.feeds) + 1, 1, constrained_layout=True) # One axis per MRTFeed + axis for correlation heatmap
        fig.set_figheight(8)
        fig.set_figwidth(16)

        fig.suptitle(f'All feeds, multidimensional metric: {metric}')

        for i, feed in enumerate(self.feeds):

            #Select all deciles columns if metric is a decile
            if 'decile' in metric:
                #TODO: PLOT ALL DECILES FOR mutual/fwd/bwd IN ONE GRAPH (BASICALLY A MERGE OF ALL GRAPHS PER DECILE NUMBER!?)
                pass
            
            # Generation of numeric dataframe from multidimensional metric, ready to be processed
            df_T = self.get_df_of_multidim_metric(feed, metric)
            df_T['Index'] = df_T.index # Adding explicit index column for plotting labels

            ######################################################################################## PARALLEL COORDINATES
            palette = sns.color_palette(None, len(df_T.index)) # On index are the metric's dimensions
            axs[i].set_title(f'{feed.id} : {metric}')
            axs[i].set(xlabel='Transition entry #')
            parallel_coordinates(df_T, 'Index', ax=axs[i], color=palette).legend_.remove()
        
        handles, labels = axs[0].get_legend_handles_labels()
        fig.legend(handles, labels, loc='upper right')
        
        cor_avgs, _ = self.corr_multidim_metric(metric)
        sns.heatmap(cor_avgs, ax=axs[-1] ,annot=True, fmt='.2f', cmap=plt.cm.Blues, vmin=-1, vmax=1)
        plt.savefig(MY_SAVE_PATH_DEFAULT + metric + '.png')
        
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
            Then applies corr() on dataset 

            **************************
            M_monodim_metric[i, j] = corr(
                feed_i[metric],
                feed_j[metric]
            )
            **************************
        """    
        self.check_metric_monodim(metric)
        
        #NOTE: REAL CONSTRUCTOR: {feed.id : feed.data[metric].values.tolist() for feed in self.feeds} - Used to test: {feed.id + str(i) : feed.data[metric].values.tolist() for i, feed in enumerate(self.feeds)}
        per_metric_dict = {feed.id.split('_')[-1] : feed.data[metric].values.tolist() for feed in self.feeds}
        per_metric_feeds_df = pd.DataFrame.from_dict(per_metric_dict)
        #plt.figure(figsize=(18, 14))
        cor = per_metric_feeds_df.corr().fillna(0)
        #print(cor)
        #plt.tight_layout()
        #sns.heatmap(cor, annot=True, fmt='.2f', cmap=plt.cm.Blues)
        #plt.show()
        return cor


    def corr_multidim_metric(self, metric):
        """
        TODO TODO TODO
            - POPULATE ONLY UPPER TRIANGULAR

            ************************************
            M_multidim_metric[i, j] = avg(
                corr(feed_i[metric][dim1], feed_j[metric][dim1])
                ...,
                corr(feed_i[metric][dimN], feed_j[metric][dimN])
            )
            ************************************
        """

        self.check_metric_multidim(metric)
                                        # Feed-specific dataframe of multidim metric 
        metric_dfs_dict = {feed.id.split('_')[-1] : self.get_df_of_multidim_metric(feed, metric) for feed in self.feeds}
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

        #print(corr_matrix_all_values)
        #print(corr_matrix_averages)
        
        #plt.figure(figsize=(10, 6))
        #sns.heatmap(corr_matrix_averages, annot=True, fmt='.2f', cmap=plt.cm.Blues)
        #plt.show()
        return corr_matrix_averages, corr_matrix_all_values

    def total_avg_corr(self):
        """Computes correlation over all contributing features, returns descriptors"""
        monodim_features_correlation_arrays = []
        multidim_features_correlation_arrays = []
        for col in self.significant_features:
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
    
    def metric_exists(self, metric):
        try:
            # TODO: Test
            probe = self.feeds[0].data[metric][0]
            return True
        except Exception as e:
            return False

    def align_feeds(self):
        """Normalizes feeds lists according to number of transitions recorded, and timings"""
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
        probe = self.feeds[0].data[metric][0]
        try:
            a = ast.literal_eval(probe)
        except Exception as e:
            #print(e)
            return True
        return False
    def is_multidim_metric(self, metric):
        probe = self.feeds[0].data[metric][0]
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



    print('>>> Testing MRTADashboard!')
    ezviz_metadata_path = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/configs/characterization_datas/ch_data_ezviz.json'
    ezviz_mrt_feed_csv_path = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ezviz-pf/ezviz-pf_mrt_transitions_dfs/clusters_evols_20211028_13-56-55_ezviz-pf-SAME-ORDER.csv'
    ezviz_mrt_feed_csv_path_diff = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ezviz-pf/ezviz-pf_mrt_transitions_dfs/clusters_evols_20211104_11-41-20_ezviz-pf-RAND-ORDER.csv'

    nugu_metadata_path = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/configs/characterization_datas/ch_data_nugu.json'
    nugu_mrt_feed_csv_path = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/nugu-pf/nugu-pf_mrt_transitions_dfs/clusters_evols_20211028_13-56-40_nugu-pf-SAME-ORDER.csv'
    nugu_mrt_feed_csv_path_diff = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/nugu-pf/nugu-pf_mrt_transitions_dfs/clusters_evols_20211104_11-43-21_nugu-pf-RAND-ORDER.csv'

    mrt_ezviz_pf_ord = MRTFeed(ezviz_metadata_path, ezviz_mrt_feed_csv_path)
    mrt_ezviz_pf_diff = MRTFeed(ezviz_metadata_path, ezviz_mrt_feed_csv_path_diff)
    
    mrt_nugu_pf_ord = MRTFeed(nugu_metadata_path, nugu_mrt_feed_csv_path)
    mrt_nugu_pf_diff = MRTFeed(nugu_metadata_path, nugu_mrt_feed_csv_path_diff)

    #air_quality = pd.read_csv("src/tests/air_quality_no2.csv", index_col=0, parse_dates=True)

    dim = sys.argv[1]

    ########################## METADATAS
    ut_tplink_plug_metadata = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/configs/characterization_datas/ch_fedlab_ut_tplink.json'
    ut_wansview_cam_metadata = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/configs/characterization_datas/ch_fedlab_ut_wansview.json'
    tue_tplink_plug_metadata = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/configs/characterization_datas/ch_fedlab_tue_tplink.json'
    tue_foscam_cam_metadata = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/configs/characterization_datas/ch_fedlab_tue_foscam.json'


    ########################## DEMO
    from os import walk

    ut_df_path = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ut-tplink-demo/ut-tplink-demo_mrt_transitions_dfs/'
    ut_demo_df = [x[2] for x in walk(ut_df_path)][0][0]
    ut_tplink_plug_mrt_feed_demo = ut_df_path + ut_demo_df
    print(ut_tplink_plug_mrt_feed_demo)
    
    tue_df_path = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/tue-tplink-demo/tue-tplink-demo_mrt_transitions_dfs/'
    tue_demo_df = [x[2] for x in walk(tue_df_path)][0][0]
    tue_tplink_plug_mrt_feed_demo = tue_df_path + tue_demo_df
    print(tue_tplink_plug_mrt_feed_demo)

    mrt_f_ut_tplink_demo = MRTFeed(ut_tplink_plug_metadata, ut_tplink_plug_mrt_feed_demo)
    mrt_f_tue_tplink_demo = MRTFeed(tue_tplink_plug_metadata, tue_tplink_plug_mrt_feed_demo)

    ########################## Experiment 1
    ut_tplink_plug_mrt_feed_exp1 = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ut-tplink-plug/ut-tplink-plug_mrt_transitions_dfs/clusters_evols_20211119_14-14-38_ut-tplink-plug.csv'
    tue_tplink_plug_mrt_feed_exp1 = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/tue-tplink-plug/tue-tplink-plug_mrt_transitions_dfs/clusters_evols_20211119_14-15-57_tue-tplink-plug.csv'
    ut_wansview_mrt_feed_exp1 = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ut-wansview-cam-exp1/ut-wansview-cam-exp1_mrt_transitions_dfs/clusters_evols_20211120_12-40-51_ut-wansview-cam-exp1.csv'
    tue_foscam_mrt_feed_exp1 = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/tue-foscam-cam-exp1/tue-foscam-cam-exp1_mrt_transitions_dfs/clusters_evols_20211120_12-41-41_tue-foscam-cam-exp1.csv'

    # Feeds
    mrt_f_ut_tplink_1 = MRTFeed(ut_tplink_plug_metadata, ut_tplink_plug_mrt_feed_exp1)
    mrt_f_tue_tplink_1 = MRTFeed(tue_tplink_plug_metadata, tue_tplink_plug_mrt_feed_exp1)
    mrt_f_ut_wansview_1 = MRTFeed(ut_wansview_cam_metadata, ut_wansview_mrt_feed_exp1)
    mrt_f_tue_foscam_1 = MRTFeed(tue_foscam_cam_metadata, tue_foscam_mrt_feed_exp1)

    ########################## Experiment 2
    ut_wansview_mrt_feed_exp2 = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ut-wansview-cam-exp2/ut-wansview-cam-exp2_mrt_transitions_dfs/clusters_evols_20211119_17-30-00_ut-wansview-cam-exp2.csv'
    # NOTE: *trimmed*
    tue_tplink_plug_mrt_feed_exp2 = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/tue-tplink-plug-exp2/tue-tplink-plug-exp2_mrt_transitions_dfs/clusters_evols_20211119_17-30-49_tue-tplink-plug-exp2.csv'
    # NOTE: *trimmed*
    tue_foscam_cam_mrt_feed_exp2 = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/tue-foscam-cam-exp2/tue-foscam-cam-exp2_mrt_transitions_dfs/clusters_evols_20211122_10-54-51_tue-foscam-cam-exp2.csv'
    ut_tplink_plug_mrt_feed_exp2 = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ut-tplink-plug-exp2/ut-tplink-plug-exp2_mrt_transitions_dfs/clusters_evols_20211122_11-12-40_ut-tplink-plug-exp2.csv'
    
    # Feeds
    mrt_f_ut_wansview_2 = MRTFeed(ut_wansview_cam_metadata, ut_wansview_mrt_feed_exp2)
    mrt_f_tue_tplink_2 = MRTFeed(tue_tplink_plug_metadata, tue_tplink_plug_mrt_feed_exp2)
    mrt_f_ut_tplink_2 = MRTFeed(ut_tplink_plug_metadata, ut_tplink_plug_mrt_feed_exp2)
    mrt_f_tue_foscam_2 = MRTFeed(tue_foscam_cam_metadata, tue_foscam_cam_mrt_feed_exp2)

    ########################## Experiment 2b
    ut_wansview_mrt_feed_exp2b = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ut-wansview-cam-exp2b/ut-wansview-cam-exp2b_mrt_transitions_dfs/clusters_evols_20211124_10-05-51_ut-wansview-cam-exp2.csv'
    tue_tplink_plug_mrt_feed_exp2b = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/tue-tplink-plug-exp2b/tue-tplink-plug-exp2b_mrt_transitions_dfs/clusters_evols_20211123_17-31-19_tue-tplink-plug-exp2.csv'
    #tue_foscam_cam_mrt_feed_exp2b = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/tue-foscam-cam-exp2b/tue-foscam-cam-exp2b_mrt_transitions_dfs/'
    #ut_tplink_plug_mrt_feed_exp2b = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ut-tplink-plug-exp2b/ut-tplink-plug-exp2b_mrt_transitions_dfs/'
    
    # Feeds
    mrt_f_ut_wansview_2b = MRTFeed(ut_wansview_cam_metadata, ut_wansview_mrt_feed_exp2b)
    mrt_f_tue_tplink_2b = MRTFeed(tue_tplink_plug_metadata, tue_tplink_plug_mrt_feed_exp2b)
    #mrt_f_ut_tplink_2b = MRTFeed(ut_tplink_plug_metadata, ut_tplink_plug_mrt_feed_exp2b)
    #mrt_f_tue_foscam_2b = MRTFeed(tue_foscam_cam_metadata, tue_foscam_cam_mrt_feed_exp2b)



    ########################## Experiment 3 (UT wansview and TUe foscam attacked)
    ut_wansview_mrt_feed_exp3 = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ut-wansview-cam-exp3/ut-wansview-cam-exp3_mrt_transitions_dfs/clusters_evols_20211124_11-33-24_ut-wansview-cam-exp3.csv'
    tue_foscam_mrt_feed_exp3 = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/tue-foscam-cam-exp3/tue-foscam-cam-exp3_mrt_transitions_dfs/clusters_evols_20211124_11-33-56_tue-foscam-cam-exp3.csv'
    ut_tplink_mrt_feed_exp3 = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ut-tplink-plug-exp3/ut-tplink-plug-exp3_mrt_transitions_dfs/clusters_evols_20211124_11-58-33_ut-tplink-plug-exp3.csv'
    tue_tplink_mrt_feed_exp3 = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/tue-tplink-plug-exp3/tue-tplink-plug-exp3_mrt_transitions_dfs/clusters_evols_20211124_11-58-55_tue-tplink-plug-exp3.csv'

    mrt_f_ut_wansview_3 = MRTFeed(ut_wansview_cam_metadata, ut_wansview_mrt_feed_exp3)
    mrt_f_tue_foscam_3 = MRTFeed(tue_foscam_cam_metadata, tue_foscam_mrt_feed_exp3)
    mrt_f_ut_tplink_3 = MRTFeed(ut_tplink_plug_metadata, ut_tplink_mrt_feed_exp3)
    mrt_f_tue_tplink_3 = MRTFeed(tue_tplink_plug_metadata, tue_tplink_mrt_feed_exp3)

    ########################## Experiment 4 (Only UT attacked)
    ut_wansview_mrt_feed_exp4 = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ut-wansview-cam-exp4/ut-wansview-cam-exp4_mrt_transitions_dfs/clusters_evols_20211124_12-25-08_ut-wansview-cam-exp4.csv'
    ut_tplink_mrt_feed_exp4 = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ut-tplink-plug-exp4/ut-tplink-plug-exp4_mrt_transitions_dfs/clusters_evols_20211124_12-33-14_ut-tplink-plug-exp4.csv'

    mrt_f_ut_wansview_4 = MRTFeed(ut_wansview_cam_metadata, ut_wansview_mrt_feed_exp4)
    mrt_f_ut_tplink_4 = MRTFeed(ut_tplink_plug_metadata, ut_tplink_mrt_feed_exp4)

    ########################## Experiment 4bis (no attacks to UT) TODO RERUN
    ut_tplink_mrt_feed_exp4bis = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ut-tplink-plug-exp4bis/ut-tplink-plug-exp4bis_mrt_transitions_dfs/clusters_evols_20211124_12-47-36_ut-tplink-plug-exp4bis.csv'
    ut_wansview_mrt_feed_exp4bis = '/Users/lucamrgs/Desktop/My_Office/TNO/Dev/thesis-luca-morgese/outputs/ut-wansview-cam-exp4bis/ut-wansview-cam-exp4bis_mrt_transitions_dfs/clusters_evols_20211124_12-35-04_ut-wansview-cam-exp4bis.csv'

    mrt_f_ut_tplink_4bis = MRTFeed(ut_tplink_plug_metadata, ut_tplink_mrt_feed_exp4bis)
    mrt_f_ut_wansview_4bis = MRTFeed(ut_wansview_cam_metadata, ut_wansview_mrt_feed_exp4bis)





    ########################## RESULTS RUNS
    mrta_d = MRTADashboard()
    
    # DEMO
    #mrta_d.populate([mrt_f_ut_tplink_demo, mrt_f_tue_tplink_demo])

    # PRE-FINAL Experiments
    #mrta_d.populate([mrt_ezviz_pf_ord, mrt_nugu_pf_ord])
    #mrta_d.populate([mrt_ezviz_pf_diff, mrt_nugu_pf_diff])

    # Experiment 1
    #mrta_d.populate([mrt_f_ut_tplink_1, mrt_f_tue_tplink_1])
    #mrta_d.populate([mrt_f_ut_wansview_1, mrt_f_tue_foscam_1])
    #mrta_d.populate([mrt_f_ut_tplink_1, mrt_f_tue_tplink_1, mrt_f_ut_wansview_1, mrt_f_tue_foscam_1])

    # Experiment 2
    #mrta_d.populate([mrt_f_ut_wansview_2, mrt_f_tue_tplink_2]) # attacked
    #mrta_d.populate([mrt_f_ut_tplink_2, mrt_f_tue_foscam_2]) # non-attacked
    #mrta_d.populate([mrt_f_ut_wansview_2, mrt_f_tue_tplink_2, mrt_f_ut_tplink_2, mrt_f_tue_foscam_2]) # all
    # Experiment 2b
    #mrta_d.populate([mrt_f_ut_wansview_2b, mrt_f_tue_tplink_2b]) # attacked
    #mrta_d.populate([mrt_f_ut_tplink_2b, mrt_f_tue_foscam_2b]) # non-attacked
    #mrta_d.populate([mrt_f_ut_wansview_2b, mrt_f_tue_tplink_2b, mrt_f_ut_tplink_2, mrt_f_tue_foscam_2]) # all
    
    # Experiment 3
    #mrta_d.populate([mrt_f_ut_wansview_3, mrt_f_tue_foscam_3])
    #mrta_d.populate([mrt_f_ut_tplink_3, mrt_f_tue_tplink_3])
    #mrta_d.populate([mrt_f_ut_wansview_3, mrt_f_tue_foscam_3, mrt_f_ut_tplink_3, mrt_f_tue_tplink_3])

    # Experiment 4
    #mrta_d.populate([mrt_f_ut_tplink_4, mrt_f_ut_wansview_4])
    # Experiment 4bis
    #mrta_d.populate([mrt_f_ut_tplink_4bis, mrt_f_ut_wansview_4bis])
    mrta_d.populate([mrt_f_ut_tplink_4, mrt_f_ut_wansview_4, mrt_f_ut_tplink_4bis, mrt_f_ut_wansview_4bis])

    

    mrta_d.total_avg_corr()
    
    
    if dim == 'mono':
        mrta_d.plot_monodim_metric('clusters_balance')
        mrta_d.plot_monodim_metric('noise_balance')
        mrta_d.plot_monodim_metric('all_dists_avg')
        mrta_d.plot_monodim_metric('all_dists_std')

        mrta_d.plot_monodim_metric('mutual_matches_n')
        mrta_d.plot_monodim_metric('mutual_matches_percentage')
        
        mrta_d.plot_monodim_metric('fwd_matches_n')
        mrta_d.plot_monodim_metric('fwd_matches_percentage')
        mrta_d.plot_monodim_metric('fwd_matches_agglomeration_avg')
        mrta_d.plot_monodim_metric('fwd_matches_agglomeration_std')
        mrta_d.plot_monodim_metric('fwd_matches_agglomeration_max')
        mrta_d.plot_monodim_metric('fwd_matches_agglomeration_max_percentage')
        
        mrta_d.plot_monodim_metric('bwd_matches_n')
        mrta_d.plot_monodim_metric('bwd_matches_percentage')
        mrta_d.plot_monodim_metric('bwd_matches_agglomeration_avg')
        mrta_d.plot_monodim_metric('bwd_matches_agglomeration_std')
        mrta_d.plot_monodim_metric('bwd_matches_agglomeration_max')
        mrta_d.plot_monodim_metric('bwd_matches_agglomeration_max_percentage')
    
    elif dim == 'monodim':
        mrta_d.plot_monodim_metric('clusters_balance')

        mrta_d.plot_monodim_metric('mutual_matches_n')
        mrta_d.plot_monodim_metric('mutual_matches_percentage')
        
        mrta_d.plot_monodim_metric('fwd_matches_n')
        mrta_d.plot_monodim_metric('fwd_matches_percentage')
        mrta_d.plot_monodim_metric('fwd_matches_agglomeration_avg')
        mrta_d.plot_monodim_metric('fwd_matches_agglomeration_std')
        mrta_d.plot_monodim_metric('fwd_matches_agglomeration_max')
        mrta_d.plot_monodim_metric('fwd_matches_agglomeration_max_percentage')
        
        mrta_d.plot_monodim_metric('bwd_matches_n')
        mrta_d.plot_monodim_metric('bwd_matches_percentage')
        mrta_d.plot_monodim_metric('bwd_matches_agglomeration_avg')
        mrta_d.plot_monodim_metric('bwd_matches_agglomeration_std')
        mrta_d.plot_monodim_metric('bwd_matches_agglomeration_max')
        mrta_d.plot_monodim_metric('bwd_matches_agglomeration_max_percentage')

    elif dim == 'multi':

        mrta_d.plot_multidim_metric('all_dists_deciles')
        mrta_d.plot_multidim_metric('mutual_vects_decile_5')
        
        mrta_d.plot_multidim_metric('mutual_vects_avg')
        mrta_d.plot_multidim_metric('mutual_vects_std')

        mrta_d.plot_multidim_metric('fwd_vects_avg')
        mrta_d.plot_multidim_metric('fwd_vects_std')

        mrta_d.plot_multidim_metric('bwd_vects_avg')
        mrta_d.plot_multidim_metric('bwd_vects_std')

        for i in range(1, 10):
            mrta_d.plot_multidim_metric('mutual_vects_decile_' + str(i))
            mrta_d.plot_multidim_metric('fwd_vects_decile_' + str(i))
            mrta_d.plot_multidim_metric('bwd_vects_decile_' + str(i))
    else:
        raise ValueError(f'>>> ERROR: Check dim parameter when directly calling this script.')