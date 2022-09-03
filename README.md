# MUDscope


**Description**

This software is of the publication [stepping out of the MUD: contextual network threat information for IoT devices from manufacturer-provided behaviour profiles, Zangrandi et al.]

This program generates a MUD profile (IETF RFC 8520: https://datatracker.ietf.org/doc/rfc8520/) using MUDgee tool (https://github.com/ayyoob/mudgee), and filters out packets that do not abide by MUD rules from a PCAP capture. It characterizes MUD-rejected traffic (MRT) to isolate network events, and observe their evolution. The core idea of this project is to use a generic MUD enforcer as a distributed Network Telescope for IoT-related traffic, starting from using MUD as specification-based and consistent IDS across deployments.

This project currently is PCAP-based and operates on a device-specific basis to generate MUD-rejected traffic analyses.

The pipeline works throuhg these steps:
1. generates a MUD profile for a device, from pcap captures containing beningn traffic (uses MUDgee (Hamza et al., 2018) as of current implementation);
2. produces MUD-rejected traffic (referred as _MRT_) from pcap captures interesting a specific device *on a time-window basis*;
3. produces a custom NetFlow CSV dataset file of bi-directional flows of such rejected traffic;
4. performs hierarchical clustering (with HDBSCAN: https://hdbscan.readthedocs.io/en/latest/how_hdbscan_works.html) of MUD-rejected flows at each time window to discern the connection types of MUD-rejected traffic;
5. produces dataset entries that describe the evolution of so-produced clusters - thus network/connection events across each two consecutive MUD-rejected traffic time windows. This is performed across multiple consecutive characterisation. This produces a MUD-rejected traffic feed.
6. Compares multiple MUD-rejected traffic feeds from two or more devices to provide insights on how and what similar/dissimilar anomalous activities affect the selected devices.

Below, the documentation for the executable files and usage of this software is provided.

In Usage sample pipeline, the whole sequence of commands to execute the pipeline is exemplified.

# Documentation

## Requisites

- python 3.9+
- MUDgee requirements: at https://github.com/ayyoob/mudgee:
    - LibPcap (install tcpdump)
```sh
    Linux: ``apt-get install tcpdump''
    OSX: readily available by default.
    Windows: follow instructions at: https://nmap.org/npcap/
```
    - Maven
```sh
    Follow instructions at: https://www.baeldung.com/install-maven-on-windows-linux-mac for installation.
```
- editcap (https://www.wireshark.org/docs/man-pages/editcap.html)


## Installation

1. Clone code to repo
2. Make sure that BASE_DIR constant in src/Constants.py points to correct directory
3. pip3 install -r requirements.txt


## Main usage (suggested)

``python run.py <arguments>``

``--pcap_limit``: if set to an integer, limits the number of packets processed in 'reject' mode to the one indicated.

``--mode mudgen`` : generates MUD data using MUDgee
``--mudgen_config <json_file_name>`` : name of json file in /mudgen_configs on which MUD profile and filtering rules are created
OUTPUT: a folder in /mudscope/result/ containing device-specific MUD profile and derived OF rules.

To use MUDscope meaningfully as of its current implementation, it is expected to consume a folder containing pcap files, resulting from a subdivision for a bigger capture. These pcap files will represent the *time-windows* on the basis of which traffic is characterised, and its evolution is recorded. Time-based subdivision of a pcap can be achieved with the tool and command:
``editcap -i <60> path/to/input.pcap path/to/output.pcap``splits a pcap file into smaller files each containing traffic for ``-i`` seconds, outputting all generated files to the specified path. Refer to:
- https://serverfault.com/questions/131872/how-to-split-a-pcap-file-into-a-set-of-smaller-ones
- https://www.wireshark.org/docs/man-pages/editcap.html

After generating the MUD and related rules for a device, add reject_config files for the device, specifying network addresses and pcap capture to process with MUDscope, at: configs/reject_configs/{devname}/{session}/'. Where 'session' is used to group together reject_configs for multiple devices of which MRT traffic shall be compared. A reject_config shall be generated with the script
``src/generate_rjt_config``.
Use of this script is suggested as it automatically generates multiple reject_configs referred to multiple (time-window) pcap files located in a directory, for instance the one used with ``editcap``. See script code directly, or run ``python3 src/generate_rjt_config.py -h`` to consult usage.

Finally, to characterise traffic, the tool translates pcaps to bi-directional flows, and scales their features. To do this, a dataset scaling reference (DSR) is needed. A DSR shall be created from a single pcap file with normal (benign) network activity. It does not need to be deployment specific, and there are no length requirements. A 1 hour-long capture obtained from sniffing the network traffic of the deployment, while using the devices present therein, should work well. Of course, the longer and more exaustive, the better.

A dataset scaling references can be obtained with the following scripts, present in this project (src folder):

- device_mrt_pcaps_to_csv.py: transforms a pcap file to a bi-directional flows CSV file.
- scale_reference_df_script.py: performs some pre-processing and scaling of flow features.

With the generated device MUD data, reject configurations, and DSR, the whole pipeline up to generation of the MRT Feed can be run with the following script.

``mudscope.py <arguments>``
- ``--devname <name>`` : name that was assigned to the device through mudgen_config file. This name will also be used to generate all related folders and outputs.
- ``--analysis_capture_metadata <json_file_name>`` : name of json file (to be located in configs/characterization_datas/ directory) that contains the intended metadata information for the deployment and device. NOTE: it has to abide by a specific format, as its values are directly accessed by the code. See examples in indicated folder.
- ``--dsr_path <path/to/file.csv>`` : Dataset Scaler Reference path. Path to a CSV bi-directional flows file that will be taken as a reference for the scaling of flows values.
- ``--session <name>`: Used to fetch together reject_configs for a single device, and group together outputs for all devices assigned to the same analysis session.

A MUD-rejected traffic evolution feed will generated for the device, on the set of (time-consecutive) pcap files indicated.

To compare anomalous activities captured in MRTs for multiple devices, use again the ``run.py`` script, with the following argument:

- ``--mode monitor``
- ``--mrtfeeds_config <path/to/json_file>`` : path to json file listing the set of MRT feeds and associated device metadata to compare. In the file, also lists the features of the MRTfeeds to analyse for correlation. ``features_watch`` is the list of features on which mrt feeds are compared. To be provided as a single string, where features are divided by comma (,). E.g.: --monitor_features feature1,feature2. See examples in folder. Available/suggested features are:
    clusters_balance;
    all_dists_avg;
    mutual_matches_n;
    mutual_matches_percentage;
    fwd_matches_n;
    fwd_matches_percentage;
    fwd_matches_agglomeration_avg;
    fwd_matches_agglomeration_max;
    bwd_matches_n;
    bwd_matches_percentage;
    bwd_matches_agglomeration_avg;
    bwd_matches_agglomeration_max.
    An example can be found in configs/monitor_configs/monitor_test.json.
    The command outputs one plot per specified 'watch feature', for each of the devices specified in the mrtfeeds_config. Additionally, a log file is output where device-specific anomalies are shown, as well as pairwise matches of anomalous activities, if present.


## Alternative usage: fine-grained invocations

For a very fine-grained usage of the tool, below are listed the atomic commands that can be invoked, and related parameters, to run the pipeline.


- ``reject`` : returns packets filtered from a pcap file by a virtual MUD enforcer
    - ``--reject_config`` : path to reject config file of reference OR folder containing a set of reject config files - config files contain device info and gateway MAC addresses related to filtering, and pcap to filter
         IF reject_config is a file, a MRT pcap is output at folder for specified device
         ELIF reject_config is a folder to reject config files, the program iterates over these and output all respective MRT pcaps
    - ``--reject_mud_rules`` : relative path to filtering rules (just CSV OpenFlow rules output by MUDgee currently supported)
    - ``--reject_to_named_dir`` : OPTIONAL - name (not path! just name) of the directory that will be created in the device's folder, and where the reject outputs will be saved. The directory in the device's folder will be named <devname>[provided parameter].
    - ``--reject_online_interface`` : DISCONTINUED AS OF NOW - name of the local interface on which the program will sniff the traffic with scapy (run ``ifconfig`` to find local interafaces)

- ``flows_gen``
    - ``--flowsgen_tgt_dir`` : path to directory containing the MUD-rejected traffic pcap files produced with ``run.py --mode reject ...``

- ``analyze``
    - ``--analysis_tgt`` : full or relative path to (a) pcap or (b) json or (c) csv or (d) directory - as below specified:
        - (a) rejected packets obtained with "reject" mode (specify ``outputs/<devname>/<capture-rejected.pcap>``),
        - (b) rejected packets register obtained with "reject" mode (specify ``outputs/<devname>/<capture-rejected.json>``),
        - (c) NetFlow CSV file of rejected flows, obtained with ``--mode flows_gen ...``,
        - (d) directory containing characterization files for a device, obtained with "mrta_characterize" analysis action. (Specify ``outputs/<devname>/mrt_characterizations/>``)

    - ``--analysis_devname`` : name of the device for which traffic was filtered, needed to reference the correct output location
    - ``--analysis_action`` : analysis action to perform. Can be one of 
       
        For pcaps only
        - ``packets_csv`` : outputs a csv version of the pcap capture
        - ``filter_known_providers`` : outputs a filtered pcap file where there are no packets outgoing or incoming to IP ranges known to be of notorious third party providers (e.g., Google, Amazon, Microsoft).
    
        For pcaps and json registers
        - ``ips_flow_graphs`` : produces a graph showing how many flows are associated to each IP address in the capture
        - ``ips_map`` : produces a map using Folium, pinning the locations and volumes of src and dst IPs on a global map
        - ``ports_flow_graphs`` : produces a graph showing how many flows are associated to each port/service detected in the capture.
    
        For NetFlow flows CSV file
        - ``mrta_characterize`` : produces a ch_ file, containing the clustering output and statistical descriptors of the flows per-cluster, over the NetFlow bidirectional flows CSV file, produced by ``device_mrt_pcaps_to_csv.py``.
    
        For ``mrt_characterizations`` directories
        - ``device_mrt_evolution_datagen`` : generates a dataframe and related CSV file listing the entries of the evolution of flow clusters over the MUD-rejected traffic concerning one device. It does so by ordering the related characterization files chronologically over the datetime of the first flow processed by each characterization file - then computes two-by-two pairwise transition entries.
    
    If analysis_action is ``mrta_characterize``, the following parameter is needed:
    - ``--analysis_capture_metadata`` : name of json file (to be located in configs/characterization_datas/ directory) that contains the intended metadata information for the deployment and device. NOTE: it has to abide by a specific format, as its values are directly accessed by the code. See example in indicated directory.

- ``monitor``
    - ``--mrtfeeds_config`` : path to json file listing the set of MRT feeds and associated device metadata to compare. In the file, also lists the features of the MRTfeeds to analyse for correlation. ``features_watch`` is the list of features on which mrt feeds are compared. To be provided as a single string, where features are divided by comma (,). E.g.: --monitor_features feature1,feature2. See examples in folder. Available/suggested features are:
    clusters_balance;
    all_dists_avg;
    mutual_matches_n;
    mutual_matches_percentage;
    fwd_matches_n;
    fwd_matches_percentage;
    fwd_matches_agglomeration_avg;
    fwd_matches_agglomeration_max;
    bwd_matches_n;
    bwd_matches_percentage;
    bwd_matches_agglomeration_avg;
    bwd_matches_agglomeration_max.
    An example can be found in configs/monitor_configs/monitor_test.json.
    The command outputs one plot per specified 'watch feature', for each of the devices specified in the mrtfeeds_config. Additionally, a log file is output where device-specific anomalies are shown, as well as pairwise matches of anomalous activities, if present.


**Pipeline Usage Template**

1. \> run.py --mode mudgen 
    --mudgen_config [from ./configs/mudgen/]<mudgee_config_file_path>.json
    out \>\>\>
        result/<device_name> folder w/ MUD profile, CSV OF rules


2. \> run.py --mode reject 
    --reject_mud_rules <result/<device\>/<device\>rule.csv> [or any other CSV structured as OF switch rules] 
    --reject_config <reject_config_files_path/to/directory> OR <reject_config_file/path>.json
    [ --reject_online_interface <iface_name> [ALTERNATIVE to reject_config] - DISCONTINUED, FOR THE MOMENT ]
    --pcaps_limit OPTIONAL (use only if necessary. E.g., crashes...), limits the number of packets processed per-pcap. Example: <300000>
    out \>\>\> 
        outputs/<device_name>/
            <pcap_file_basename>-rejected.pcap,
            <pcap_file_basename>-rejected.json
        For each reject config file specified (either a single one, or those in the reject configs folder)


3. \> run.py --mode flows_gen
    --flowsgen_tgt_dir outputs/<device_name>/ [or any directory containing MRT PCAPS obtained with ``--mode reject``]
    out \>\>\>
        outputs/<device_name>/<device_name>-all-flows-csv/ : contains a CSV ending with ``-CLN.csv``, which is the main NetFlow bidirectional flows CSV file of interes.


4. \> run.py --mode analyze

    --analysis_tgt [as specified in Usage > 1 > mode analyze > analysis_tgt]
    --analysis_devname <device_name> [refers to the per-device folder where outputs are saved]
    --analysis_action mrta_characterize [device_mrt_evolution_datagen] [one of those specified in Usage > 1 > mode analyze > analysis_action]
    if the analysis action is ``mrta_characterize``:
    --analysis_capture_metadata [configs/characterization_datas/]<capture-metadata-file>.json
    out \>\>\>
        For pcaps and json registers actions, consult Usage > 1 > analysis action above
        For netflow csv file:
            outputs/<device_name>/<device_name>_mrt_characterizations/<ch_[datetime-when-generated]_[device_name]>.json
        For characterization files folder:
            outputs/<device_name>/<device_name>_mrt_transitions_df/<clusters_evols_[datetime-when-generated]_[device_name]>.csv


5. \> run.py --mode monitor
    --mrtfeeds_config configs/monitor_configs/<file>.json
