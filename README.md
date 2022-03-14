# nw_ds_reader


**Description**

This program generates a MUD profile using MUDgee tool, filters out packets that do not abide by MUD rules from a PCAP capture, and characterizes the rejected traffic to isolate network events, and observe their evolution, as detected by 'MUD enforcers'. The core idea of this project is to use MUD enforcers as a specification-based and consistent IDS across deployments, to provide for a distributed Network Telescope for IoT-related traffic.

This project is currently MUDgee-based and PCAP-based. Each invocation is to be referred to a single device. The final outcome of the pipeline that this software implements shall instead compare outputs across two or more devices.

The pipeline works throuhg these steps:
1. generates a MUD profile for a device, from pcap captures containing beningn traffic (uses MUDgee (Hamza et al., 2018) as of current implementation);
2. produces MUD-rejected traffic (referred as _MRT_) from pcap captures interesting a specific device - referring to a specific time window;
3. produces a custom NetFlow CSV dataset file of bi-directional flows of such rejected traffic;
4. performs hierarchical clustering (characterization) of these flows to discern the connection types of MUD-rejected traffic;
5. produces dataset entries that describe the evolution of so-produced clusters - thus network/connection events - across pairwise comparison of MUD-rejected traffic per given time windows.
6. compares multiple MUD-rejected traffic description datasets from two or more devices to provide insights on how anomalous activities affect the selected devices.

Below, the documentation for the executable files and usage of this software is provided.

In Usage sample pipeline, the whole sequence of commands to execute the pipeline is exemplified.

NOTEs:
    - This project has been developed on the IEEE-Dataport IoT Network Intrusion Dataset (https://ieee-dataport.org/open-access/iot-network-intrusion-dataset), by Kang et al.
    - I make use of the MUDgee project Github repository to generate MUD profiles (https://github.com/ayyoob/mudgee/tree/f63a88de84bb9d402b7b214bea2944a534c6c555) by Hamza et al.


**Requisites**

- Docker


**Installation**

1. Download the repository and navigate to folder.
2. Run ``docker run --name mudscope -w /mudscope -v "$(pwd):/mudscope" python:3.9-bullseye sh -c "pip3 install --no-cache-dir -r requirements.txt && tail -f /dev/null"``. This will start a docker container hosting the application, binding a volume to the MUDscope directory.
3. Run ``docker exec -it mudscope \bin\bash``. This will open a terminal window to the environment where the code is ready to be run.

NOTE: Place input files in the ``input`` folder in the MUDscope directory.

5. Exit the terminal with ``exit`` when done
6. Run ``docker rm -f mudscope`` to stop and remove the project image


**Usage Documentation**

NOTE: change system path constant as indicated in ``src/constants.py`` to local repo/files locations.


``python run.py``

``--pcap_limit``: if set to an integer, limits the number of packets processed in 'reject' mode to the one indicated.

``--mode`` 

- ``mudgen`` : generates MUD data using MUDgee
    - ``--mudgen_config`` : name of json file in /mudgen_configs on which MUD profile and filtering rules are created

- ``reject`` : returns packets filtered from a pcap file by a virtual MUD enforcer
    - ``--reject_config`` : path to reject config file of reference OR folder containing a set of reject config files - config files contain device info and gateway MAC addresses related to filtering, and pcap to filter
        * IF reject_config is a file, a MRT pcap is output at folder for specified device
        * ELIF reject_config is a folder to reject config files, the program iterates over these and output all respective MRT pcaps
    - ``--reject_mud_rules`` : relative path to filtering rules (just CSV OpenFlow rules output by MUDgee currently supported)
    - ``--reject_to_named_dir`` : OPTIONAL - name (not path! just name) of the directory that will be created in the device's folder, and where the reject outputs will be saved. The directory in the device's folder will be named <devname>[provided parameter].
    - ``--reject_online_interface`` : DISCONTINUED AS OF NOW - name of the local interface on which the program will sniff the traffic with scapy (run ``ifconfig`` to find local interafaces)

- ``flows_gen``
    - ``--flowsgen_tgt_dir`` : path to directory containing the MUD-rejected traffic pcap files produced with ``run.py --mode reject ...``

- ``analyze``
    - ``--analysis_tgt`` : full or relative path to (a) pcap or (b) json or (c) csv or (d) directory - as below specified:
        (a) rejected packets obtained with "reject" mode (specify ``outputs/<devname>/<capture-rejected.pcap>``),
        (b) rejected packets register obtained with "reject" mode (specify ``outputs/<devname>/<capture-rejected.json>``),
        (c) NetFlow CSV file of rejected flows, obtained with ``--mode flows_gen ...``,
        (d) directory containing characterization files for a device, obtained with "mrta_characterize" analysis action. (Specify ``outputs/<devname>/mrt_characterizations/>``)
    - ``--analysis_devname`` : name of the device for which traffic was filtered, needed to reference the correct output location
    - ``--analysis_action`` : analysis action to perform. Can be one of 
            * For pcaps only
            - ``packets_csv`` : outputs a csv version of the pcap capture
            - ``filter_known_providers`` : outputs a filtered pcap file where there are no packets outgoing or incoming to IP ranges known to be of notorious third party providers (e.g., Google, Amazon, Microsoft)
            * For pcaps and json registers
            - ``ips_flow_graphs`` : produces a graph showing how many flows are associated to each IP address in the capture
            - ``ips_map`` : produces a map using Folium, pinning the locations and volumes of src and dst IPs on a global map
            - ``ports_flow_graphs`` : produces a graph showing how many flows are associated to each port/service detected in the capture
            * For NetFlow flows CSV file
            - ``mrta_characterize`` : produces a ch_ file, containing the clustering output and statistical descriptors of the flows per-cluster, over the NetFlow bidirectional flows CSV file, produced by ``device_mrt_pcaps_to_csv.py``
            * For ``mrt_characterizations`` directories
            - ``device_mrt_evolution_datagen`` : generates a dataframe and related CSV file listing the entries of the evolution of flow clusters over the MUD-rejected traffic concerning one device. It does so by ordering the related characterization files chronologically over the datetime of the first flow processed by each characterization file - then computes two-by-two pairwise transition entries
    If analysis_action is ``mrta_characterize``, the following parameter is needed:
    - ``--analysis_capture_metadata`` : name of json file (to be located in configs/characterization_datas/ directory) that contains the intended metadata information for the deployment and device. NOTE: it has to abide by a specific format, as its values are directly accessed by the code.

- ``monitor``
    - ``--mrtfeeds_config`` : path to json file listing the set of MRT feeds and associated device metadata to compare. An example can be found in configs/monitor_configs/monitor_test.json
    - ``--monitor_features`` : list of features on which mrt feeds are compared. To be provided as a single string, where features are divided by comma (,). E.g.: --monitor_features feature1,feature2. Available/suggested features are: clusters_balance;
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
    bwd_matches_agglomeration_max


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
    --monitor_features <feature1_name>,<feature2_name>,... [example: all_dists_avg,mutual_matches_n,mutual_matches_percentage]
