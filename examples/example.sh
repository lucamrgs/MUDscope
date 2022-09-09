#!/bin/bash

# Clean script
# Usage: ./example.sh clean
# Deletes all files generated when running ./example.sh
if [ "$1" == "clean" ]; then
    # Remove result directory
    rm -rf result/

    # Exit
    exit
fi

# Create output directory
mkdir result

# 1. Create MUD profile from benign data traces
# UT trace
python3 -m mudscope --mode mudgen \
    --mudgen_config config/mudgen/ut-tplink.json

# TUe trace
python3 -m mudscope --mode mudgen \
    --mudgen_config config/mudgen/tue-tplink.json

# MUDgee stores its profiles in the result/ directory by default.
# We move everything to a separate mud_profiles folder within this 
# directory to create a clear result for each step of MUDscope.
mkdir result/mud_profiles/
mv result/tue-tplink-plug result/mud_profiles/
mv result/ut-tplink-plug result/mud_profiles/

# 2. Filter rejected traffic from malign pcap files
# UT traces
python3 -m mudscope --mode reject \
    --reject_mud_rules result/mud_profiles/ut-tplink-plug/ut-tplink-plugrule.csv \
    --reject_config config/reject/ut-tplink/*.json \
    --reject_to_named_dir result/rejected/

# TUe traces
python3 -m mudscope --mode reject \
    --reject_mud_rules result/mud_profiles/tue-tplink-plug/tue-tplink-plugrule.csv \
    --reject_config config/reject/tue-tplink/*.json \
    --reject_to_named_dir result/rejected/

# 3. Transform MUD-rejected traffic (MRT) pcaps into netflows
# UT traces
python3 -m mudscope --mode flows_gen \
    --flowsgen_tgt_dir result/rejected/ut-tplink/ \
    --flowsgen_outdir result/netflows/rejected/ut-tplink/

# TUe traces
python3 -m mudscope --mode flows_gen \
    --flowsgen_tgt_dir result/rejected/tue-tplink/ \
    --flowsgen_outdir result/netflows/rejected/tue-tplink/

# 3a. Transform benign pcaps into netflows
python3 -m mudscope.device_mrt_pcaps_to_csv \
    data/benign/ \
    --outdir result/netflows/benign/

# AUXILIARY STEP - Create dataset scaling reference (DSR)
python3 -m mudscope.scale_reference_df_script \
    result/netflows/benign/benign-custom-format-CLN.csv


# 4. Analyze NetFlows to perform clustering
# UT traces
python3 -m mudscope --mode analyze \
    --analysis_action mrta_characterize \
    --analysis_tgt result/netflows/rejected/ut-tplink/*-CLN.csv \
    --analysis_capture_metadata config/characterization/ut_tplink.json \
    --dsr_path result/netflows/benign/benign-custom-format-CLN-SCALED.csv \
    --analysis_output result/characterization/ut-tplink/

# TUe traces
python3 -m mudscope --mode analyze \
    --analysis_action mrta_characterize \
    --analysis_tgt result/netflows/rejected/tue-tplink/*-CLN.csv \
    --analysis_capture_metadata config/characterization/tue_tplink.json \
    --dsr_path result/netflows/benign/benign-custom-format-CLN-SCALED.csv \
    --analysis_output result/characterization/tue-tplink/


# 5. Analyze characterizations to generate MRT feeds
python3 -m mudscope --mode analyze \
    --analysis_action device_mrt_evolution_datagen \
    --analysis_tgt result/characterization/ut-tplink/*.json \
    --analysis_output result/evolution/ut-tplink.csv

python3 -m mudscope --mode analyze \
    --analysis_action device_mrt_evolution_datagen \
    --analysis_tgt result/characterization/tue-tplink/*.json \
    --analysis_output result/evolution/tue-tplink.csv

# python3 -m mudscope.MRTADashboard \
#     demo \
#     clusters_balance,all_dists_avg,mutual_matches_n,mutual_matches_percentage,fwd_matches_n,fwd_matches_percentage,bwd_matches_n,bwd_matches_percentage
