#!/bin/bash

# Clean script
# Usage: ./example.sh clean
# Deletes all files generated when running ./example.sh
if [ "$1" == "clean" ]; then
    # Remove generated MUD profiles
    rm -rf result/

    # Remove MRT files
    rm -rf rejected/

    # Remove netflow files
    rm -rf netflows/

    # Remove analyses
    rm -rf analysis/

    # Exit
    exit
fi

# 1. Create MUD profile from benign data traces
# UT trace
python3 -m mudscope --mode mudgen \
    --mudgen_config config/mudgen/ut-tplink.json

# TUe trace
python3 -m mudscope --mode mudgen \
    --mudgen_config config/mudgen/tue-tplink.json


# 2. Filter rejected traffic from malign pcap files
# UT traces
python3 -m mudscope --mode reject \
    --reject_mud_rules result/ut-tplink-plug/ut-tplink-plugrule.csv \
    --reject_config config/reject/ut-tplink/*.json \
    --reject_to_named_dir rejected/

# TUe traces
python3 -m mudscope --mode reject \
    --reject_mud_rules result/tue-tplink-plug/tue-tplink-plugrule.csv \
    --reject_config config/reject/tue-tplink/*.json \
    --reject_to_named_dir rejected/


# 3. Transform MUD-rejected traffic (MRT) pcaps into netflows
# UT traces
python3 -m mudscope --mode flows_gen \
    --flowsgen_tgt_dir rejected/ut-tplink/ \
    --flowsgen_outdir netflows/ut-tplink/rejected/

# TUe traces
python3 -m mudscope --mode flows_gen \
    --flowsgen_tgt_dir rejected/tue-tplink/ \
    --flowsgen_outdir netflows/tue-tplink/rejected/

# 3a. Transform benign pcaps into netflows
python3 -m mudscope.device_mrt_pcaps_to_csv \
    data/benign/ \
    --outdir netflows/benign/

# AUXILIARY STEP - Create dataset scaling reference (DSR)
python3 -m mudscope.scale_reference_df_script \
    netflows/benign/benign-custom-format-CLN.csv


# 4. Analyze NetFlows to perform clustering
# UT traces
python3 -m mudscope --mode analyze \
    --analysis_action mrta_characterize \
    --analysis_tgt netflows/ut-tplink/rejected/*-CLN.csv \
    --analysis_devname ut-tplink \
    --analysis_capture_metadata config/characterization/ut_tplink.json \
    --dsr_path netflows/benign/benign-custom-format-CLN-SCALED.csv \
    --analysis_output analysis/characterization/ut-tplink/

# TUe traces
python3 -m mudscope --mode analyze \
    --analysis_action mrta_characterize \
    --analysis_tgt netflows/tue-tplink/rejected/*-CLN.csv \
    --analysis_devname tue-tplink \
    --analysis_capture_metadata config/characterization/tue_tplink.json \
    --dsr_path netflows/benign/benign-custom-format-CLN-SCALED.csv \
    --analysis_output analysis/characterization/tue-tplink/


# 5. Analyze characterizations to generate MRT feeds
python3 -m mudscope --mode analyze \
    --analysis_action device_mrt_evolution_datagen \
    --analysis_tgt analysis/characterization/ut-tplink/*.json \
    --analysis_devname ut-tplink \
    --analysis_output analysis/evolution/ut-tplink.csv

python3 -m mudscope --mode analyze \
    --analysis_action device_mrt_evolution_datagen \
    --analysis_tgt analysis/characterization/tue-tplink/*.json \
    --analysis_devname tue-tplink \
    --analysis_output analysis/evolution/tue-tplink.csv
