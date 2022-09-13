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
python3 -m mudscope mudgen \
    --config config/mudgen/ut-tplink.json

# TUe trace
python3 -m mudscope mudgen \
    --config config/mudgen/tue-tplink.json

# MUDgee stores its profiles in the result/ directory by default.
# We move everything to a separate mud_profiles folder within this 
# directory to create a clear result for each step of MUDscope.
mkdir result/mud_profiles/
mv result/tue-tplink-plug result/mud_profiles/
mv result/ut-tplink-plug result/mud_profiles/

# 2. Filter rejected traffic from malign pcap files
# UT traces
python3 -m mudscope reject \
    --config config/reject/ut-tplink/*.json \
    --rules result/mud_profiles/ut-tplink-plug/ut-tplink-plugrule.csv \
    --output result/rejected/

# TUe traces
python3 -m mudscope reject \
    --config config/reject/tue-tplink/*.json \
    --rules result/mud_profiles/tue-tplink-plug/tue-tplink-plugrule.csv \
    --output result/rejected/

# 3. Transform MUD-rejected traffic (MRT) pcaps into netflows
# UT traces
python3 -m mudscope netflows \
    --input result/rejected/ut-tplink/ \
    --output result/netflows/rejected/ut-tplink/

# TUe traces
python3 -m mudscope netflows \
    --input result/rejected/tue-tplink/ \
    --output result/netflows/rejected/tue-tplink/

# 3a. Transform benign pcaps into netflows
python3 -m mudscope.device_mrt_pcaps_to_csv \
    data/benign/ \
    --outdir result/netflows/benign/

# AUXILIARY STEP - Create dataset scaling reference (DSR)
python3 -m mudscope.scale_reference_df_script \
    result/netflows/benign/benign-custom-format-CLN.csv


# 4. Characterize NetFlows by performing clustering
# UT traces
python3 -m mudscope characterize \
    --input result/netflows/rejected/ut-tplink/*-CLN.csv \
    --metadata config/characterization/ut_tplink.json \
    --dsr result/netflows/benign/benign-custom-format-CLN-SCALED.csv \
    --output result/characterization/ut-tplink/

# TUe traces
python3 -m mudscope characterize \
    --input result/netflows/rejected/tue-tplink/*-CLN.csv \
    --metadata config/characterization/tue_tplink.json \
    --dsr result/netflows/benign/benign-custom-format-CLN-SCALED.csv \
    --output result/characterization/tue-tplink/


# 5. Analyze characterizations to generate MRT feeds
python3 -m mudscope evolution \
    --input result/characterization/ut-tplink/*.json \
    --output result/evolution/ut-tplink.csv

python3 -m mudscope evolution \
    --input result/characterization/tue-tplink/*.json \
    --output result/evolution/tue-tplink.csv


# 6. Monitor changes in MRT feeds
python3 -m mudscope monitor \
    --config config/monitor/tplink.json \
    --output result/monitor/