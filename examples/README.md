# MUDscope example
This directory provides the example script `example.sh` on how to use mudscope together with sample configuration files (`config/`) and a small sample dataset (`data/`).
Here, we explain the different steps taken in the example script and how they correspond to the inner workings of MUDscope. When running `example.sh` all resulting files will be stored in a new `result/` directory.

## Generate MUD profiles
MUDscope requires MUD profiles to detect disallowed traffic in pcap files. Therefore, we first have to obtain MUD profiles for the given devices. When these devices are provided by a manufacturer, this step is not necessary. However, for this example, we will automatically generate MUD profiles using [MUDgee](https://github.com/ayyoob/mudgee). This can be done by running mudscope in the `mudgen` mode:

```bash
# UT trace
python3 -m mudscope mudgen \
    --config config/mudgen/ut-tplink.json

# TUe trace
python3 -m mudscope mudgen \
    --config config/mudgen/tue-tplink.json
```
Where:
 - `--config`: path to `mudgen.json` file containing the configuration on how MUDgee should run.

## Filter PCAP based on MUD profile
Next, we use the MUD profiles generated in the previous step to filter traffic from pcap files based on the MUD profile. To this end, we run mudscope in the `reject` mode:

```bash
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
```
Where:
 - `--config`: path(s) to configuration file(s) from which to generate rejected traffic.
 - `--rules`: path rule.csv file generated in step 1.
 - `--output`: output directory in which to store rejected traffic.

## Create NetFlows based on MUD-rejected traffic (MRT) pcaps.
After filtering out the rejected traffic, this traffic is still in `.pcap` format. MUDscope requires NetFlows, and thus we have to extract all netflows from the generated pcap files using MUDscope's `flows_gen` mode:

```bash
# UT traces
python3 -m mudscope flows_gen \
    --input result/rejected/ut-tplink/ \
    --output result/netflows/rejected/ut-tplink/

# TUe traces
python3 -m mudscope flows_gen \
    --input result/rejected/tue-tplink/ \
    --output result/netflows/rejected/tue-tplink/
```
Where:
 - `--input`: directory containing all MRT pcap files. Output of step 2 
 - `--output`: directory in which to store output NetFlows.

### Create Dataset Scaling Reference (DSR)
For our next analyses, we will have to scaling various features to allow for better clustering. To this end, we require a sample dataset (DSR) that we can use to adjust our scaling mechanism. We create this dataset from benign data by first creating netflows from the benign data:

```bash
python3 -m mudscope.device_mrt_pcaps_to_csv \
    data/benign/ \
    --outdir result/netflows/benign/
```

And then transform these netflows to a DSR-accepted format:

```bash
python3 -m mudscope.scale_reference_df_script \
    result/netflows/benign/benign-custom-format-CLN.csv
```

## Characterize NetFlows using cluster methods
Next we create characterization files describing the different traffic clusters from the produced NetFlows. We use MUDscope's `analyze` mode in combination with the `mrta_characterize` action:

```bash
# UT traces
python3 -m mudscope analyze \
    --action mrta_characterize \
    --input result/netflows/rejected/ut-tplink/*-CLN.csv \
    --metadata config/characterization/ut_tplink.json \
    --dsr result/netflows/benign/benign-custom-format-CLN-SCALED.csv \
    --output result/characterization/ut-tplink/

# TUe traces
python3 -m mudscope analyze \
    --action mrta_characterize \
    --input result/netflows/rejected/tue-tplink/*-CLN.csv \
    --metadata config/characterization/tue_tplink.json \
    --dsr result/netflows/benign/benign-custom-format-CLN-SCALED.csv \
    --output result/characterization/tue-tplink/
```
Where:
 - `--action` gives the `mrta_characterize` action we want to take.
 - `--input` points to all netflow `.csv` files generated in the previous step.
 - `--metadata` is the path to the configuration file used for the analysis.
 - `--dsr` is the path to the DSR file produced in the previous step.
 - `--output` is the path to the output directory in which to store the output.

## Generate MRT feeds from characterisation files
After generating the characterization files, we can produce MRT feeds by comparing differences between subsequent files. For this, we use MUDscope's `analyze` mode in combination with the `device_mrt_evolution_datagen` action:

```bash
python3 -m mudscope analyze \
    --action device_mrt_evolution_datagen \
    --input result/characterization/ut-tplink/*.json \
    --output result/evolution/ut-tplink.csv

python3 -m mudscope analyze \
    --action device_mrt_evolution_datagen \
    --input result/characterization/tue-tplink/*.json \
    --output result/evolution/tue-tplink.csv
```
Where:
 - `--action` gives the `device_mrt_evolution_datagen` action we want to take.
 - `--input` points to all characterization files used to generate the MRT feed.
 - `--output` is the path to the output directory in which to store the output.

## Clean output
If you wish to remove all output, simply remove the `result/` directory or run `./example clean`.
