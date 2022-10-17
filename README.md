# MUDscope
This repository contains the code for MUDscope by the authors of the ACSAC 2022 paper "Stepping out of the MUD: Contextual threat information for IoT devices with manufacturer-provided behaviour profiles" [PDF](https://vm-thijs.ewi.utwente.nl/static/homepage/papers/mudscope.pdf) [1]. Please [cite](#References) MUDscope when using it in academic publications.

## Table of Contents

 * [Introduction](#introduction)
 * [Overview](#overview)
 * [Installation](#installation)
   * [Manual](#manual-installation)
   * [Dependencies](#dependencies)
 * [Usage](#usage)
   * [mudgen](#mudgen)
   * [reject](#reject)
   * [netflows](#netflows)
   * [characterize](#characterize)
   * [evolution](#evolution)
   * [monitor](#monitor)
 * [Dataset](#dataset)
 * [References](#references)
 

## Introduction
Besides coming with unprecedented benefits, the Internet of Things (IoT) suffers deficits in security measures, leading to attacks increas- ing every year. In particular, network environments such as smart homes lack managed security capabilities to detect IoT-related at- tacks; IoT devices hosted therein are thus more easily infiltrated by threats. As such, context awareness on IoT infections is hard to achieve, preventing prompt response. In this work, we propose MUDscope, an approach to monitor malicious network activities affecting IoT in real-world consumer environments. We leverage the recent Manufacturer Usage Description (MUD) specification, which defines networking whitelists for IoT devices in MUD pro- files, to reflect consistent and necessarily-anomalous activities from smart things. Our approach characterizes this traffic and extracts signatures for given attacks. By analyzing attack signatures for multiple devices, we gather insights into emerging attack patterns. We evaluate our approach on both an existing dataset, and a new openly available dataset created for this research. We show that MUDscope detects several attacks targeting IoT devices with an F1-score of 95.77% and correctly identifies signatures for specific attacks with an F1-score of 87.72%.

## Overview
The goal of MUDscope is to provide a distributed Network Telescope for IoT-related traffic that uses MUD enforcers as a specification-based IDS to consistently detect malicious network traffic across deployments.
To this end, we take the following steps:
1. Create MUD profiles for each monitored device. One can use MUD profiles provided by the IoT manufacturer. In this work, we automatically generate MUD profiles from benign IoT network traffic using [MUDgee](https://github.com/ayyoob/mudgee).
2. Filter IoT network traffic (pcap files) based on MUD profile, called MUD-rejected traffic (MRT).
3. Group filtered network traffic into NetFlows per device per time window.
4. Cluster NetFlows using [HDBSCAN](https://hdbscan.readthedocs.io/en/latest/how_hdbscan_works.html) to obtain groups of similar traffic (characterisations).
5. Compare characterisations of subsequent time windows to describe the evolution of MRT over time.
6. Compare MRT descriptions from multiple devices to provide insights on how anomalous activities affect the selected devices.

## Installation
The easiest way of installing MUDscope including all its dependencies is using our [Docker](https://www.docker.com/) container:

```bash
git clone https://github.com/lucamrgs/MUDscope.git  # Clone repository
cd MUDscope                                         # Change into MUDscope directory
docker build .                                      # Build docker container
docker container run -it <image> bash               # Run bash from within the built docker container, see Usage/examples for using MUDscope
```

### Manual installation
Alternatively, you can install MUDscope manually:
1. Clone our repository
```bash
git clone git@github.com:lucamrgs/MUDscope.git     # Using SSH
git clone https://github.com/lucamrgs/MUDscope.git # Using HTTPS
```
2. Make sure you have installed all [Dependencies](#Dependencies)
3. Install MUDscope as python tool:
```bash
pip3 install -e /path/to/directory/containing/mudscope/pyproject.toml/
```

### Dependencies
Please install the following dependencies to run MUDscope

- [python 3.8+](https://www.python.org/downloads/release/python-380/)
- [MUDgee](https://github.com/ayyoob/mudgee), additionally requires:
  - [java](https://www.oracle.com/java/technologies/downloads/)
  - [tcpdump](https://www.tcpdump.org/)
  - [Maven](https://maven.apache.org/)
- [editcap](https://www.wireshark.org/docs/man-pages/editcap.html)
- [nfpcapd](https://github.com/phaag/nfdump) v1.6.24, note that this binary should be compiled with the `--enable-nfpcapd` flag set

```bash
# Dependencies
sudo apt install libpcap-dev

# Installation
git clone https://github.com/phaag/nfdump.git # Clone nfdump directory
cd nfdump                                     # Change to nfdump directory
git checkout v1.6.24                          # Ensure we are working with v1.6.24
./autogen.sh                                  # Setup configuration
./configure --enable-nfpcapd                  # Build nfpcapd
make                                          # Make file
make install                                  # Make file
sudo cp ./bin/.libs/libnfdump-1.6.24.so /usr/lib/ # Because library does not install correctly
```

When all dependencies have been installed, make sure you have the correct python libraries installed by installing them from the `requirements.txt` file:
```bash
pip3 install -r requirements.txt
```

## Usage
Once MUDscope is installed, you can use the tool to execute the steps described in our paper.
To this end, MUDscope works in different `mode`s corresponding to the steps of our approach:

```bash
python3 -m mudscope <mode> [-h]
```

Which supports the following modes:
1. `mudgen`, creates MUD files from benign network traces.
2. `reject`, filters MUD rejected traffic from pcap files.
3. `netflows`, transforms MRT pcap files to NetFlows.
4. `characterize`, Perform characterization analysis on MRT netflows.
5. `evolution`, Perform evolution analysis on characterization files to produce MRT feeds.
6. `monitor`, Monitor and compare anomalous activities captured in MRT feeds.

```
usage: __main__.py [-h] {mudgen,reject,netflows,characterize,evolution,monitor} ...

MUDscope - Stepping out of the MUD: Contextual threat information for IoT devices with manufacturer-
provided behaviour profiles.

optional arguments:
  -h, --help            show this help message and exit

mode:
  Mode in which to run MUDscope.

  {mudgen,reject,netflows,characterize,evolution,monitor}
    mudgen              Create MUD files from benign network traces.
    reject              Filter MUD rejected traffic from pcap files.
    netflows            Transform MRT pcap files to NetFlows.
    characterize        Perform characterization analysis on MRT netflows.
    evolution           Perform evolution analysis on characterization files to produce MRT feeds.
    monitor             Monitor and compare anomalous activities captured in MRT feeds.
```

### mudgen
MUDscope enforces MUD profiles in pcap files to filter malicious traffic from these files. However, manufacturers often do not specify MUD profiles for their IoT devices. Therefore, we provide an easy interface to learn MUD profiles from a trace of benign network traffic of a device using the tool [MUDgee](https://github.com/ayyoob/mudgee). This mode takes a MUDgee `config` file as input and produces MUD profiles for network traces specified in this `config` file. See [MUDgee](https://github.com/ayyoob/mudgee) or one of our [examples](examples/) for the format of these `config` files.

```
usage: __main__.py mudgen [-h] --config <path>

Create MUD files from benign network traces.

optional arguments:
  -h, --help       show this help message and exit
  --config <path>  path to JSON config file for mudgee MUD generation
```

**Note:** by default the MUD profiles will be stored in a (newly created) `result` directory, which is the default behaviour of [MUDgee](https://github.com/ayyoob/mudgee).

### reject
MUDscope enforces MUD profiles by taking `config`s specifying `pcap` files for which to filter given MUD `rules`. When enforcing MUD profiles, traffic that does not conform to the MUD specification will be **rejected** and stored as a separate `pcap` file in the specified `output` directory.

```
usage: __main__.py reject [-h] --config <path> [<path> ...] --rules <path> --output <path>
                          [--limit <int>]

Filter MUD rejected traffic from pcap files.

optional arguments:
  -h, --help            show this help message and exit
  --config <path> [<path> ...]
                        path(s) to JSON config file(s) for MUD enforcement
  --rules <path>        path to MUD rules CSV file generated by MUDgee
  --output <path>       path to output directory in which to store results
  --limit <int>         optional, limits the number of packets processed when rejecting traffic
```

**Note:** We provide an [example](examples/) for the format of accepted `config` files. However, to create these reject `config` files manually, you can use the script:
```bash
python3 -m mudscope.generate_rjt_config
```

We recommend using this script instead of manual configuration as it automatically generates multiple reject `config` files referred to multiple (time-window) pcap files located in a directory, for instance the one used with ``editcap``. See script code directly, or run ``python3 -m mudscope.generate_rjt_config -h`` to consult usage.


### netflows
The `pcap` files containing MUD-rejected traffic (MRT) must be transformed into NetFlows which are used by the remainder of MUDscope. To transform MRT pcap files into NetFlow files, we use MUDscope's `netflows` mode that takes as `input` a directory containing all MRT pcap files, transforms them into NetFlow files that will be stored in the `output` directory.

```
usage: __main__.py netflows [-h] --input <path> --output <path>

Transform MRT pcap files to NetFlows.

optional arguments:
  -h, --help       show this help message and exit
  --input <path>   path to directory containing MUD-rejected pcap files
  --output <path>  path to output directory in which to store NetFlows
```

**Note:** MUDscope expects that input pcaps are already into separate *time-windows*, i.e. each pcap represents a new time-window. These separate pcaps are required during the `netflows`, `characterize`, and `evolution` modes. Therefore, as input for this step, make sure that your `malicious` pcap files are split into time-windows. You can divide pcap files spanning multiple time-windows into smaller pcaps using `editcap`:

```bash
editcap -i <60> path/to/input.pcap path/to/output.pcap
```

This splits a pcap file into smaller files each containing traffic for `-i` seconds, outputting all generated files to the specified path. See [editcap doc](https://www.wireshark.org/docs/man-pages/editcap.html) for more information.

In our running [example](examples/), this split has already been performed.

### characterize
Using the generated NetFlows, MUDscope clusters the traffic for multiple time windows and creates characterization files describing these clusters. In our paper, we show that these clusters often correspond to different types of attacks. To generate these characterization files, MUDscope takes as `input` the paths to the CSV files containing MRT netflows generated in the previous step. It also requires `metadata` containing information about the device we are characterizing (see our [examples](examples/) for the format), and it requires a `dsr` (Dataset Scaler Reference CSV file, see [examples](examples/)) to perform correct feature scaling. Using these inputs, MUDscope outputs characterization files in the given `output` directory.

```
usage: __main__.py characterize [-h] --input <path> [<path> ...] --metadata <path> --dsr <path>
                                --output <path>

Perform characterization analysis on MRT netflows.

optional arguments:
  -h, --help            show this help message and exit
  --input <path> [<path> ...]
                        path(s) to CSV file(s) containing MRT netflows
  --metadata <path>     path to JSON file describing the capture to analyse
  --dsr <path>          path to Dataset Scaler Reference (DSR) CSV file
  --output <path>       output directory in which to store analyzed file(s)
```

**Note:** When characterizing traffic, MUDscope translates pcaps to bi-directional flows, and scales their features. To do this, a dataset scaling reference (DSR) is required. A DSR file can be created from a single pcap file with normal (benign) network activity. It does not need to be deployment specific, and there are no length requirements. A 1 hour-long capture obtained from sniffing the network traffic of the deployment containing your IoT devices should work well. Here, longer and more exaustive captures will provide a better scaling reference.

To generate a DSR yourself, you can use the following scripts, also see [example](examples/):

```bash
# Transform benign pcaps into netflows
python3 -m mudscope.device_mrt_pcaps_to_csv \
    <path/to/directory/containing/benign/pcap/files/> \
    --outdir <path/to/output/directory/>

# Create dataset scaling reference (DSR)
python3 -m mudscope.scale_reference_df_script \
    <path/to/output/csv/of/previous/step.csv>
```

### evolution
We now have produced MUDscope characterizations of malicious traffic for each time window. However, we would also like to analyze how these characterizations evolve over time in order to produce MRT feeds. MUDscope's `evolution` mode takes as `input` the paths to JSON characterization files, analyzes the evolution of these characterizations and stores them in the MRT feed format in the specified `output` file.

```
usage: __main__.py evolution [-h] --input <path> [<path> ...] --output <path>

Perform evolution analysis on characterization files to produce MRT feeds.

optional arguments:
  -h, --help            show this help message and exit
  --input <path> [<path> ...]
                        path(s) to file(s) containing JSON characterization files
  --output <path>       output file in which to store MRT feed
```

### monitor
After generating MRT feeds for each device, we can compare feeds from different devices or vendors to see larger trends in the attacks targeting these devices. To this end, MUDscope provides the `monitor` mode which takes as input a `config` file specifying which MRT feeds to analyze and for which features to analyze them (see [example](examples/) for an example config file). Next, it will `output` its report and produced plots into the specified `output` directory.

```
usage: __main__.py monitor [-h] --config <path> --output <path>

Monitor and compare anomalous activities captured in MRT feeds.

optional arguments:
  -h, --help       show this help message and exit
  --config <path>  monitor config file specifying MRT feeds to compare
  --output <path>  path to directory which to write output monitor plots
```


## Examples
We provide a running example in the [examples/](examples/) directory.


## Dataset
Our evaluations were performed on two datasets:
- Our own dataset available here: [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.7182597.svg)](https://doi.org/10.5281/zenodo.7182597)
- The IEEE-Dataport IoT [Network Intrusion Dataset](https://ieee-dataport.org/open-access/iot-network-intrusion-dataset), by Kang et al.


## References
[1] `Luca Morgese Zangrandi, Thijs van Ede, Tim Booij, Savio Sciancalepore, Luca Allodi, and Andrea Continella. 2022. Stepping out of the MUD: Contextual threat information for IoT devices with manufacturer-provided behaviour profiles. In Proceedings of ACSAC ’22: ACM Annual Computer Security Applications Conference (ACSAC ’22).`

### Bibtex
```
@inproceedings{morgesezangrandi2022mudscope,
  title={{Stepping out of the MUD: Contextual threat information for IoT devices with manufacturer-provided behavior profiles}},
  author={Morgese Zangrandi, Luca and van Ede, Thijs and Booij, Tim and Sciancalepore, Savio and Allodi, Luca and Continella, Andrea},
  booktitle={Proceedings of ACSAC '22: ACM Annual Computer Security Applications Conference (ACSAC '22).},
  year={2022},
  organization={ACM}
}
```
