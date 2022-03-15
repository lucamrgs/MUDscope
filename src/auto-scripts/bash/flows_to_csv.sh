#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo ">>> Illegal number of parameters running flows_to_csv.sh"
    exit 2
fi
counter=0;
dir=$1;
#echo "$dir"
base_dir_name=$(basename $dir)
for file in "$dir"/nfcapd.*;
do
    #echo "$file"
    out_name=$dir/"${base_dir_name%/}"_$((counter+1)).csv
    #echo "$out_name"
    # -b ENSURES BIDIRECTIONAL FLOWS!! And -B swaps flows so that port < 1024 is the DEST PORT
    # Ref at http://manpages.ubuntu.com/manpages/trusty/man1/nfdump.1.html 
    nfdump -B -r "$file" -o "fmt:%ts,%te,%td,%pr,%sa,%da,%sp,%dp,%sas,%pas,%ipkt,%opkt,%ibyt,%obyt,%flg,%dir,%bps,%pps,%bpp,%cl,%sl,%al" > $out_name && ((counter++));
done