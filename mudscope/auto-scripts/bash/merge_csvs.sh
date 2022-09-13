#!/bin/bash
#from https://stackoverflow.com/questions/24641948/merging-csv-files-appending-instead-of-merging/24643455

if [ "$#" -ne 1 ]; then
    echo ">>> Illegal number of parameters running merge_csvs.sh"
    exit 2
fi

dir=$1;
base_dir_name=$(basename $dir)
OutFileName="$base_dir_name.csv" #output csv has name directory.csv
i=0  # Reset a counter

for filename in $dir/*.csv; do
	if [ "$filename"  != "$OutFileName" ] ;      # Avoid recursion 
	then 
		if [[ $i -eq 0 ]] ; then 
			head -1  "$filename" >   $dir/"$OutFileName" # Copy header if it is the first file
		fi
		tail -n +2  "$filename" >>  $dir/"$OutFileName" # Append from the 2nd line each file
		i=$(( $i + 1 ))                            # Increase the counter
	fi
done