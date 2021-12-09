echo "hi"

if [ "$#" -ne 1 ]; then
    echo ">>> Illegal number of parameters running pcap_to_flows.sh"
    exit 2
fi

counter=0;
dir=$1;
echo "$dir"
for file in "$dir"/*.pcap;
do
    #echo "$file"
    my_name="$(basename -s .pcap $file)"
    #echo "$my_name"
    mkdir -p $dir/"$my_name"
    nfpcapd -r "$file" -l $dir/"$my_name"
done