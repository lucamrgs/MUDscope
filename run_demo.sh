trap "exit" INT

echo ''
echo ''
echo '~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~'
echo '              ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ REJECTING TRAFFIC ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                    '
echo '~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~'
echo ''
echo ''
sleep 1.2

python3 run.py --mode reject --reject_mud_rules result/ut-tplink-plug/ut-tplink-plugrule.csv --reject_config configs/reject_configs/ut-tplink-demo/ &
python3 run.py --mode reject --reject_mud_rules result/tue-tplink-plug/tue-tplink-plugrule.csv --reject_config configs/reject_configs/tue-tplink-demo/ &
wait

echo ''
echo ''
echo '~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~'
echo '               ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ GENERATING FLOWS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                    '
echo '~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~'
echo ''
echo ''
sleep 1.2

python3 run.py --mode flows_gen --flowsgen_tgt_dir outputs/ut-tplink-demo/ &
python3 run.py --mode flows_gen --flowsgen_tgt_dir outputs/tue-tplink-demo/ &
wait

echo ''
echo ''
echo '~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~'
echo '        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ CHARACTERISING MUD-REJECTED TRAFFIC ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~        '
echo '~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~'
echo ''
echo ''
sleep 1.2

python3 run.py --mode analyze --analysis_devname ut-tplink-demo --analysis_action mrta_characterize --dsr_path /Users/lucamrgs/Big_Data/FederatedLab/UT/ut-all-scaling-ref-flows-custom-hdr-CLN-SCALED.csv --analysis_capture_metadata ch_fedlab_ut_tplink.json --analysis_tgt outputs/ut-tplink-demo/ut-tplink-demo-all-flows-csv/ &
python3 run.py --mode analyze --analysis_devname tue-tplink-demo --analysis_action mrta_characterize --dsr_path /Users/lucamrgs/Big_Data/FederatedLab/TUe/tue-all-scaling-ref-flows-custom-hdr-CLN-SCALED.csv --analysis_capture_metadata ch_fedlab_tue_tplink.json --analysis_tgt outputs/tue-tplink-demo/tue-tplink-demo-all-flows-csv/ &
wait

echo ''
echo ''
echo '~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~'
echo '              ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ GENERATING MRT FEEDS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                 '
echo '~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~'
echo ''
echo ''
sleep 1.2

python3 run.py --mode analyze --analysis_devname ut-tplink-demo --analysis_action device_mrt_evolution_datagen --analysis_tgt outputs/ut-tplink-demo/ut-tplink-demo_mrt_characterizations/ &
python3 run.py --mode analyze --analysis_devname tue-tplink-demo --analysis_action device_mrt_evolution_datagen --analysis_tgt outputs/tue-tplink-demo/tue-tplink-demo_mrt_characterizations/ &
wait

echo ''
echo ''
echo '~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~'
echo '              ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ COMPARING MRT FEEDS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                  '
echo '~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~*~'
echo ''
echo ''
sleep 1.2

#python3 src/MRTADashboard.py monodim
python3 run.py --mode monitor --mrtfeeds_config /Users/lucamrgs/mudscope/configs/monitor_configs/monitor_test.json --monitor_features clusters_balance;all_dists_avg;mutual_matches_n;mutual_matches_percentage;fwd_matches_n;fwd_matches_percentage;bwd_matches_n;bwd_matches_percentage