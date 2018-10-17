#### Create, Generate Key, Finalize, getlog, deletePartition
for i in {1..999999}
do
    date=`date` ; echo "LOOOOP $i, $date"

    for i in {1..31}
    do
        source ~/oracle_conf.sh $i 1 ; $createpart ; sleep 1 ; $cfminit ; $kek ; $createau ; sleep 1 
        sleep 2
    done

    for i in {1..31}
    do
        ./Cfm2Util-orig -p PARTITION_$i singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65537 -l rsa &
        ./Cfm2Util-orig -p PARTITION_$i singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 &
    done
    sleep 5

    for i in {1..31}
    do
        source ~/oracle_conf.sh $i 1 ; $finalze ; $getlog
    done
    sleep 2

    for i in {1..31}
    do
        source ~/oracle_conf.sh $i 1 ; $deletepart
    done
    sleep 5
    date=`date` ; echo "LOOOOP END, $date"

done
