#!/usr/bin/bash

master="/home/suresh/1614/bin/Cfm2MasterUtil singlecmd loginHSM -u CO -s crypto_officer -p so12345"
co="/home/suresh/1614/bin/Cfm2Util singlecmd loginHSM -u CO -s crypto_officer -p so12345"
cu="/home/suresh/1614/bin/Cfm2Util singlecmd loginHSM -u CU -s crypto_user -p user123"
def="/home/suresh/1614/bin/Cfm2Util singlecmd loginHSM -u CO -s cavium -p default"

start=$(date +%s)
end=$(date +%s)
DIFF=$(( $end - $start))
time=600

while [ $DIFF -le $time ]; do
    killall Cfm2MasterUtil
    killall Cfm2Util

    partitions=$($master getAllPartitionInfo | grep name)
    for i in "${partitions[@]}"
    do
        name=$(echo $i | cut -d : -f 2)
        $master deletePartition -n $name -f
    done

    $master createPartition -n PARTITION_1 -s 2048 -c 2048 -d 1 -f 1 -an csr -b 1 -a -i 1
    $def initHSM -p so12345 -sO crypto_officer -a 0 -f ../data/hsm_config
    $co generateKEK
    $co createUser -u CU -p user123 -s cu1

    for i in {1..10}; do
        ./test_crypto -p user123 -s cu1 -verbose &
        printf "N\nN\n10\n10\nD\n256\n100\nX\n" | ./pkpspeed -p user123 -s cu1 &
    done


### Verification of Process ###
    a=$(pgrep -l pkpspeed | wc -l)
    while [ $a -ne 0 ]
    do
        a=$(pgrep -l pkpspeed | wc -l)
        if test $a -eq 0; then
            break
        fi
        sleep 1
    done

    a=$(pgrep -l test_crypto | wc -l)
    while [ $a -ne 0 ]
    do
        a=$(pgrep -l test_crypto | wc -l)
        if test $a -eq 0; then
            break
        fi
        sleep 1
    done

    end=$(date +%s)
    DIFF=$(( $end - $start))
    echo "$end $DIFF seconds"
    read txt
done
