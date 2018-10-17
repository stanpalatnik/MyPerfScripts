if test $# -ne 1; then echo "Usage: sh $0 block / nonblock / all"; exit ; fi
time=2 ; thread=1 ; thread_nb=10

cal_perf()
{
    file=$1
    a=$(cat $logdir/$file | grep OPERATIONS | awk '{print $NF}' | cut -d / -f 1 | paste -sd+ - | bc)
    b=$((a / $time))
    if [[ $file == *rsa* ]]; then
        echo "$b" >> $logdir/result
    else
        pkt_size=$2
        c=$((b*$pkt_size*8 /1048576))
        echo "$c" >> $logdir/result
    fi
}

checkprocess()
{
    a=$(pgrep -l pkpspeed | wc -l)
    if test $a -eq 1; then
        sleep 1
#        mpstat -P ALL 4 1 > a ; awk '/%idle/ {for (i=1;i<=NF;i++) {if ($i=="%idle") col=i}}/Aver/ {print $col}' a | sed -n 1~2p | tr "\n" "\t" ; echo -e "\n"
        mpstat -P ALL 4 1 > a
        echo $(awk '/%idle/ {for (i=1;i<=NF;i++) {if ($i=="%idle") col=i}}/Aver/ {print $col}' a | sed -n 1~2p | tr "\n" "\t" ; echo -e "\n") > b
    fi

    a=$(pgrep -l pkpspeed | wc -l)
    while [ $a -ne 0 ]
    do
        a=$(pgrep -l pkpspeed | wc -l)
        if test $a -eq 0; then
            break
        fi
        sleep 1
    done
    return
}

runrsa()
{
mod=$1
string=$2
for crt in A B; do
    for static in y n; do
        for mod in $mod; do
            ext="rsa$crt$static$mod"
            echo "Running $ext"
            printf "B\n$thread\n$time\n$crt\nA\n$mod\n$static\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/$ext&
            checkprocess ;cal_perf $ext
            cat b >> $string ; sed -i "s/%idle/$ext/g" $string
            sleep 1
        done
    done
done
}

if test "$1" == "block" || test "$1" == "all"
then
logdir="logs_blocking_$thread" ; rm -rf $logdir ; rm -rf blockingCpu ; mkdir $logdir
echo "Running pkpSpeed Blocking Tests"

runrsa 2048 blockingCpu ; sleep 1

## RSA 2048 Server Full
for mod in 2048
do
    echo "RsaServerFull $mod"
    printf "B\n$thread\n$time\nF\n$mod\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsaserverfull_$mod&
    checkprocess ; cal_perf rsaserverfull_$mod ; sleep 1
    cat b >> blockingCpu ; sed -i "s/%idle/rsaSE2048/g" blockingCpu
done

runrsa 3072 blockingCpu ; sleep 1

## RSA 3072 Server Full
for mod in 3072
do
    echo "RsaServerFull $mod"
    printf "B\n$thread\n$time\nF\n$mod\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsaserverfull_$mod&
    checkprocess ; cal_perf rsaserverfull_$mod ; sleep 1
    cat b >> blockingCpu ; sed -i "s/%idle/rsaSE3072/g" blockingCpu
done

## Record Processing and Plain Crypto Algorithms
for pkt in {16,32,64,128,256,512,1024,2048,3072,4096,8192,16384}
do
    echo "recdes_$pkt"
    printf "B\n$thread\n$time\nG\n1\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/recdes_$pkt&
    checkprocess ; cal_perf recdes_$pkt $pkt ; sleep 1 ; cat b >> blockingCpu ; sed -i "s/%idle/recdes_$pkt/g" blockingCpu

    echo "recaes128_$pkt"
    printf "B\n$thread\n$time\nG\n0\n128\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/recaes128_$pkt&
    checkprocess ; cal_perf recaes128_$pkt $pkt ; sleep 1 ; cat b >> blockingCpu ; sed -i "s/%idle/recaes128_$pkt/g" blockingCpu

    echo "recaes256_$pkt"
    printf "B\n$thread\n$time\nG\n0\n256\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/recaes256_$pkt&
    checkprocess ; cal_perf recaes256_$pkt $pkt ; sleep 1 ; cat b >> blockingCpu ; sed -i "s/%idle/recaes256_$pkt/g" blockingCpu

    echo "recaesgcm128_$pkt"
    printf "B\n$thread\n$time\nG\n2\n128\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/recaesgcm128_$pkt&
    checkprocess ; cal_perf recaesgcm128_$pkt $pkt ; sleep 1 ; cat b >> blockingCpu ; sed -i "s/%idle/recaesgcm128_$pkt/g" blockingCpu

    echo "recaesgcm256_$pkt"
    printf "B\n$thread\n$time\nG\n2\n256\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/recaesgcm256_$pkt&
    checkprocess ; cal_perf recaesgcm256_$pkt $pkt ; sleep 1 ; cat b >> blockingCpu ; sed -i "s/%idle/recaesgcm256_$pkt/g" blockingCpu

    echo "des_$pkt"
    printf "B\n$thread\n$time\nC\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/des_$pkt&
    checkprocess ; cal_perf des_$pkt $pkt ; sleep 1 ; cat b >> blockingCpu ; sed -i "s/%idle/des_$pkt/g" blockingCpu

    echo "aes128_$pkt"
    printf "B\n$thread\n$time\nD\n128\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/aes128_$pkt&
    checkprocess ; cal_perf aes128_$pkt $pkt ; sleep 1 ; cat b >> blockingCpu ; sed -i "s/%idle/aes128_$pkt/g" blockingCpu

    echo "aes192_$pkt"
    printf "B\n$thread\n$time\nD\n192\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/aes192_$pkt&
    checkprocess ; cal_perf aes192_$pkt $pkt ; sleep 1 ; cat b >> blockingCpu ; sed -i "s/%idle/aes192_$pkt/g" blockingCpu

    echo "aes256_$pkt"
    printf "B\n$thread\n$time\nD\n256\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/aes256_$pkt&
    checkprocess ; cal_perf aes256_$pkt $pkt ; sleep 1 ; cat b >> blockingCpu ; sed -i "s/%idle/aes256_$pkt/g" blockingCpu

done

echo "Fips Random"
printf "B\n$thread\n$time\nH\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsafips&
checkprocess ; cal_perf rsafips; sleep 1 ; cat b >> blockingCpu ; sed -i "s/%idle/fipsrandom/g" blockingCpu
echo "ECDHFull P256"
printf "B\n$thread\n$time\nJ\nP256\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsap256&
checkprocess ; cal_perf rsap256 ; sleep 1 ; cat b >> blockingCpu ; sed -i "s/%idle/eccp256/g" blockingCpu
echo "ECDHFull P384"
printf "B\n$thread\n$time\nJ\nP384\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsap384&
checkprocess ; cal_perf rsap384 ; sleep 1 ; cat b >> blockingCpu ; sed -i "s/%idle/eccp384/g" blockingCpu

fi  ## End of IF Case for Blocking Tests

if test "$1" == "nonblock" || test "$1" == "all"
then
logdir="logs_non_block_$thread_nb" ; rm -rf $logdir ; rm -rf nonblockingCpu ; mkdir $logdir
echo "Running pkpSpeed Non Blocking Tests"


runrsa 2048 nonblockingCpu ; sleep 1
runrsa 3072 nonblockingCpu ; sleep 1

## Record Processing and Plain Crypto Algorithms
for pkt in {16,32,64,128,256,512,1024,2048,3072,4096,8192,16384}
do
    echo "des_$pkt"
    printf "B\n$thread\n$time\nC\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/des_$pkt&
    checkprocess ; cal_perf des_$pkt $pkt ; sleep 1 ; cat b >> nonblockingCpu ; sed -i "s/%idle/des_$pkt/g" nonblockingCpu

    echo "aes128_$pkt"
    printf "B\n$thread\n$time\nD\n128\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/aes128_$pkt&
    checkprocess ; cal_perf aes128_$pkt $pkt ; sleep 1 ; cat b >> nonblockingCpu ; sed -i "s/%idle/aes128_$pkt/g" nonblockingCpu

    echo "aes256_$pkt"
    printf "B\n$thread\n$time\nD\n256\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/aes256_$pkt&
    checkprocess ; cal_perf aes256_$pkt $pkt ; sleep 1 ; cat b >> nonblockingCpu ; sed -i "s/%idle/aes256_$pkt/g" nonblockingCpu
done

fi  ## End of IF Case for Non Blocking Tests

exit
