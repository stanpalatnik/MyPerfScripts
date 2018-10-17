if test $# -ne 1; then echo "Usage: sh $0 block / nonblock / all"; exit ; fi
time=10 ; thread=100 ; thread_nb=10

cal_perf()
{
    file=$1
    a=$(cat $logdir/$file | grep OPERATIONS | awk '{print $NF}' | cut -d / -f 1 | paste -sd+ - | bc)
    b=$((a / $time))
    if [[ $file == *rsa* ]]; then
        echo "$file $b" >> $logdir/result
    else
        pkt_size=$2
        c=$((b*$pkt_size*8 /1048576))
        echo "$file $c" >> $logdir/result
    fi
}

checkprocess()
{
    a=$(pgrep -l pkpspeed | wc -l)
    if test $a -eq 1; then
        sleep 3
        mpstat -P ALL 4 1 > a ; awk '/%idle/ {for (i=1;i<=NF;i++) {if ($i=="%idle") col=i}}/Aver/ {print $col}' a | sed -n 1~2p | tr "\n" "\t" ; echo -e "\n"
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

if test "$1" == "block" || test "$1" == "all"
then
logdir="logs_blocking_$thread" ; rm -rf $logdir ; mkdir $logdir
echo "Running pkpSpeed Blocking Tests"

for mod in 2048 3072
do
    echo "RSA Non CRT $mod with static Key"
    printf "B\n$thread\n$time\nA\nA\n$mod\ny\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsanoncrt_with_static_$mod&
    checkprocess
    cal_perf rsanoncrt_with_static_$mod
    sleep 20
done

for mod in 2048 3072
do
    echo "RSA Non CRT $mod without static Key"
    printf "B\n$thread\n$time\nA\nA\n$mod\nn\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsanoncrt_without_static_$mod&
    checkprocess
    cal_perf rsanoncrt_without_static_$mod
    sleep 20
done

for mod in 2048 3072
do
    echo "RSA CRT $mod with static Key"
    printf "B\n$thread\n$time\nB\nA\n$mod\ny\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsacrt_with_static_$mod&
    checkprocess
    cal_perf rsacrt_with_static_$mod
    sleep 20
done

for mod in 2048 3072
do
    echo "RSA CRT $mod without static Key"
    printf "B\n$thread\n$time\nA\nA\n$mod\nn\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsacrt_without_static_$mod&
    checkprocess
    cal_perf rsacrt_without_static_$mod
    sleep 20
done

## DES-CBC Test
for pkt in {16,32,64,128,256,512,1024,2048,3072,4096,8192,16384}
do
    printf "B\n$thread\n$time\nC\n$pkt\nX\n" | ./pkpspeed -s crypto_user -p user123 >> $logdir/des_$pkt&
    echo "DES $pkt"
    checkprocess
    cal_perf des_$pkt $pkt
    sleep 20
done

## AES Test
for key in {128,192,256}
do
for pkt in {16,32,64,128,256,512,1024,2048,3072,4096,8192,16384}
do
    echo "AES $key $pkt" ; ext="$key$pkt"
    printf "B\n$thread\n$time\nD\n$key\n$pkt\nX\n" | ./pkpspeed -s crypto_user -p user123 >> $logdir/aes_$ext&
    checkprocess
    cal_perf aes_$ext $pkt
    sleep 20
done
done

## RSAServerFull Test
for mod in 2048 3072
do
    echo "RsaServerFull $mod"
    printf "B\n$thread\n$time\nF\n$mod\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsaserverfull_$mod&
    checkprocess
    cal_perf rsaserverfull_$mod
    sleep 20
done

## AES & AES_GCM Record Enc
for typ in 0 2
do
    if test $typ -eq 0; then type="aes" ;fi
    if test $typ -eq 2; then type="aesgcm" ;fi
    for key in 128 256
    do
        for pkt in 16 32 64 128 256 512 1024 3072 2048 4096 8192 16384
        do
            echo "Record $type $key $pkt" ; ext="$type$key$pkt"
            printf "B\n$thread\n$time\nG\n$typ\n$key\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rec_$ext&
            checkprocess
            cal_perf rec_$ext $pkt
            sleep 20
        done
    done
done

## DES Record Enc
for typ in 1
do
    for pkt in 16 32 64 128 256 512 1024 2048 3072 4096 8192 16384
    do
        echo "DES Record $pkt" ; ext="des$pkt"
        printf "B\n$thread\n$time\nG\n$typ\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rec_$ext&
        checkprocess
        cal_perf rec_$ext $pkt
        sleep 20
    done
done

echo "Fips Random"
printf "B\n$thread\n$time\nH\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsafips&
checkprocess ; cal_perf rsafips; sleep 20

echo "ECDHFull P256"
printf "B\n$thread\n$time\nJ\nP256\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsap256&
checkprocess ; cal_perf rsap256 ; sleep 20
echo "ECDHFull P384"
printf "B\n$thread\n$time\nJ\nP384\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsap384&
checkprocess ; cal_perf rsap384 ; sleep 20

## AES_GCM Test
for key in 128 256
do
    for pkt in 16 32 64 128 256 512 1024 2048 4096 8192 16384
    do
        echo "AES GCM $key $pkt" ; ext="$key$pkt"
        printf "B\n$thread\n$time\nD\n$key\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/aesgcm_$ext&
        checkprocess
        cal_perf aesgcm_$ext $pkt
        sleep 20
    done
done

fi  ## End of IF Case

if test "$1" == "nonblock" || test "$1" == "all"
then
logdir="logs_non_block_$thread_nb" ; rm -rf $logdir ; mkdir $logdir
echo "Running pkpSpeed Non Blocking Tests"

for mod in 2048 3072
do
    echo "RSA Non CRT $mod with static Key"
    printf "N\n$thread_nb\n$time\nA\nA\n$mod\ny\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/nb_rsanoncrt_with_static_$mod&
    checkprocess
    cal_perf nb_rsanoncrt_with_static_$mod
    sleep 20
done

for mod in 2048 3072
do
    echo "RSA Non CRT $mod without static Key"
    printf "N\n$thread_nb\n$time\nA\nA\n$mod\nn\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/nb_rsanoncrt_without_static_$mod&
    checkprocess
    cal_perf nb_rsanoncrt_without_static_$mod
    sleep 20
done

for mod in 2048 3072
do
    echo "RSA CRT $mod with static"
    printf "N\n$thread_nb\n$time\nB\nA\n$mod\ny\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/nb_rsacrt_with_static_$mod&
    checkprocess
    cal_perf nb_rsacrt_with_static_$mod
    sleep 20
done

for mod in 2048 3072
do
    echo "RSA CRT $mod without static"
    printf "N\n$thread_nb\n$time\nB\nA\n$mod\nn\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/nb_rsacrt_without_static_$mod&
    checkprocess
    cal_perf nb_rsacrt_without_static_$mod
    sleep 20
done

for pkt in 16 32 64 128 256 512 1024 2048 3072 4096 8192 16384
do
    echo "3DES $pkt"
    printf "N\n$thread_nb\n$time\nC\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/nb_des_$pkt&
    checkprocess
    cal_perf nb_des_$pkt $pkt
    sleep 20
done

for key in 128 256
do
    for pkt in 16 32 64 128 256 512 1024 2048 3072 4096 8192 16384
    do
        echo "AES $key $pkt" ; ext="$key$pkt"
        printf "N\n$thread_nb\n$time\nD\n$key\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/nb_aes_$ext&
        checkprocess
        cal_perf nb_aes_$ext $pkt
        sleep 20
    done
done

fi
