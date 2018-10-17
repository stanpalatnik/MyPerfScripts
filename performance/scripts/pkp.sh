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

if test "$1" == "block" || test "$1" == "all"
then
logdir="logs_blocking_$thread" ; rm -rf $logdir ; mkdir $logdir
echo "Running pkpSpeed Blocking Tests"

for mod in 2048 3072 4096
do
    echo "RSA Non CRT $mod with static Key"
    printf "B\n$thread\n$time\nA\nA\n$mod\ny\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsanoncrt_with_static_$mod
    cal_perf rsanoncrt_with_static_$mod
    sleep 10
done

for mod in 2048 3072 4096
do
    echo "RSA Non CRT $mod Public Key Decryption with static Key"
    printf "B\n$thread\n$time\nA\nB\n$mod\ny\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsanoncrt_pub_with_static_$mod
    cal_perf rsanoncrt_pub_with_static_$mod
    sleep 10
done

for mod in 2048 3072 4096
do
    echo "RSA CRT $mod with static"
    printf "B\n$thread\n$time\nB\nA\n$mod\ny\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsacrt_with_static_$mod
    cal_perf rsacrt_with_static_$mod
    sleep 10
done

for mod in 2048 3072 4096
do
    echo "RSA CRT $mod Public Key Decryption with static Key"
    printf "B\n$thread\n$time\nB\nB\n$mod\nn\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsacrt_pub_with_static_$mod
    cal_perf rsacrt_pub_with_static_$mod
    sleep 10
done

for pkt in 16 32 64 128 256 512 1024 2048 4096 8192 16384
do
    echo "3DES $pkt"
    printf "B\n$thread\n$time\nC\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/des_$pkt
    cal_perf des_$pkt $pkt
    sleep 10
done

for key in 128 192 256
do
    for pkt in 16 32 64 128 256 512 1024 2048 4096 8192 16384
    do
        echo "AES $key $pkt" ; ext="$key$pkt"
        printf "B\n$thread\n$time\nD\n$key\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/aes_$ext
        cal_perf aes_$ext $pkt
        sleep 10
    done
done

for mod in 2048 4096
do
    echo "RsaServerFull $mod"
    printf "B\n$thread\n$time\nF\n$mod\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsaserverfull_$mod
    cal_perf rsaserverfull_$mod
done

## AES & AES_GCM Record Enc
for typ in 0 2
do
    for key in 128 256
    do
        for pkt in 16 32 64 128 256 512 1024 2048 4096 8192 16384
        do
            echo "Record $typ $key $pkt" ; ext="$typ$key$pkt"
            printf "B\n$thread\n$time\nG\n$typ\n$key\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rec_$ext
            cal_perf rec_$ext $pkt
            sleep 10
        done
    done
done

## DES Record Enc
for typ in 1
do
    for pkt in 16 32 64 128 256 512 1024 2048 4096 8192 16384
    do
        echo "Record $typ $pkt" ; ext="$typ$pkt"
        printf "B\n$thread\n$time\nG\n$typ\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rec_$ext
        cal_perf rec_$ext $pkt
        sleep 10
    done
done


echo "Fips Random"
printf "B\n$thread\n$time\nH\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsafips ; cal_perf rsafips

echo "ECDHFull"
printf "B\n$thread\n$time\nJ\nP256\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsap256 ; cal_perf rsap256
printf "B\n$thread\n$time\nJ\nP384\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/rsap384 ; cal_perf rsap384

for key in 128 192 256
do
    for pkt in 16 32 64 128 256 512 1024 2048 4096 8192 16384
    do
        echo "AES GCM $key $pkt" ; ext="$key$pkt"
        printf "B\n$thread\n$time\nD\n$key\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/aesgcm_$ext
        cal_perf aesgcm_$ext $pkt
        sleep 10
    done
done

fi

if test "$1" == "nonblock" || test "$1" == "all"
then
logdir="logs_non_block_$thread_nb" ; rm -rf $logdir ; mkdir $logdir
echo "Running pkpSpeed Non Blocking Tests"

for mod in 2048 3072 4096
do
    echo "RSA Non CRT $mod with static Key"
    printf "N\n$thread_nb\n$time\nA\nA\n$mod\ny\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/nb_rsanoncrt_with_static_$mod
    cal_perf nb_rsanoncrt_with_static_$mod
    sleep 10
done

for mod in 2048 3072 4096
do
    echo "RSA Non CRT $mod Public Key Decryption with static Key"
    printf "N\n$thread_nb\n$time\nA\nB\n$mod\ny\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/nb_rsanoncrt_pub_with_static_$mod
    cal_perf nb_rsanoncrt_pub_with_static_$mod
    sleep 10
done

for mod in 2048 3072 4096
do
    echo "RSA CRT $mod with static"
    printf "N\n$thread_nb\n$time\nB\nA\n$mod\ny\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/nb_rsacrt_with_static_$mod
    cal_perf nb_rsacrt_with_static_$mod
    sleep 10
done

for mod in 2048 3072 4096
do
    echo "RSA CRT $mod Public Key Decryption with static Key"
    printf "N\n$thread_nb\n$time\nB\nB\n$mod\nn\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/nb_rsacrt_pub_with_static_$mod
    cal_perf nb_rsacrt_pub_with_static_$mod
    sleep 10
done

for pkt in 16 32 64 128 256 512 1024 2048 4096 8192 16384
do
    echo "3DES $pkt"
    printf "N\n$thread_nb\n$time\nC\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/nb_des_$pkt
    cal_perf nb_des_$pkt $pkt
    sleep 10
done

for key in 128 192 256
do
    for pkt in 16 32 64 128 256 512 1024 2048 4096 8192 16384
    do
        echo "AES $key $pkt" ; ext="$key$pkt"
        printf "N\n$thread_nb\n$time\nD\n$key\n$pkt\nX" | ./pkpspeed -s crypto_user -p user123 >> $logdir/nb_aes_$ext
        cal_perf nb_aes_$ext $pkt
        sleep 10
    done
done

fi
