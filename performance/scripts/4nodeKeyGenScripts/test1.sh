echo "Testing "rsa 2048"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "rsa 3072"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 3072 -e 65539 -l rsa &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 3072 -e 65539 -l rsa &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 3072 -e 65539 -l rsa &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 3072 -e 65539 -l rsa &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "rsa 4096"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 4096 -e 65539 -l rsa &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 4096 -e 65539 -l rsa &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 4096 -e 65539 -l rsa &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 4096 -e 65539 -l rsa &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "rsa 2048 sess"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa -sess &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa -sess &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa -sess &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa -sess &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "ecc 256"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 2 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 2 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 2 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 2 &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "ecc 384"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 14 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 14 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 14 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 14 &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "ecc 521"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 15 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 15 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 15 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 15 &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "aes 24"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 24 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 24 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 24 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 24 &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "aes 32"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "aes 32 sess"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -sess &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -sess &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -sess &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -sess &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "generic"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 16 -s 32 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 16 -s 32 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 16 -s 32 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 16 -s 32 &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "rsa 2048 attest"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa -attest &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa -attest &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa -attest &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa -attest &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "aes attest"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -attest &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -attest &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -attest &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -attest &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "import private"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 importPrivateKey -l imprsa -f expriv -w 4 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 importPrivateKey -l imprsa -f expriv -w 4 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 importPrivateKey -l imprsa -f expriv -w 4 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 importPrivateKey -l imprsa -f expriv -w 4 &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "import aes"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 imSymKey -l imsym -f exsym -w 4 -t 31 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 imSymKey -l imsym -f exsym -w 4 -t 31 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 imSymKey -l imsym -f exsym -w 4 -t 31 &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 imSymKey -l imsym -f exsym -w 4 -t 31 &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "import private sess"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 importPrivateKey -l imprsa -f expriv -w 4 -sess &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 importPrivateKey -l imprsa -f expriv -w 4 -sess &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 importPrivateKey -l imprsa -f expriv -w 4 -sess &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 importPrivateKey -l imprsa -f expriv -w 4 -sess &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10

echo "Testing "import aes sess"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 imSymKey -l imsym -f exsym -w 4 -t 31 -sess &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 imSymKey -l imsym -f exsym -w 4 -t 31 -sess &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 imSymKey -l imsym -f exsym -w 4 -t 31 -sess &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 imSymKey -l imsym -f exsym -w 4 -t 31 -sess &
a="$(pgrep -l Cfm3Util| wc -l)"
while [ $a -ne 0 ]
do
    a="$(pgrep -l Cfm3Util| wc -l)"
done
sleep 10
