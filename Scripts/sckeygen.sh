echo "CMD: rsa 2048"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa
sleep 10

echo "CMD: rsa 3072"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 3072 -e 65539 -l rsa
sleep 10

echo "CMD: rsa 4096"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 4096 -e 65539 -l rsa
sleep 10

echo "CMD: rsa 2048 sess"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa -sess
sleep 10

echo "CMD: ecc 256"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 2
sleep 10

echo "CMD: ecc 384"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 14
sleep 10

echo "CMD: ecc 521"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 15
sleep 10

echo "CMD: aes 24"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 24
sleep 10

echo "CMD: aes 32"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32
sleep 10

echo "CMD: aes 32 sess"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -sess
sleep 10

echo "CMD: generic"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 16 -s 64
sleep 10

echo "CMD: rsa 2048 attest"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa -attest
sleep 10

echo "CMD: aes attest"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -attest
sleep 10

echo "CMD: import private"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 importPrivateKey -l imprsa -f expriv -w 4
sleep 10

echo "CMD: import aes"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 imSymKey -l imsym -f exsym -w 4 -t 31
sleep 10

echo "CMD: import private sess"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 importPrivateKey -l imprsa -f expriv -w 4 -sess
sleep 10

echo "CMD: import aes sess"
./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 imSymKey -l imsym -f exsym -w 4 -t 31 -sess
sleep 10


