echo "rsa 2048"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa
sleep 10

echo "rsa 3072"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 3072 -e 65539 -l rsa
sleep 10

echo "rsa 4096"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 4096 -e 65539 -l rsa
sleep 10

echo "rsa 2048 sess"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa -sess
sleep 10

echo "ecc 256"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 2
sleep 10

echo "ecc 384"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 14
sleep 10

echo "ecc 521"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genECCKeyPair -l ecc -i 15
sleep 10

echo "aes 24"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 24
sleep 10

echo "aes 32"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32
sleep 10

echo "aes 32 sess"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -sess
sleep 10

echo "generic"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 16 -s 32
sleep 10

echo "rsa 2048 attest"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genRSAKeyPair -m 2048 -e 65539 -l rsa -attest
sleep 10

echo "aes attest"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -attest
sleep 10

echo "import private"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 importPrivateKey -l imprsa -f expriv -w 4
sleep 10

echo "import aes"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 imSymKey -l imsym -f exsym -w 4 -t 31
sleep 10

echo "import private sess"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 importPrivateKey -l imprsa -f expriv -w 4 -sess
sleep 10

echo "import aes sess"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 imSymKey -l imsym -f exsym -w 4 -t 31 -sess
sleep 10


