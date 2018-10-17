#echo "aes 32"
#time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 &
#time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 &
#time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 &
#time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 &

echo "aes 32 sess"
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -sess &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -sess &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -sess &
time ./Cfm3Util singlecmd loginHSM -u CU -s crypto_user -p user123 genSymKey -l aes -t 31 -s 32 -sess &

