#!/bin/bash
set -e
set -x

PREFIX="/home/bhanuteja/driver/";

CARD_KEYS="/home/bhanuteja/card_keys/"

Id=1;

cd $PREFIX/bin/;

./Cfm2MasterUtil singlecmd loginHSM -u CO -p so12345 -s crypto_officer createPartition -n PARTITION_$Id -s 10075 -c 25000 -d 2 -f 1 -b 1

echo "Using $PREFIX/data/hsm_config"

./Cfm2Util -p PARTITION_$Id singlecmd loginHSM -u CO -s cavium -p default initHSM -sO crypto_officer -p so12345 -a 0 -f $PREFIX/data/hsm_config

./Cfm2Util -p PARTITION_$Id singlecmd listUsers

./Cfm2Util -p PARTITION_$Id singlecmd loginHSM -u CO -s crypto_officer -p so12345 getCertReq -f $CARD_KEYS/P1.csr

openssl x509 -days 365 -req -in $CARD_KEYS/P1.csr -CA $CARD_KEYS/PO.crt -CAkey $CARD_KEYS/PO.key -set_serial 01 -out $CARD_KEYS/POsigned.crt

./Cfm2Util -p PARTITION_$Id singlecmd loginHSM -u CO -s crypto_officer -p so12345 storeCert -f $CARD_KEYS/PO.crt -s 4

./Cfm2Util -p PARTITION_$Id singlecmd loginHSM -u CO -s crypto_officer -p so12345 storeCert -f $CARD_KEYS/POsigned.crt -s 8

./Cfm2Util -p PARTITION_$Id singlecmd loginHSM -u CO -s crypto_officer -p so12345 generateKEK

./Cfm2Util -p PARTITION_$Id singlecmd loginHSM -u CO -s crypto_officer -p so12345 createUser -u CU -s crypto_user -p user123

./Cfm2Util -p PARTITION_$Id singlecmd loginHSM -u CO -s crypto_officer -p so12345 createUser -u AU -s app_user -p user1234567890

./Cfm2Util -p PARTITION_$Id singlecmd listUsers

