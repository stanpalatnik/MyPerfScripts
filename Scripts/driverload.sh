#!/bin/bash

checkdriverstate () {
a="$(dmesg -c)"
flag=0
for i in {1..120}; do
  a="$(dmesg)"

  for j in $a; do
    if test "$j" == "Operational"; then
      flag=1; break
    fi
  done

  if test $flag -eq 1; then
    echo "HSM driver has now become Operational";break
  fi
  sleep 1

done
}

testresult (){
  if test $1 -ne 0; then
    echo "Command failed"
    eval "date"; exit
  fi
}

co="/root/n3fips/google/cnn35xx-nfbe-kvm-xen-pf/software/bindist/Cfm2Util singlecmd loginHSM -u CO -s crypto_officer -p so12345"
echo "start date"
eval "date"

for i in {1..99999}
do
    echo "loop $i"
    eval "make hsm_reload vf_count=32"; testresult $?; checkdriverstate; sleep 2
    eval "date"
    #eval "make hsm_reload"; sleep 10
done

echo "end date"
eval "date"
