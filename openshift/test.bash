#!/bin/bash
export NAMESPACE=`oc project -q`
helm uninstall -n $NAMESPACE $(helm list -aq -n $NAMESPACE)
sleep 3
./deploycn.bash
ret=$?;[[ $ret -ne 0 ]] && exit $ret
sleep 3
./deployran.bash
ret=$?;[[ $ret -ne 0 ]] && exit $ret

CUCP=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-gnb-cu-cp`
CUUP=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-gnb-cu-up`
DU=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-gnb-du`
UE=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-nr-ue`
UPF=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-upf`
AMF=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-amf`
SMF=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-smf`

oc rsh -c nr-ue $UE ping -c 10 8.8.8.8 -I oaitun_ue1

oc logs $UE -c nr-ue > ue.log
oc logs $DU -c gnbdu > du.log
oc logs $CUCP -c gnbcucp > cucp.log
oc logs $CUUP -c gnbcuup > cuup.log
oc logs $AMF -c amf > amf.log
oc logs $SMF -c smf > smf.log
oc logs $UPF -c upf > upf.log

#sleep 20
#oc rsync -c tcpdump $AMF:/tmp/pcap .
#oc rsync -c tcpdump $CUCP:/tmp/pcap .
#oc rsync -c tcpdump $CUUP:/tmp/pcap .
#oc rsync -c tcpdump $DU:/tmp/pcap .
#oc rsync -c tcpdump $UPF:/tmp/pcap .
#mkdir -p /tmp/pcap
#mv pcap/*.pcap  /tmp/pcap
#rmdir pcap

exit 0


