#!/bin/bash
export NAMESPACE=`oc project -q`
helm uninstall -n $NAMESPACE $(helm list -aq -n $NAMESPACE)
sleep 3
./deploycn.bash
ret=$?;[[ $ret -ne 0 ]] && exit $ret
sleep 3
./deployran.bash
ret=$?;

CUCP=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-cu-cp`
CUUP1=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-cu-up-`
CUUP2=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-cu-up2`
DU=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-du`
UE1=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-nr-ue-`
UPF=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-upf`
AMF=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-amf`
SMF=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-smf`

if [[ $ret -eq 0 ]]; then
  oc rsh -c nr-ue $UE1 ping -c 10 8.8.8.8 -I oaitun_ue1
fi

helm install -f ../charts/oai-5g-ran/oai-nr-ue2/Chart.yaml ue2 ../charts/oai-5g-ran/oai-nr-ue2
while [[ $(kubectl get pods -l app=oai-nr-ue2 -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-nr-ue2" && sleep 1; done
UE2_POD_NAME=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-nr-ue2`
UE2=$UE2_POD_NAME
echo "UE2=$UE2_POD_NAME"

# Waiting for UE receive its IP address from CN with time-out
for ((i=1;i<=10;i++)); do
  UE2_LOG=$(kubectl logs -c nr-ue $UE2_POD_NAME | grep 'Interface oaitun_ue1' | wc -l)
  if [[ $UE2_LOG == 0 ]]; then
    echo "waiting for UE receive its IP address from CN..."
    sleep 2
  else
    break
  fi
done
IP_ADDR=$(kubectl exec -it -n $NAMESPACE -c nr-ue $UE2_POD_NAME -- ifconfig oaitun_ue1 |grep -E '(^|\s)inet($|\s)' | awk {'print $2'})

if python3 -c "import ipaddress; ipaddress.ip_address('${IP_ADDR}')" 2>/dev/null; then
  echo "UE2 IP_ADDR $IP_ADDR is a valid IPv4 or IPv6 address"
  oc rsh -c nr-ue $UE2_POD_NAME ping -c 10 8.8.8.8 -I oaitun_ue1
else
  echo "UE2 IP_ADDR $IP_ADDR is not a valid IPv4 or IPv6 address"
fi

sleep 20
echo 'Logging...'
oc logs $UE1 -c nr-ue > ue1.log
oc logs $UE2 -c nr-ue > ue2.log
oc logs $DU -c gnbdu > du.log
oc logs $CUCP -c gnbcucp > cucp.log
oc logs $CUUP1 -c gnbcuup > cuup1.log
oc logs $CUUP2 -c gnbcuup > cuup2.log
oc logs $AMF -c amf > amf.log
oc logs $SMF -c smf > smf.log
oc logs $UPF -c upf > upf.log

echo 'Get pcaps from pods...'
oc rsync -c tcpdump $AMF:/tmp/pcap .
oc rsync -c tcpdump $CUCP:/tmp/pcap .
oc rsync -c tcpdump $CUUP2:/tmp/pcap .
#oc rsync -c tcpdump $DU:/tmp/pcap .
#oc rsync -c tcpdump $UPF:/tmp/pcap .
mkdir -p /tmp/pcap
mv pcap/*.pcap  /tmp/pcap
rmdir pcap

exit 0


