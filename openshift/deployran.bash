#!/bin/bash
NAMESPACE=`oc project -q`
while [[ $(kubectl get pods -l app=oai-amf -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-amf" && sleep 1; done
while [[ $(kubectl get pods -l app=oai-smf -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-smf" && sleep 1; done
while [[ $(kubectl get pods -l app=oai-upf -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-upf" && sleep 1; done
AMF_POD_NAME=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-amf`

sleep 3

helm install -f ../charts/oai-5g-ran/oai-cu-cp/Chart.yaml cucp ../charts/oai-5g-ran/oai-cu-cp \
        --set start.tcpdump="true"        

while [[ $(kubectl get pods -l app=oai-cu-cp -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-cu-cp" && sleep 1; done
CUCP_POD_NAME=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-cu-cp`
echo "CUCP=$CUCP_POD_NAME"
sleep 3
AMF_LOG=$(kubectl logs -c amf $AMF_POD_NAME | grep 'Sending NG_SETUP_RESPONSE Ok' | wc -l)
if [[ $AMF_LOG == 0 ]]; then
  echo 'Error: CUCP did not connect to AMF!'
  exit 1
else
  echo 'CUCP connected to AMF!'
fi

helm install -f ../charts/oai-5g-ran/oai-cu-up/Chart.yaml cuup1 ../charts/oai-5g-ran/oai-cu-up \
        --set serviceAccount.name=oai-cu-up1-sa \
        --set multus.e1Interface.IPadd="192.168.18.13" \
        --set multus.n3Interface.IPadd="192.168.25.4" \
        --set multus.f1uInterface.IPadd="192.168.20.14" \
        --set config.e1IpAddress="192.168.18.12" \
        --set config.f1duIpAddress="192.168.20.13" \
        --set config.nssaiSst="1" \
        --set config.nssaiSd="0xffffff" \
        --set start.tcpdump="false"
while [[ $(kubectl get pods -l app=oai-cu-up -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-cu-up" && sleep 1; done
CUUP1=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-cu-up`
echo "CUUP1=$CUUP1"
oc logs $CUUP1 -c gnbcuup > cuup1-start.log

helm install -f ../charts/oai-5g-ran/oai-cu-up2/Chart.yaml cuup2 ../charts/oai-5g-ran/oai-cu-up2 \
        --set multus.e1Interface.IPadd="192.168.18.14" \
        --set multus.n3Interface.IPadd="192.168.25.5" \
        --set multus.f1uInterface.IPadd="192.168.20.15" \
        --set config.e1IpAddress="192.168.18.12" \
        --set config.f1duIpAddress="192.168.20.13" \
        --set config.nssaiSst="2" \
        --set config.nssaiSd="0xffffff" \
        --set start.tcpdump="true"
while [[ $(kubectl get pods -l app=oai-cu-up2 -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-cu-up2" && sleep 1; done
CUUP2=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep -v $CUUP1 | grep oai-cu-up2`
echo "CUUP2=$CUUP2"
oc logs $CUUP2 -c gnbcuup > cuup2-start.log

helm install -f ../charts/oai-5g-ran/oai-du/Chart.yaml du ../charts/oai-5g-ran/oai-du
while [[ $(kubectl get pods -l app=oai-du -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-du" && sleep 1; done
DU_POD_NAME=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-du`
echo "DU=$DU_POD_NAME"

sleep 5

helm install -f ../charts/oai-5g-ran/oai-nr-ue/Chart.yaml ue1 ../charts/oai-5g-ran/oai-nr-ue
while [[ $(kubectl get pods -l app=oai-nr-ue -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-nr-ue" && sleep 1; done
UE1_POD_NAME=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-nr-ue`
echo "UE1=$UE1_POD_NAME"
sleep 10
IP_ADDR=$(kubectl exec -it -n $NAMESPACE -c nr-ue $UE1_POD_NAME -- ifconfig oaitun_ue1 |grep -E '(^|\s)inet($|\s)' | awk {'print $2'})

if python3 -c "import ipaddress; ipaddress.ip_address('${IP_ADDR}')" 2>/dev/null; then
  echo "UE1 IP_ADDR is a valid IPv4 or IPv6 address"
  exit 0
else
  echo "UE1 IP_ADDR is not a valid IPv4 or IPv6 address"
  exit 1
fi

