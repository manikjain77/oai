#!/bin/bash
while [[ $(kubectl get pods -l app=oai-amf -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-amf" && sleep 1; done
while [[ $(kubectl get pods -l app=oai-smf -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-smf" && sleep 1; done
while [[ $(kubectl get pods -l app=oai-upf -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-upf" && sleep 1; done
AMF_POD_NAME=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-amf`

sleep 3

helm install -f ../charts/oai-5g-ran/oai-gnb-cu-cp/Chart.yaml cucp ../charts/oai-5g-ran/oai-gnb-cu-cp
while [[ $(kubectl get pods -l app=oai-gnb-cu-cp-cp -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-gnb-cu-cp" && sleep 1; done
CUCP_POD_NAME=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-gnb-cu-cp`
echo "CUCP=$CUCP_POD_NAME"
sleep 3
AMF_LOG=$(kubectl logs -c amf $AMF_POD_NAME | grep 'Sending NG_SETUP_RESPONSE Ok' | wc -l)
if [[ $AMF_LOG == 0 ]]; then
  echo 'Error: CUCP did not connect to AMF!'
  exit 1
else
  echo 'CUCP connected to AMF!'
fi

helm install -f ../charts/oai-5g-ran/oai-gnb-cu-up/Chart.yaml cuup ../charts/oai-5g-ran/oai-gnb-cu-up
while [[ $(kubectl get pods -l app=oai-gnb-cu-up -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-gnb-cu-up" && sleep 1; done
CUUP_POD_NAME=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-gnb-cu-up`
echo "CUUP=$CUUP_POD_NAME"

helm install -f ../charts/oai-5g-ran/oai-gnb-du/Chart.yaml du ../charts/oai-5g-ran/oai-gnb-du
while [[ $(kubectl get pods -l app=oai-gnb-du -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-gnb-du" && sleep 1; done
DU_POD_NAME=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-gnb-du`
echo "DU=$DU_POD_NAME"

sleep 5

helm install -f ../charts/oai-5g-ran/oai-nr-ue/Chart.yaml ue1 ../charts/oai-5g-ran/oai-nr-ue
while [[ $(kubectl get pods -l app=oai-nr-ue -o 'jsonpath={..status.conditions[?(@.type=="Ready")].status}') != "True" ]]; do echo "waiting for pod oai-nr-ue" && sleep 1; done
UE_POD_NAME=`oc get pods -o custom-columns=POD:.metadata.name --no-headers | grep oai-nr-ue`
echo "UE=$UE_POD_NAME"
sleep 5
IP_ADDR=$(kubectl exec -it -n $NAMESPACE -c nr-ue $UE_POD_NAME -- ifconfig oaitun_ue1 |grep -E '(^|\s)inet($|\s)' | awk {'print $2'})

if python3 -c "import ipaddress; ipaddress.ip_address('${IP_ADDR}')" 2>/dev/null; then
  echo "IP_ADDR is a valid IPv4 or IPv6 address"
  exit 0
else
  echo "IP_ADDR is not a valid IPv4 or IPv6 address"
  exit 1
fi
