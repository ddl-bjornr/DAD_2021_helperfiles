#!/bin/bash
P_NS='domino-platform'
C_NS=$( kubectl get ns -l domino-platform=true  |grep Active |tail -1 |awk '{print $1}')

C_NS='domino-compute'
C_NS=$( kubectl get ns -l domino-compute=true  |grep Active |tail -1 |awk '{print $1}')

# Prepare for data-plane-agent restart
kubectl delete secret -n $C_NS    agent-app-role

# Remedies build/model publishing
echo "Fix for if buildkit cannot be configured due to cert expiry:"
kubectl delete secret -n $P_NS    hephaestus-webhook-tls

if [ "$1" == "-nuclear" ]; then

 echo "hephaestus-root-tls"
 kubectl delete secret -n $P_NS hephaestus-root-tls
 # delete Rabbit PVC
 # delete https://github.com/cert-manager/cert-manager/issues/3495
 kubectl scale sts -n $P_NS -l app.kubernetes.io/name=rabbitmq-ha --replicas=0
 kubectl delete pvc -n $P_NS $( kubectl get pvc -A |grep rabbit | awk '{print $2}' | xargs echo )
 
 # Flush buildkit pods
 kubectl scale sts -n $C_NS -l app.kubernetes.io/name=hephaestus --replicas=0
 kubectl delete pvc -n $C_NS $( kubectl get pvc -A |grep buildkit | awk '{print $2}' | xargs echo )

# deleting only cert-manager-webhook-tls and cert-manager-webhook-ca secrets fixed it for me. I also think only deleting cert-manager-webhook-tls might have solved it.
 kubectl delete secret -n $P_NS cert-manager-webhook-ca cert-manager-webhook-tls

 # Restart services
 kubectl scale sts -n $P_NS -l app.kubernetes.io/name=rabbitmq-ha --replicas=3

fi

kubectl delete pod -n $P_NS -l app.kubernetes.io/name=hephaestus

kubectl delete pod -n $P_NS -l app.kubernetes.io/name=repoman

echo "buildkit is stuck on verifying buildkitd:"
PLATTOKEN=$( kubectl get secret -n $P_NS |grep hephaestus-token-  |awk '{print $1}' )
kubectl delete secret -n $P_NS    hephaestus-buildkit-client-tls $PLATTOKEN
echo "Build are stuck randomly (wipe may fail since these secrets may not exist):"
kubectl delete secret -n $C_NS    hephaestus-buildkit-server-tls $PLATTOKEN 
kubectl delete secret -n $P_NS    hephaestus-buildkit-server-tls $PLATTOKEN 
# This requires nucleus service restart to become effective
# Typically x509 cert errors are seen and go away after the above
# but if it's only stuck on verifying and fails, restart nucleus

# STS='keycloak rabbitmq-ha'
STS='vault rabbitmq-ha'

for sts in $STS ; do
   echo "Restartingt STS $sts"
   SERVICE=$( kubectl get -n "$P_NS" sts -l app.kubernetes.io/name=${sts} | tail -1 |awk '{print $1}' )
   kubectl -n "$P_NS" rollout restart sts $SERVICE
done

# This is perhaps not ideal way - to avoid killing dispatcher. If this does not work then disable the following and instead add Deployment/nucleus-dispatcher to the SERVICES after this
# SERVICES='Deployment/nucleus-dispatcher'
# OLD=$( kubectl get pods -n $P_NS -l app.kubernetes.io/component=dispatcher  |grep nucleus |awk '{print $1}' |tail -1 )
# for SERVICE in $SERVICES; do
#    echo '--------------------'
#    echo "Resizing service $SERVICE in namespace $P_NS"
#    kubectl -n "$P_NS" scale  "$SERVICE" --replicas=2
#    sleep 100
#    kubectl delete pod -n $P_NS $OLD --force --grace-period=0
#    kubectl -n "$P_NS" scale  "$SERVICE" --replicas=1
#a done

# SERVICES='StatefulSet/keycloakv17 sts/rabbitmq-ha-39 Deployment/pusher-service Deployment/k8s-event-pump  Deployment/nucleus-dispatcher Deployment/nucleus-frontend '
# SERVICES='Deployment/pusher-service Deployment/k8s-event-pump  Deployment/nucleus-frontend '
SERVICES='Deployment/pusher-service Deployment/k8s-event-pump  Deployment/nucleus-dispatcher Deployment/nucleus-frontend '

for SERVICE in $SERVICES; do
   echo '--------------------'
   echo "Restarting service $SERVICE in namespace $P_NS"
   kubectl -n "$P_NS" rollout restart "$SERVICE"
   kubectl -n "$P_NS" rollout status "$SERVICE"
done

 
# Redundant, left in for 'old' restart order. Repeated after data-plane-agent
kubectl delete pod -n $P_NS -l app.kubernetes.io/name=pusher-service

SERVICES='Deployment/data-plane-agent'
echo "--------------------"
echo "Restarting service $SERVICE in namespace $C_NS"
for SERVICE in $SERVICES; do
   kubectl -n "$C_NS" rollout restart "$SERVICE"
   kubectl -n "$C_NS" rollout status "$SERVICE"
done

kubectl delete pod -n $P_NS -l app.kubernetes.io/name=pusher-service

