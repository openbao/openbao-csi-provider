#!/usr/bin/env bats

load _helpers

export SETUP_TEARDOWN_OUTFILE=/dev/null
if [[ -n "${DISPLAY_SETUP_TEARDOWN_LOGS:-}" ]]; then
    export SETUP_TEARDOWN_OUTFILE=/dev/stdout
fi

# SKIP_TEARDOWN=true
export CONFIGS=test/bats/configs

setup() {
    # 1. Configure Openbao.

    # 1. a) Openbao policies
    cat $CONFIGS/openbao-policy-db.hcl | kubectl --namespace=csi exec -i openbao-0 -- bao policy write db-policy -
    cat $CONFIGS/openbao-policy-kv.hcl | kubectl --namespace=csi exec -i openbao-0 -- bao policy write kv-policy -
    cat $CONFIGS/openbao-policy-pki.hcl | kubectl --namespace=csi exec -i openbao-0 -- bao policy write pki-policy -
    cat $CONFIGS/openbao-policy-kv-custom-audience.hcl | kubectl --namespace=csi exec -i openbao-0 -- bao policy write kv-custom-audience-policy -

    # 1. b) i) Setup kubernetes auth engine.
    kubectl --namespace=csi exec openbao-0 -- bao auth enable kubernetes

    kubectl --namespace=csi exec openbao-0 -- sh -c 'bao write auth/kubernetes/config \
        kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443"'

    kubectl --namespace=csi exec openbao-0 -- bao write auth/kubernetes/role/db-role \
        bound_service_account_names=nginx-db \
        bound_service_account_namespaces=test \
        audience=openbao \
        policies=db-policy \
        ttl=20m

    kubectl --namespace=csi exec openbao-0 -- bao write auth/kubernetes/role/kv-role \
        bound_service_account_names=nginx-kv \
        bound_service_account_namespaces=test \
        audience=openbao \
        policies=kv-policy \
        ttl=20m

    kubectl --namespace=csi exec openbao-0 -- bao write auth/kubernetes/role/kv-custom-audience-role \
        audience=custom-audience \
        bound_service_account_names=nginx-kv-custom-audience \
        bound_service_account_namespaces=test \
        policies=kv-custom-audience-policy \
        ttl=20m

    kubectl --namespace=csi exec openbao-0 -- bao write auth/kubernetes/role/pki-role \
        bound_service_account_names=nginx-pki \
        bound_service_account_namespaces=test \
        audience=openbao \
        policies=pki-policy \
        ttl=20m

    kubectl --namespace=csi exec openbao-0 -- bao write auth/kubernetes/role/all-role \
        bound_service_account_names=nginx-all \
        bound_service_account_namespaces=test \
        audience=openbao \
        policies=db-policy,kv-policy,pki-policy \
        ttl=20m

    # 1. b) ii) Setup JWT auth
    kubectl --namespace=csi exec openbao-0 -- bao auth enable jwt

    kubectl --namespace=csi exec openbao-0 -- bao write auth/jwt/config \
        oidc_discovery_url=https://kubernetes.default.svc.cluster.local \
        oidc_discovery_ca_pem=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

    kubectl --namespace=csi exec openbao-0 -- bao write auth/jwt/role/jwt-kv-role \
        role_type="jwt" \
        bound_audiences="openbao" \
        user_claim="sub" \
        bound_subject="system:serviceaccount:test:nginx-kv" \
        policies="kv-policy" \
        ttl="1h"

    # 1. c) Setup pki secrets engine.
    kubectl --namespace=csi exec openbao-0 -- bao secrets enable pki
    kubectl --namespace=csi exec openbao-0 -- bao write -field=certificate pki/root/generate/internal \
        common_name="example.com"
    kubectl --namespace=csi exec openbao-0 -- bao write pki/config/urls \
        issuing_certificates="http://127.0.0.1:8200/v1/pki/ca"
    kubectl --namespace=csi exec openbao-0 -- bao write pki/roles/example-dot-com \
        allowed_domains="example.com" \
        allow_subdomains=true

    # 1. d) Setup kv secrets in Openbao.
    kubectl --namespace=csi exec openbao-0 -- bao secrets enable -path=secret -version=2 kv
    kubectl --namespace=csi exec openbao-0 -- bao kv put secret/kv1 bar1=hello1
    kubectl --namespace=csi exec openbao-0 -- bao kv put secret/kv2 bar2=hello2
    kubectl --namespace=csi exec openbao-0 -- bao kv put secret/kv-sync1 bar1=hello-sync1
    kubectl --namespace=csi exec openbao-0 -- bao kv put secret/kv-sync2 bar2=hello-sync2
    kubectl --namespace=csi exec openbao-0 -- bao kv put secret/kv-sync3 bar3=aGVsbG8tc3luYzM=
    kubectl --namespace=csi exec openbao-0 -- bao kv put secret/kv-custom-audience bar=hello-custom-audience

    # 2. Create shared k8s resources.
    kubectl create namespace test
    kubectl --namespace=test apply -f $CONFIGS/openbao-all-secretproviderclass.yaml
    kubectl --namespace=test apply -f $CONFIGS/openbao-db-secretproviderclass.yaml
    kubectl --namespace=test apply -f $CONFIGS/openbao-kv-custom-audience-secretproviderclass.yaml
    kubectl --namespace=test apply -f $CONFIGS/openbao-kv-namespace-secretproviderclass.yaml
    kubectl --namespace=test apply -f $CONFIGS/openbao-kv-secretproviderclass.yaml
    kubectl --namespace=test apply -f $CONFIGS/openbao-kv-secretproviderclass-jwt-auth.yaml
    kubectl --namespace=test apply -f $CONFIGS/openbao-kv-sync-secretproviderclass.yaml
    kubectl --namespace=test apply -f $CONFIGS/openbao-kv-sync-multiple-secretproviderclass.yaml
    kubectl --namespace=test apply -f $CONFIGS/openbao-pki-secretproviderclass.yaml
}

teardown() {
    if [[ -n $SKIP_TEARDOWN ]]; then
        echo "Skipping teardown"
        return
    fi

    { # Braces used to redirect all teardown logs.

    # If the test failed, print some debug output
    if [[ "$BATS_ERROR_STATUS" -ne 0 ]]; then
        echo "DESCRIBE NGINX PODS"
        kubectl describe pod -l app=nginx --all-namespaces=true
        echo "PROVIDER LOGS"
        kubectl --namespace=csi logs -l app=openbao-csi-provider --tail=50
        echo "OPENBAO LOGS"
        kubectl --namespace=csi logs openbao-0
    fi

    # Teardown Openbao configuration.
    kubectl --namespace=csi exec openbao-0 -- bao auth disable kubernetes
    kubectl --namespace=csi exec openbao-0 -- bao auth disable jwt
    kubectl --namespace=csi exec openbao-0 -- bao secrets disable secret
    kubectl --namespace=csi exec openbao-0 -- bao secrets disable pki
    kubectl --namespace=csi exec openbao-0 -- bao secrets disable database
    kubectl --namespace=csi exec openbao-0 -- bao policy delete example-policy
    kubectl --namespace=csi exec openbao-0 -- bao kv delete secret/kv1
    kubectl --namespace=csi exec openbao-0 -- bao kv delete secret/kv2
    kubectl --namespace=csi exec openbao-0 -- bao kv delete secret/kv-custom-audience
    kubectl --namespace=csi exec openbao-0 -- bao kv delete secret/kv-sync1
    kubectl --namespace=csi exec openbao-0 -- bao kv delete secret/kv-sync2
    kubectl --namespace=csi exec openbao-0 -- bao kv delete secret/kv-sync3

    # Teardown shared k8s resources.
    kubectl delete --ignore-not-found namespace test
    kubectl delete --ignore-not-found namespace negative-test-ns
    } > $SETUP_TEARDOWN_OUTFILE
}

@test "1 Inline secrets-store-csi volume" {
    helm --namespace=test install nginx $CONFIGS/nginx \
        --set engine=kv --set sa=kv \
        --wait --timeout=5m

    kubectl get pods -n test

    result=$(kubectl --namespace=test exec nginx-kv -- cat /mnt/secrets-store/secret-1)
    [[ "$result" == "hello1" ]]

    # Check file permission is non-default
    result=$(kubectl --namespace=test exec nginx-kv -- stat -c '%a' /mnt/secrets-store/..data/secret-1)
    [[ "$result" == "600" ]]

    result=$(kubectl --namespace=test exec nginx-kv -- cat /mnt/secrets-store/secret-2)
    [[ "$result" == "hello2" ]]

    # Check file permission is default
    result=$(kubectl --namespace=test exec nginx-kv -- stat -c '%a' /mnt/secrets-store/..data/secret-2)
    [[ "$result" == "644" ]]
}

@test "2 Sync with kubernetes secrets" {
    # Deploy some pods that should cause k8s secrets to be created.
    kubectl --namespace=test apply -f $CONFIGS/nginx-kv-env-var.yaml

    # This line sometimes throws an error
    kubectl --namespace=test wait --for=condition=Ready --timeout=5m pod -l app=nginx

    POD=$(kubectl --namespace=test get pod -l app=nginx -o jsonpath="{.items[0].metadata.name}")
    result=$(kubectl --namespace=test exec $POD -- cat /mnt/secrets-store/secret-1)
    [[ "$result" == "hello-sync1" ]]

    result=$(kubectl --namespace=test exec $POD -- cat /mnt/secrets-store/secret-2)
    [[ "$result" == "hello-sync2" ]]

    run kubectl get secret --namespace=test kvsecret
    [ "$status" -eq 0 ]

    result=$(kubectl --namespace=test get secret kvsecret -o jsonpath="{.data.pwd}" | base64 -d)
    [[ "$result" == "hello-sync1" ]]

    result=$(kubectl --namespace=test exec $POD -- printenv | grep SECRET_USERNAME | awk -F"=" '{ print $2 }' | tr -d '\r\n')
    [[ "$result" == "hello-sync2" ]]

    result=$(kubectl --namespace=test get secret kvsecret -o jsonpath="{.data.username_b64}" | base64 -d)
    [[ "$result" == "hello-sync3" ]]

    result=$(kubectl --namespace=test get secret kvsecret -o jsonpath="{.metadata.labels.environment}")
    [[ "${result//$'\r'}" == "test" ]]

    result=$(kubectl --namespace=test get secret kvsecret -o jsonpath="{.metadata.labels.secrets-store\.csi\.k8s\.io/managed}")
    [[ "${result//$'\r'}" == "true" ]]

    # There isn't really an event we can wait for to ensure this has happened.
    for i in {0..60}; do
        result="$(kubectl --namespace=test get secret kvsecret -o json | jq '.metadata.ownerReferences | length')"
        if [[ "$result" -eq 1 ]]; then
            break
        fi
        sleep 1
    done
    # The secret's owner is the ReplicaSet created by the deployment from $CONFIGS/nginx-kv-env-var.yaml
    [[ "$result" -eq 1 ]]

    # Wait for secret deletion in a background process.
    kubectl --namespace=test wait --for=delete --timeout=60s secret kvsecret &
    WAIT_PID=$!

    # Trigger deletion implicitly by deleting only owners.
    kubectl --namespace=test delete -f $CONFIGS/nginx-kv-env-var.yaml
    echo "Waiting for kvsecret to get deleted"
    wait $WAIT_PID

    # Ensure it actually got deleted.
    run kubectl --namespace=test get secret kvsecret
    [ "$status" -eq 1 ]
}

@test "3 SecretProviderClass in different namespace not usable" {
    kubectl create namespace negative-test-ns
    helm --namespace=negative-test-ns install nginx $CONFIGS/nginx \
        --set engine=kv --set sa=kv
    kubectl --namespace=negative-test-ns wait --for=condition=PodScheduled --timeout=60s pod nginx-kv

    wait_for_success "kubectl --namespace=negative-test-ns describe pod nginx-kv | grep 'FailedMount.*failed to get secretproviderclass negative-test-ns/openbao-kv.*not found'"
}

@test "4 Pod with multiple SecretProviderClasses" {
    POD=nginx-multiple-volumes
    kubectl --namespace=test apply -f $CONFIGS/nginx-kv-multiple-volumes.yaml
    kubectl --namespace=test wait --for=condition=Ready --timeout=5m pod $POD

    result=$(kubectl --namespace=test exec $POD -- cat /mnt/secrets-store-1/secret-1)
    [[ "$result" == "hello-sync1" ]]
    result=$(kubectl --namespace=test exec $POD -- cat /mnt/secrets-store-2/secret-2)
    [[ "$result" == "hello-sync2" ]]

    result=$(kubectl --namespace=test get secret kvsecret-1 -o jsonpath="{.data.username}" | base64 -d)
    [[ "$result" == "hello-sync1" ]]
    result=$(kubectl --namespace=test get secret kvsecret-2 -o jsonpath="{.data.pwd}" | base64 -d)
    [[ "$result" == "hello-sync2" ]]

    result=$(kubectl --namespace=test exec $POD -- printenv | grep SECRET_1_USERNAME | awk -F"=" '{ print $2 }' | tr -d '\r\n')
    [[ "$result" == "hello-sync1" ]]
    result=$(kubectl --namespace=test exec $POD -- printenv | grep SECRET_2_PWD | awk -F"=" '{ print $2 }' | tr -d '\r\n')
    [[ "$result" == "hello-sync2" ]]
}

@test "5 SecretProviderClass with query parameters and PUT method" {
    helm --namespace=test install nginx $CONFIGS/nginx \
        --set engine=pki --set sa=pki \
        --wait --timeout=5m

    result=$(kubectl --namespace=test exec nginx-pki -- cat /mnt/secrets-store/certs)
    [[ "$result" != "" ]]

    # Ensure we have some valid x509 certificates.
    echo "$result" | jq -r '.data.certificate' | openssl x509 -noout
    echo "$result" | jq -r '.data.issuing_ca' | openssl x509 -noout
    echo "$result" | jq -r '.data.certificate' | openssl x509 -noout -text | grep "test.example.com"
}

@test "6 Dynamic secrets engine, endpoint is called only once per SecretProviderClass" {
    setup_postgres

    # Now deploy a pod that will generate some dynamic credentials.
    helm --namespace=test install nginx $CONFIGS/nginx \
        --set engine=db --set sa=db \
        --wait --timeout=5m

    # Read the creds out of the pod and verify they work for a query.
    DYNAMIC_USERNAME=$(kubectl --namespace=test exec nginx-db -- cat /mnt/secrets-store/dbUsername)
    DYNAMIC_PASSWORD=$(kubectl --namespace=test exec nginx-db -- cat /mnt/secrets-store/dbPassword)
    result=$(kubectl --namespace=test exec postgres -- psql postgres://${DYNAMIC_USERNAME}:${DYNAMIC_PASSWORD}@127.0.0.1:5432/db --command="SELECT usename FROM pg_catalog.pg_user" --csv | sed -n '3 p')

    [[ "$result" != "" ]]
    [[ "$result" == "${DYNAMIC_USERNAME}" ]]
}

@test "7 SecretProviderClass with multiple secret types" {
    setup_postgres

    helm --namespace=test install nginx $CONFIGS/nginx \
        --set engine=all --set sa=all \
        --wait --timeout=5m

    # Verify dynamic database creds.
    DYNAMIC_USERNAME=$(kubectl --namespace=test exec nginx-all -- cat /mnt/secrets-store/dbUsername)
    DYNAMIC_PASSWORD=$(kubectl --namespace=test exec nginx-all -- cat /mnt/secrets-store/dbPassword)
    result=$(kubectl --namespace=test exec postgres -- psql postgres://${DYNAMIC_USERNAME}:${DYNAMIC_PASSWORD}@127.0.0.1:5432/db --command="SELECT usename FROM pg_catalog.pg_user" --csv | sed -n '3 p')

    [[ "$result" != "" ]]
    [[ "$result" == "${DYNAMIC_USERNAME}" ]]

    # Verify kv secret.
    result=$(kubectl --namespace=test exec nginx-all -- cat /mnt/secrets-store/secret-1)
    [[ "$result" == "hello1" ]]

    # Verify certificates.
    result=$(kubectl --namespace=test exec nginx-all -- cat /mnt/secrets-store/certs)
    [[ "$result" != "" ]]

    echo "$result" | jq -r '.data.certificate' | openssl x509 -noout
    echo "$result" | jq -r '.data.issuing_ca' | openssl x509 -noout
    echo "$result" | jq -r '.data.certificate' | openssl x509 -noout -text | grep "test.example.com"
}

@test "8 Wrong service account does not have access to Openbao" {
    helm --namespace=test install nginx $CONFIGS/nginx \
        --set engine=kv --set sa=pki
    kubectl --namespace=test wait --for=condition=PodScheduled --timeout=60s pod nginx-kv

    wait_for_success "kubectl --namespace=test describe pod nginx-kv | grep 'FailedMount.*failed to mount secrets store objects for pod test/nginx-kv'"
    wait_for_success "kubectl --namespace=test describe pod nginx-kv | grep 'service account name not authorized'"
}

@test "9 Custom audience" {
    helm --namespace=test install nginx $CONFIGS/nginx \
        --set engine=kv-custom-audience --set sa=kv-custom-audience \
        --wait --timeout=5m

    result=$(kubectl --namespace=test exec nginx-kv-custom-audience -- cat /mnt/secrets-store/secret)
    [[ "$result" == "hello-custom-audience" ]]
}

@test "10 Consistent version hashes" {
    helm --namespace=test install nginx $CONFIGS/nginx \
        --set engine=kv --set sa=kv \
        --wait --timeout=5m

    # HMAC secret should exist.
    kubectl --namespace=csi get secrets openbao-csi-provider-hmac-key

    # Save the status UID and secret versions.
    statusUID1=$(kubectl --namespace=test get secretproviderclasspodstatus nginx-kv-test-openbao-kv -o jsonpath='{.metadata.uid}')
    versions1=$(kubectl --namespace=test get secretproviderclasspodstatus nginx-kv-test-openbao-kv -o jsonpath='{.status.objects[*].version}')

    # Recreate the pod, which should remount the secrets and recreate the status object.
    helm --namespace=test uninstall nginx
    helm --namespace=test install nginx $CONFIGS/nginx \
        --set engine=kv --set sa=kv \
        --wait --timeout=5m

    # Now the uid should be different, but versions should still be the same.
    statusUID2=$(kubectl --namespace=test get secretproviderclasspodstatus nginx-kv-test-openbao-kv -o jsonpath='{.metadata.uid}')
    versions2=$(kubectl --namespace=test get secretproviderclasspodstatus nginx-kv-test-openbao-kv -o jsonpath='{.status.objects[*].version}')

    [[ "$statusUID1" != "$statusUID2" ]]
    [[ "$versions1" == "$versions2" ]]

    # Finally, delete the HMAC secret and recreate the pod one more time.
    # The HMAC secret should get regenerated and the secret versions should then change.
    kubectl --namespace=csi delete secret openbao-csi-provider-hmac-key
    helm --namespace=test uninstall nginx
    helm --namespace=test install nginx $CONFIGS/nginx \
        --set engine=kv --set sa=kv \
        --wait --timeout=5m

    kubectl --namespace=csi get secrets openbao-csi-provider-hmac-key

    statusUID3=$(kubectl --namespace=test get secretproviderclasspodstatus nginx-kv-test-openbao-kv -o jsonpath='{.metadata.uid}')
    versions3=$(kubectl --namespace=test get secretproviderclasspodstatus nginx-kv-test-openbao-kv -o jsonpath='{.status.objects[*].version}')

    [[ "$statusUID1" != "$statusUID3" ]]
    [[ "$statusUID2" != "$statusUID3" ]]
    [[ "$versions2" != "$versions3" ]]
}

@test "11 JWT auth" {
    helm --namespace=test install nginx $CONFIGS/nginx \
        --set engine=kv-jwt-auth --set sa=kv \
        --wait --timeout=5m

    result=$(kubectl --namespace=test exec nginx-kv-jwt-auth -- cat /mnt/secrets-store/secret-1)
    [[ "$result" == "hello1" ]]
}
