# Openbao Provider for Secrets Store CSI Driver

> :warning: **Please note**: We take OpenBao's security and our users' trust very seriously. If
you believe you have found a security issue in OpenBao Helm, _please responsibly disclose_
by contacting us at [openbao-security@lists.openssf.org](mailto:openbao-security@lists.openssf.org).


[Openbao](https://openbao.org) provider for the [Secrets Store CSI driver](https://github.com/kubernetes-sigs/secrets-store-csi-driver) allows you to get secrets stored in
Openbao and use the Secrets Store CSI driver interface to mount them into Kubernetes pods.

## Installation

### Prerequisites

* Supported Kubernetes version, see the [documentation](https://openbao.org/docs/platform/k8s/csi#supported-kubernetes-versions) (runs on Linux nodes only)
* [Secrets store CSI driver](https://secrets-store-csi-driver.sigs.k8s.io/getting-started/installation.html) installed

### Using helm

The recommended installation method is via helm 3:

```bash
helm repo add openbao https://openbao.github.io/openbao-helm
# Just installs Openbao CSI provider. Adjust `server.enabled` and `injector.enabled`
# if you also want helm to install Openbao and the Openbao Agent injector.
helm install openbao openbao/openbao \
  --set "server.enabled=false" \
  --set "injector.enabled=false" \
  --set "csi.enabled=true"
```

### Using yaml

You can also install using the deployment config in the `deployment` folder:

```bash
kubectl apply -f deployment/openbao-csi-provider.yaml
```

## Usage

See the [documentation pages](https://openbao.org/docs/platform/k8s/csi) for
full details of deploying, configuring and using Openbao CSI provider. The
integration tests in [test/bats/provider.bats](./test/bats/provider.bats) also
provide a good set of fully worked and tested examples to build on.

## Troubleshooting

To troubleshoot issues with Openbao CSI provider, look at logs from the Openbao CSI
provider pod running on the same node as your application pod:

  ```bash
  kubectl get pods -o wide
  # find the Openbao CSI provider pod running on the same node as your application pod

  kubectl logs openbao-csi-provider-7x44t
  ```

Pass `-debug=true` to the provider to get more detailed logs. When installing
via helm, you can use `--set "csi.debug=true"`.

## Developing

The Makefile has targets to automate building and testing:

```bash
make build test
```

The project also uses some linting and formatting tools. To install the tools:

```bash
make bootstrap
```

You can then run the additional checks:

```bash
make fmt lint mod
```

To run a full set of integration tests on a local kind cluster, ensure you have
the following additional dependencies installed:

* `docker`
* [`kind`](https://github.com/kubernetes-sigs/kind)
* [`kubectl`](https://kubernetes.io/docs/tasks/tools/)
* [`helm`](https://helm.sh/docs/intro/install/)
* [`bats`](https://bats-core.readthedocs.io/en/stable/installation.html)

You can then run:

```bash
make setup-kind e2e-image e2e-setup e2e-test
```

Finally tidy up the resources created in the kind cluster with:

```bash
make e2e-teardown
```
