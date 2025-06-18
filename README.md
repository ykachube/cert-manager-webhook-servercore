# ACME webhook for Servercore DNS API forked from https://github.com/vadimkim/cert-manager-webhook-hetzner

This solver can be used when you want to use cert-manager with Servercore DNS API. API documentation is [here](https://dns.servercore.com/api-docs)

## Requirements
-   [go](https://golang.org/) >= 1.13.0
-   [helm](https://helm.sh/) >= v3.0.0
-   [kubernetes](https://kubernetes.io/) >= v1.14.0
-   [cert-manager](https://cert-manager.io/) >= 0.12.0

## Installation

### cert-manager

Follow the [instructions](https://cert-manager.io/docs/installation/) using the cert-manager documentation to install it within your cluster.

### Webhook

#### Using public helm chart
```bash
helm repo add cert-manager-webhook-servercore https://ykachube.github.io/cert-manager-webhook-servercore
# Replace the groupName value with your desired domain
helm install --namespace cert-manager cert-manager-webhook-servercore cert-manager-webhook-servercore/cert-manager-webhook-servercore --set groupName=acme.yourdomain.tld
```

#### From local checkout

```bash
helm install --namespace cert-manager cert-manager-webhook-servercore deploy/cert-manager-webhook-servercore
```
**Note**: The kubernetes resources used to install the Webhook should be deployed within the same namespace as the cert-manager.

To uninstall the webhook run
```bash
helm uninstall --namespace cert-manager cert-manager-webhook-servercore
```

## Issuer

Create a `ClusterIssuer` or `Issuer` resource as following:
(Keep in Mind that the Example uses the Staging URL from Let's Encrypt. Look at [Getting Start](https://letsencrypt.org/getting-started/) for using the normal Let's Encrypt URL.)
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    # The ACME server URL
    server: https://acme-staging-v02.api.letsencrypt.org/directory

    # Email address used for ACME registration
    email: mail@example.com # REPLACE THIS WITH YOUR EMAIL!!!

    # Name of a secret used to store the ACME account private key
    privateKeySecretRef:
      name: letsencrypt-staging

    solvers:
      - dns01:
          webhook:
            # This group needs to be configured when installing the helm package, otherwise the webhook won't have permission to create an ACME challenge for this API group.
            groupName: acme.yourdomain.tld
            solverName: servercore
            config:
              secretName: servercore-dns-credentials
              zoneName: example.com # (Optional): When not provided the Zone will searched in Servercore API by recursion on full domain name
              apiUrl: https://dns.servercore.com/api/v1
```

### Credentials
In order to access the Servercore API, the webhook needs an API token.

If you choose another name for the secret than `servercore-secret`, you must install the chart with a modified `secretName` value. Policies ensure that no other secrets can be read by the webhook. Also modify the value of `secretName` in the `[Cluster]Issuer`.

The secret for the example above will look like this:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: servercore-dns-credentials
  namespace: cert-manager
type: Opaque
stringData:
  username: "your-servercore-username"
  password: "your-servercore-password"
  account-id: "your-servercore-account-id"
  project-name: "your-servercore-project-name"
  # Optional: auth-url: "https://cloud.api.servercore.com/identity/v3"
```

### Create a certificate

Finally you can create certificates, for example:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-cert
  namespace: cert-manager
spec:
  commonName: example.com
  dnsNames:
    - example.com
  issuerRef:
    name: letsencrypt-staging
    kind: ClusterIssuer
  secretName: example-cert
```

## Development

### Running the test suite

All DNS providers **must** run the DNS01 provider conformance testing suite,
else they will have undetermined behaviour when used with cert-manager.

**It is essential that you configure and run the test suite when creating a
DNS01 webhook.**

First, you need to have Servercore account with access to DNS control panel. You need to create API token and have a registered and verified DNS zone there.
Then you need to replace `zoneName` parameter at `testdata/servercore/config.json` file with actual one.
You also must encode your api token into base64 and put the hash into `testdata/servercore/servercore-secret.yml` file.

You can then run the test suite with:

```bash
# first install necessary binaries (only required once)
./scripts/fetch-test-binaries.sh
# then run the tests
TEST_ZONE_NAME=example.com. make verify
```

## Creating new package

To build new Docker image for multiple architectures and push it to hub:
```shell
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t ykachube/cert-manager-webhook-servercore:1.2.0 . --push
```

To compile and publish new Helm chart version:
```shell
helm package deploy/cert-manager-webhook-servercore
git checkout gh-pages
helm repo index . --url https://ykachube.github.io/cert-manager-webhook-servercore/
```
