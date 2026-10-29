[![Artifact HUB](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/kubewarden-controller)](https://artifacthub.io/packages/helm/kubewarden/kubewarden-controller)

# adm-controller

`adm-controller` is a Kubernetes controller that allows you to
dynamically register Kubewarden admission policies.

The `adm-controller` reconciles the admission policies you
have registered with the Kubernetes webhooks of the cluster where
it's deployed.

## Usage

Once the adm-controller is up and running, you can define Kubewarden policies
using the `ClusterAdmissionPolicy` resource.

The documentation of this Custom Resource can be found
[here](https://github.com/kubewarden/adm-controller/blob/main/docs/crds/README.asciidoc)
or on [docs.crds.dev](https://doc.crds.dev/github.com/kubewarden/adm-controller).

> [!NOTE]
> `ClusterAdmissionPolicy` resources are cluster-wide.

### Deploy your first admission policy

The following snippet defines a Kubewarden Policy based on the
[psp-capabilities](https://github.com/kubewarden/psp-capabilities)
policy:

```yaml
apiVersion: policies.kubewarden.io/v1alpha2
kind: ClusterAdmissionPolicy
metadata:
  name: psp-capabilities
spec:
  module: registry://ghcr.io/kubewarden/policies/psp-capabilities:v0.1.3
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      resources: ["pods"]
      operations:
        - CREATE
        - UPDATE
  mutating: true
  settings:
    allowed_capabilities:
      - CHOWN
    required_drop_capabilities:
      - NET_ADMIN
```

This `ClusterAdmissionPolicy` evaluates all the `CREATE` and `UPDATE` operations
performed against Pods. The homepage of this policy provides more insights about
how this policy behaves.

Creating the resource inside Kubernetes is sufficient to enforce the policy:

```shell
kubectl apply -f https://raw.githubusercontent.com/kubewarden/adm-controller/main/config/samples/policies_v1alpha2_clusteradmissionpolicy.yaml
```

### Remove your first admission policy

You can delete the admission policy you just created:

```console
kubectl delete clusteradmissionpolicy psp-capabilities
kubectl patch clusteradmissionpolicy psp-capabilities -p '{"metadata":{"finalizers":null}}' --type=merge
```

## Learn more

The [documentation](https://docs.kubewarden.io) provides more insights
about how the project works and how to use it.

[How Kubewarden manages its certificates](certificate-management.md) describes
the certificates of the controller, the policy servers and the audit scanner:
who creates them, who renews them, and how the API server comes to trust them.
