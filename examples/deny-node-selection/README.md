# Deny the selection of a node

This policy denies a workload that selects its node. It applies only outside a
list of admin namespaces.

It denies these fields in a Pod or in a pod template:

- `spec.nodeName`
- `spec.nodeSelector` (an empty map is allowed)
- `spec.affinity.nodeAffinity`

It checks these resources: Pods, ReplicationControllers, Deployments,
ReplicaSets, StatefulSets, DaemonSets, Jobs and CronJobs.

## Files

- `vap.yaml`: a Kubernetes `ValidatingAdmissionPolicy` with the CEL rules.
- `binding.yaml`: the `ValidatingAdmissionPolicyBinding`. Its
  `namespaceSelector` holds the list of admin namespaces.

## Set the admin namespaces

Edit the `values` list in `binding.yaml`. The policy does not run in the
namespaces in that list.

To exempt namespaces by label, replace the `kubernetes.io/metadata.name`
expression with your own label. For example:

```yaml
namespaceSelector:
  matchExpressions:
    - key: example.com/admin
      operator: DoesNotExist
```

Only a cluster admin should be able to set that label on a namespace.

## Install with Kubewarden

Convert the pair into a `ClusterAdmissionPolicy` with `kwctl`.

The first option uses the `cel-policy` module. Pin a release of the module in
place of `latest`:

```console
kwctl scaffold vap \
  --policy vap.yaml \
  --binding binding.yaml \
  --cel-policy ghcr.io/kubewarden/policies/cel-policy:latest \
  > deny-node-selection.yaml
kubectl apply -f deny-node-selection.yaml
```

The second option compiles the CEL rules into a standalone Wasm module.
`kwctl` writes `deny-node-selection.wasm` and `metadata.yml`. Push the module
to a registry, then set `spec.module` in the output to the registry URI:

```console
kwctl scaffold vap \
  --policy vap.yaml \
  --binding binding.yaml \
  --compile-to-wasm deny-node-selection.wasm \
  > deny-node-selection.yaml
```

You can also apply `vap.yaml` and `binding.yaml` directly to a Kubernetes
cluster that supports `ValidatingAdmissionPolicy`. That path does not use
Kubewarden.

## Behavior

- A CREATE that sets one of the fields is denied.
- An UPDATE is denied only when it adds or changes one of the fields. The
  scheduler sets `spec.nodeName` on every Pod. Thus a Pod that is already
  scheduled can still get new labels and annotations.
- The DaemonSet controller adds a `nodeAffinity` to each Pod that it creates.
  The policy allows that `nodeAffinity` when the request comes from
  `system:serviceaccount:kube-system:daemon-set-controller`. A DaemonSet that
  sets a node field in its own template is still denied.

Note the effect on workloads that already exist. Suppose a Deployment set a
`nodeSelector` before you installed the policy. The Deployment itself is still
accepted. Its controller cannot create a new ReplicaSet or Pod, because the
policy denies the `nodeSelector` on that new ReplicaSet or Pod. Before you set
the policy to `protect`, deploy it in `monitor` mode to find these workloads.
