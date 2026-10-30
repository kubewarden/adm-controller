## Audit scanner

> [!NOTE]
> Don't forget to checkout [Kubewarden's Audit Scanner
> documentation](https://docs.kubewarden.io/admission-controller/latest/en/explanations/audit-scanner/audit-scanner.html) for
> more information

The Audit scanner inspects the resources defined in the cluster and
identifies the ones that are violating Kubewarden policies.

The results of the scan are stored in `PolicyReport` and `ClusterPolicyReports` custom resources.
Each resource has its own dedicated `PolicyReport` or `ClusterPolicyReport`, depending on the type of the resource.

See [Querying the reports](#querying-the-reports) for more information.

For implementation details, see [RFC-11](https://github.com/kubewarden/rfc/blob/main/rfc/0011-audit-checks.md),
[RFC-12](https://github.com/kubewarden/rfc/blob/main/rfc/0012-policy-report.md).

# Usage

```console
audit-scanner [flags]

Flags:
  -c, --cluster                       scan cluster wide resources
      --disable-store                 do not create, update or delete (Cluster)Reports in the cluster; scan results are only computed in memory (use with --output-scan)
  -f, --extra-ca string               File path to CA cert in PEM format of PolicyServer endpoints
  -h, --help                          help for audit-scanner
  -i, --ignore-namespaces strings     comma separated list of namespace names to be skipped from scan. This flag can be repeated
      --insecure-ssl                  skip SSL cert validation when connecting to PolicyServers endpoints. Useful for development
  -k, --kubewarden-namespace string   namespace where the Kubewarden components (e.g. PolicyServer) are installed (required) (default "kubewarden")
  -l, --loglevel string               level of the logs. Supported values are: [trace debug info warn error fatal] (default "info")
  -n, --namespace string              namespace to be evaluated
  -o, --output-scan                   print result of scan in JSON to stdout
      --page-size int                 number of resources to fetch from the Kubernetes API server when paginating (default 100)
      --parallel-namespaces int       number of Namespaces to scan in parallel (default 1)
      --parallel-policies int         number of policies to evaluate for a given resource in parallel (default 5)
      --parallel-resources int        number of resources to scan in parallel (default 100)
  -u, --policy-server-url string      URI to the PolicyServers the Audit Scanner will query. Example: https://localhost:3000. Useful for out-of-cluster debugging
```

## Examples

Scan the whole cluster:

```shell
audit-scanner  --kubewarden-namespace kubewarden --cluster
```

Scan a single namespace:

```shell
audit-scanner  --kubewarden-namespace kubewarden --namespace default
```

Disable storing the results in etcd (and skip deleting any existing reports) while printing the reports to stdout in JSON format:

```shell
audit-scanner  --kubewarden-namespace kubewarden --disable-store --output-scan
```

## Tuning

The audit scanner works by entering each Namespace of the cluster and finding all the policies that are "looking" at the contents of the Namespace.
It then identifies all the resource types that are relevant to these policies (e.g. Deployments, Pods, etc.) and iterates over each resource type.

When looking into a specific type of resource, audit-scanner fetches these objects in chunks. The size of the chunk can be set using the `--page-size` flag.
The scanner fetches one chunk of resources, then iterates over each one of them, evaluating all the policies that are looking at that specific resource.

Each iteration step can be done in parallel. The number of Namespaces to be evaluated at the same time can be set using the `--parallel-namespaces` flag.
The number of resources to be evaluated at the same time can be set using the `--parallel-resources` flag.
When evaluating the policies for a specific resource, the number of policies to be evaluated at the same time can be set using the `--parallel-policies` flag.

A concrete example:

- We have 5 namespaces, each with 1000 Pods.
- We have 10 `ClusterAdmissionPolicy` resources that are looking at Pods.
- We have set `--page-size=200`, `--parallel-namespaces=2`, `--parallel-resources=100`, and `--parallel-policies=5`.

The scanner will:

- Work on 2 Namespaces at the same time.
- Inside of each Namespace:
  - Fetch 200 Pods at the same time (`--page-size=200`).
  - Evaluate 100 Pods at the same time (`--parallel-resources=100`).
  - Evaluate 5 policies at the same time (`--parallel-policies=5`).

Things to consider:

- The pagination size has a direct impact on
  - The number of API calls that the scanner will make.
  - The amount of memory that the scanner will use.
- The maximum number of outgoing evaluation requests is the product of `--parallel-namespaces`, `--parallel-resources`, and `--parallel-policies`.

# Querying the reports

Using the `kubectl` command line tool, you can query the results of the scan:

List the reports in the default namespace:

```console
$ kubectl get polr -o wide

NAME                                   KIND         NAME                        PASS   FAIL   WARN   ERROR   SKIP   AGE
009805e4-6e16-4b70-80c9-cb33b6734c82   Deployment   deployment1                 5      1      0      0       0      1h
011e8ca7-40d5-4e76-8c89-6f820e24f895   Deployment   deployment2                 2      4      0      0       0      1h
02c28ab7-e332-47a2-9cc2-fe0fad5cd9ad   Pod          pod1                        10     0      0      0       0      1h
04937b2b-e68b-47d5-909d-d0ae75527f07   Pod          pod2                        9      1      0      0       0      1h
...
```

List the cluster-wide reports:

```console
$ kubectl get cpolr -o wide

NAME                                   KIND        NAME                 PASS   FAIL   WARN   ERROR   SKIP   AGE
261c9492-deec-4a09-8aa9-cd464bb4b8d1   Namespace   namespace1           3      1     0       0       0      1h
35ca342f-685b-4162-a342-8d7a52a61749   Namespace   namespace2           0      4     0       0       0      1h
3a8f8a88-338b-4905-b9e4-f13397a0d7b5   Namespace   namespace3           4      0     0       0       0      15h
```

Get the details of a specific report:

```console
$ kubectl get polr 009805e4-6e16-4b70-80c9-cb33b6734c82 -o yaml
```

Result:

```yaml
apiVersion: wgpolicyk8s.io/v1beta1
kind: PolicyReport
metadata:
  creationTimestamp: "2024-02-29T06:55:37Z"
  generation: 6
  labels:
    app.kubernetes.io/managed-by: kubewarden
  name: 009805e4-6e16-4b70-80c9-cb33b6734c82
  namespace: default
  ownerReferences:
    - apiVersion: apps/v1
      kind: Deployment
      name: deployment1
      uid: 009805e4-6e16-4b70-80c9-cb33b6734c82
  resourceVersion: "2685996"
  uid: c5a88847-d678-4733-8120-1b83fd6330cb
results:
  - category: Resource validation
    message: "The following mandatory labels are missing: cost-center"
    policy: clusterwide-safe-labels
    properties:
      policy-resource-version: "2684810"
      policy-uid: 826dd4ef-9db5-408e-9482-455f278bf9bf
      policy-name: safe-labels
      validating: "true"
    resourceSelector: {}
    result: fail
    scored: true
    severity: low
    source: kubewarden
    timestamp:
      nanos: 0
      seconds: 1709294251
# other results...
scope:
  apiVersion: apps/v1
  kind: Deployment
  name: deployment1
  namespace: default
  resourceVersion: "3"
  uid: 009805e4-6e16-4b70-80c9-cb33b6734c82
summary:
  error: 0
  fail: 10
  pass: 0
  skip: 0
  warn: 0
```

# Building

You can use the container image we maintain inside of our
[GitHub Container Registry](https://github.com/orgs/kubewarden/packages/container/package/audit-scanner).

Alternatively, the `audit-scanner` binary can be built in this way:

```shell
make build
```
