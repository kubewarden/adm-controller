# How Kubewarden manages its certificates

This document describes how Kubewarden creates, renews, and trusts its
certificates. It names each certificate, the component that creates it, the
component that renews it, and the component that writes the trust into the API
server. Then it walks through the common scenarios.

## Summary

Kubewarden runs its own small certificate authority. The controller creates
the certificates, renews them, and writes the trust into the API server. The
Helm chart renders no certificate. Each object has one owner:

- The **init mode** of the controller runs in the init container of every
  controller pod. It creates the certificate Secrets that are missing. It
  creates the two webhook configurations of the controller, or updates them to
  the webhooks of the controller version.
- The **cert controller** owns every certificate Secret. It creates a Secret
  again if a user deletes it, rotates the CA root, and renews every
  certificate. After the creation of a webhook configuration, it is the only
  writer of `caBundle`.
- The **policy reconcilers** own the webhook configuration of each policy.
  They write `caBundle` once, when they create it.
- The **PolicyServer reconciler** creates the first certificate of each policy
  server.
- The **cleanup mode** of the controller runs in the pre-delete hook of the
  chart. It deletes all of these objects on an uninstall.
- The **pre-upgrade mode** of the controller runs in the pre-upgrade hook of
  the chart. It marks the certificate Secrets and the webhook configurations
  of the controller, so that Helm and Argo CD do not delete them on an
  upgrade from a chart version that renders them.

## Terms

- **Certificate authority (CA):** a key pair that signs other certificates.
  Kubewarden has one. The code calls it the **CA root**.
- **Serving certificate:** the certificate that a server presents to a client.
  The CA root signs it. Some texts call it the leaf certificate.
- **Client certificate:** the certificate that a client presents to a server.
  The audit scanner has one.
- **Secret:** the Kubernetes object that stores a certificate and its key.
- **Webhook configuration:** a `ValidatingWebhookConfiguration` or a
  `MutatingWebhookConfiguration`. It tells the API server where to send a
  request, and which CA to trust.
- **`caBundle`:** the field `webhooks[].clientConfig.caBundle` of a webhook
  configuration. It holds the CA certificates that the API server trusts for
  that webhook. The code calls its value the **CA bundle**. Its content is
  `ca.crt`, followed by `old-ca.crt` if the CA root Secret has it.
- **Reconciler:** a loop that reads the state of the cluster and writes the
  state that it wants.
- **Init container:** a container of a pod that runs to the end before the
  other containers start.
- **Rotation:** the replacement of a CA root with a new one.
- **Renewal:** the replacement of a serving or client certificate with a new
  one, signed by the current CA root.
- **Kubelet:** the agent on each node. It copies a Secret into the volume of a
  pod, and updates the copy when the Secret changes.
- **The Kubewarden label:** `app.kubernetes.io/part-of: kubewarden`. The cert
  controller selects the Secrets and the webhook configurations by this label.

## The objects and their owners

| Object | Content | Created by | Renewed or rotated by | `caBundle` written by | Mounted by |
|---|---|---|---|---|---|
| Secret `kubewarden-ca` | `ca.crt`, `ca.key`, and `old-ca.crt` for up to 60 days after a rotation | Init mode, or the cert controller if it is missing | Cert controller | — | Audit scanner (`ca.crt` only) |
| Secret `kubewarden-webhook-server-cert` | `tls.crt`, `tls.key` of the controller webhook server | Init mode, or the cert controller if it is missing | Cert controller | — | Controller pod, in the init container and in the controller container |
| Secret `kubewarden-audit-scanner-client-cert` | `tls.crt`, `tls.key` of the audit scanner | Init mode, or the cert controller if it is missing | Cert controller | — | Audit scanner |
| Secret `policy-server-<name>`, one per policy server | `tls.crt`, `tls.key` of that policy server | PolicyServer reconciler | Cert controller | — | That policy server |
| `kubewarden-controller-validating-webhook-configuration` and `kubewarden-controller-mutating-webhook-configuration` | The webhooks for the Kubewarden CRDs | Init mode, which also updates their webhooks | — | Init mode for a new webhook, then the cert controller | — |
| Webhook configuration of each policy | One webhook per policy | Policy reconcilers | — | Policy reconcilers at creation, then the cert controller | — |

All of these objects carry the Kubewarden label. The cert controller finds the
policy server Secrets by the Kubewarden label and by
`app.kubernetes.io/component: policy-server`.

## The numbers

| Value | Time | Where |
|---|---|---|
| Life of the CA root | 10 years | `constants.CACertExpiration` |
| Life of a serving or client certificate | 1 year | `constants.ServerCertExpiration` |
| Renewal and rotation start | 60 days before the end | `constants.CertLookahead` |
| Pass of the cert controller with no event | every 12 hours | `reconcileInterval` |
| Retry of a failed pass | from 5 milliseconds, doubled on each failure, up to about 16 minutes | default backoff of the work queue |
| Wait of the init mode for the certificate files | up to 5 minutes, a check every 2 seconds | `bootstrap.CertificateFilesTimeout` |

## The actors

### The Helm chart

Files: `charts/admission-controller/templates/controller/deployment.yaml`,
`pre-delete-hook.yaml`, `pre-upgrade-hook.yaml`.

The chart renders no certificate, no CA bundle, and no webhook configuration
of the controller. It renders:

- The controller Deployment, with an init container that runs the controller
  binary with `--mode=init`, and the controller container. Both containers
  mount the Secret `kubewarden-webhook-server-cert` at
  `/tmp/k8s-webhook-server/serving-certs`. The volume is `optional: true`, so
  the pod starts before the Secret exists.
- The pre-delete hook, a Job that runs the controller binary with
  `--mode=cleanup`.
- The pre-upgrade hook, a Job that runs the controller binary with
  `--mode=pre-upgrade`. It has its own ServiceAccount, with `get` and `patch`
  on the three certificate Secrets and the two webhook configurations of the
  controller, and on nothing else.

The init container gets the same two values as the controller container: the
namespace and the name of the webhook Service. The names of the Secrets and of
the webhook configurations are constants in the code.

The init container and the containers of the hook Jobs also get the variables
of `additionalEnvironmentVariables`, as the controller container does. All of
them connect to the API server, so a variable that the controller needs to
reach it, for example a proxy, applies to all of them.

### The init mode

Files: `cmd/controller/init.go`, `internal/bootstrap/bootstrap.go`.

Every controller pod runs the init mode in its init container, before the
controller container starts. It uses a plain client, with no cache and no
leader election. It does these steps, in this order:

1. **Make sure that the certificate Secrets exist.** For `kubewarden-ca`,
   `kubewarden-webhook-server-cert`, and `kubewarden-audit-scanner-client-cert`:
   if the Secret exists, keep it as it is. If it is missing, create it. A new
   CA root lives 10 years. A new certificate lives 1 year and is signed by the
   CA root in `kubewarden-ca`. The certificate of the webhook server is for the
   DNS name of the webhook Service.
2. **Make sure that the webhook configurations of the controller exist.**
   Create the two webhook configurations, or update the ones that exist. The
   webhooks come from `internal/bootstrap/manifests.yaml`, which
   `make manifests` generates from the `+kubebuilder:webhook` markers. Each
   webhook points at the webhook Service. A webhook that exists keeps its
   `caBundle`. A new webhook gets the CA bundle of `kubewarden-ca`. The labels
   and the annotations that other tools set stay. The update carries the
   version of the object that the init mode read. If the cert controller
   writes the object in between, the API server rejects the update, and the
   init mode stops with an error. The kubelet starts the init container
   again, and the next run reads the object again and keeps the new
   `caBundle`.
3. **Wait for the certificate files.** Wait until `tls.crt` and `tls.key` are
   in `/tmp/k8s-webhook-server/serving-certs` and form a valid key pair. The
   volume belongs to the pod, so the controller container finds the files when
   it starts. After 5 minutes, exit with an error. The kubelet then starts the
   init container again.

Many replicas can run the init mode at the same time. The creation of a Secret
is atomic: if another replica creates the Secret first, this replica reads it
and signs its certificates with that CA root.

### The cert controller (`CertReconciler`)

File: `internal/controller/cert_controller.go`.

The cert controller is a controller-runtime controller. It runs on the leader
only. A pass runs:

- at the start of the controller
- every 12 hours
- when a Secret with the Kubewarden label in the namespace of Kubewarden is
  created, changes its data, or is deleted
- when a webhook configuration with the Kubewarden label is created, or a
  `caBundle` changes
- after a failed pass, with the backoff of the work queue.

All events go to the same request, so at most one pass waits in the queue. One
pass does these steps, in this order:

1. **Make sure that the CA root Secret exists.** If `kubewarden-ca` is
   missing, create it with a new CA root.
2. **Rotate the CA root.** If the CA root ends within 60 days, create a new CA
   root. Write `ca.crt` (new), `ca.key` (new), and `old-ca.crt` (the previous
   CA) into `kubewarden-ca`.
3. **Remove the old CA root.** If `old-ca.crt` exists and is past its end,
   delete it from `kubewarden-ca`.
4. **Write the CA bundle.** Build the CA bundle from `kubewarden-ca`. List
   every webhook configuration with the Kubewarden label: the two of the
   controller, one per policy, and any other one with the label. Patch each
   `caBundle` that differs. If a patch fails, stop the pass and return the
   error. No certificate is signed in that pass.
5. **Make sure that the other certificate Secrets exist.** If
   `kubewarden-webhook-server-cert` or `kubewarden-audit-scanner-client-cert`
   is missing, sign a new certificate with the CA root and create the Secret,
   with the same code as the init mode. This step comes after step 4, because
   an earlier pass can have rotated the CA root and failed to write the CA
   bundle.
6. **Renew the serving certificates.** For the webhook server certificate and
   each policy server certificate: if the certificate ends within 60 days, or
   the current CA root did not sign it, or the DNS name does not match, sign a
   new one with the CA root and write the Secret.
7. **Renew the client certificate of the audit scanner,** by the same rule.

### The policy reconcilers

Files: `internal/controller/policy_subreconciler.go`,
`policy_subreconciler_webhook.go`.

There are four of them, one per policy kind. Each one creates the webhook
configuration of a policy when its policy server is ready, and deletes it with
the policy. When they create the webhook configuration, they write the CA
bundle of `kubewarden-ca` into `caBundle`. The API server calls the policy
server at once, so the first value must be correct. When the webhook
configuration exists, they keep its live `caBundle`, if it is not empty, and
change only the other fields.

A write replaces the list of webhooks as a whole, `caBundle` included. So the
policy reconcilers write the object with an update, which carries the version
of the object that they read. If the cert controller writes a new `caBundle`
between the read and the update, the API server rejects the update. The
reconcile fails, and the work queue runs it again. The next reconcile reads
the object again, and keeps the new `caBundle`. Without this check, a change
of a rule during a rotation of the CA root can undo the new `caBundle`.

### The PolicyServer reconciler

File: `internal/controller/policyserver_controller_cert_secret.go`.

When a `PolicyServer` is created, this reconciler creates its Secret, with the
Kubewarden label and `app.kubernetes.io/component: policy-server`, and signs
the first serving certificate with the current CA root. It does not renew. It
signs again only if the Secret has no certificate, or an old format version.

### The cleanup mode

Files: `cmd/controller/cleanup.go`, `internal/cleanup/cleanup.go`.

The pre-delete hook of the chart runs the cleanup mode on `helm uninstall`. It
deletes the controller Deployment and waits until its pods are gone, so that
nothing creates the objects again. Then it deletes every webhook configuration
with the Kubewarden label, the resources of the policy servers, and the three
certificate Secrets of the controller.

### The pre-upgrade mode

Files: `cmd/controller/preupgrade.go`, `internal/upgrade/upgrade.go`.

Older chart versions render the three certificate Secrets and the two
webhook configurations of the controller. This chart does not. On an upgrade,
Helm deletes each object that leaves the chart, and Argo CD prunes it. Helm
does not delete an object whose live version has the annotation
`helm.sh/resource-policy: keep`. Argo CD does not prune an object whose live
version has `Prune=false` in the annotation `argocd.argoproj.io/sync-options`.

The pre-upgrade hook runs before Helm deletes anything. For each of the five
objects, the pre-upgrade mode:

1. Skips the object if it does not exist.
2. Skips the object if it has both annotations already.
3. Adds `helm.sh/resource-policy: keep`, and adds `Prune=false` to the Argo CD
   sync options that the object already has. It uses a merge patch, so it
   changes only the annotations.

Helm and Argo CD then leave the objects in place, and the controller keeps
using them. The cleanup mode deletes them on an uninstall.

Argo CD runs a Helm pre-upgrade hook as a `PreSync` hook, on every sync. On
the first sync, the objects do not exist, and the hook does nothing. The Job
has its own ServiceAccount because, on the first sync, the ServiceAccount of
the controller does not exist yet.

### The servers and the clients

- The **controller webhook server** reads its certificate from
  `/tmp/k8s-webhook-server/serving-certs`. The controller-runtime webhook
  server reloads the files when they change.
- Each **policy server** reads its certificate from its mounted Secret. It
  watches the directory with inotify and reloads the files when they change
  (`crates/policy-server/src/certs.rs`). A change of the Secret does not
  restart the pod.
- The **audit scanner** is a CronJob. Each run mounts `ca.crt` from
  `kubewarden-ca` and its client certificate. It trusts `ca.crt` alone, not
  `old-ca.crt`.
- The **API server** reads `caBundle` on each call to a webhook. It accepts the
  server if a CA in the bundle signed the serving certificate.

## How a new certificate reaches a pod

A write to a Secret does not reach the pod at once. The kubelet copies the
Secret into the volume on its sync period, about one minute. Then the server
reloads the file.

## The safety rule

A server must never present a certificate that the API server cannot accept.

The API server accepts a certificate when a CA in `caBundle` signed it. After a
rotation, the new CA root must be in every `caBundle` before any server
presents a certificate signed by it. One pass of the cert controller does it
in this order:

1. It writes the new CA root into `kubewarden-ca`, with the previous CA as
   `old-ca.crt`.
2. It writes `ca.crt + old-ca.crt` into every `caBundle`. A successful patch
   means that the API server stored it.
3. It signs the serving certificates with the new CA, and creates the
   certificate Secrets that are missing.
4. The kubelet updates the volumes. The servers reload. The API server accepts
   them, because the bundle holds the new CA.

Steps 1 to 3 run in one function. If step 2 fails, step 3 does not run. The
next pass writes the bundle again before it signs or creates any certificate.
So a certificate Secret that a user deletes after a failed step 2 does not
come back with a certificate that the API server cannot accept.

A stored bundle is not yet a bundle in use. The admission code of each API
server reads the webhook configurations from a local cache. A watch updates
that cache a short time after the write. A cluster with many API servers has
one cache per server. The order still holds, because of the delay of step 4.
A new certificate reaches a server only after the kubelet copies the Secret,
about one minute later. Normally, every API server uses the new bundle by
then.

## Scenarios

Each scenario names the trigger, the chain of events, the actor of each event,
and the result.

### A fresh install with `helm install`

Trigger: a user runs `helm install`.

1. **Helm chart.** It creates the controller Deployment, the Service, the RBAC
   rules, and the other objects of the chart. It creates no certificate.
2. **Init container, step 1.** It finds no certificate Secret. It creates a CA
   root, then a webhook server certificate and an audit scanner client
   certificate signed by it. It writes the three Secrets, with the Kubewarden
   label.
3. **Init container, step 2.** It finds no webhook configuration of the
   controller. It creates both, with the webhooks of the manifest, the webhook
   Service, the Kubewarden label, and `caBundle` equal to `ca.crt`.
4. **Init container, step 3.** The volume is empty, because the Secret did not
   exist when the pod started. It waits. The kubelet copies the Secret into the
   volume, about one minute later. The init container finds the files and ends.
5. **Controller container.** It starts. The webhook server reads its
   certificate. The leader starts the cert controller.
6. **Cert controller.** The informers deliver a create event for each Secret
   and webhook configuration with the Kubewarden label. One pass runs. All the
   Secrets exist. The CA root is valid for 10 years, so there is no rotation.
   There is no `old-ca.crt`. Every `caBundle` is equal to `ca.crt`, so it
   patches nothing. Every certificate is valid and signed by the CA root, so it
   signs nothing. The pass writes nothing and runs again in 12 hours.
7. **PolicyServer reconciler.** When a user creates a `PolicyServer`, it
   creates its Secret and signs the first certificate with the CA root.
8. **Policy reconcilers.** When a user creates a policy, the reconciler waits
   until the policy server is ready, then creates the webhook configuration of
   the policy, with `caBundle` equal to `ca.crt`.
9. **Cert controller.** The new Secret and the new webhook configuration start
   a pass each. Everything is correct. The passes write nothing.

Result: one CA root, every certificate signed by it, every `caBundle` equal to
`ca.crt`. The first install takes about one minute more than the start of a
pod, because of the kubelet.

### A restart of a controller pod, or a second replica

Trigger: a controller pod starts, and the certificate Secrets already exist.

1. **Init container, step 1.** It finds the three Secrets. It keeps them as
   they are.
2. **Init container, step 2.** It finds the two webhook configurations. It
   writes the webhooks of the manifest, and keeps the `caBundle` of each
   webhook. If nothing changed, it writes nothing.
3. **Init container, step 3.** The kubelet filled the volume before the start
   of the pod, because the Secret exists. It finds the files at once and ends.
4. **Controller container.** It starts at once.

Result: no change, and no wait.

### Renewal of a serving certificate

Trigger: a pass of the cert controller finds a certificate that ends within 60
days. The CA root is not affected.

1. **Cert controller.** The CA root Secret exists. The CA root ends in more than
   60 days, so there is no rotation. There is no `old-ca.crt`, or it is still
   valid, so there is nothing to delete.
2. **Cert controller.** It lists the webhook configurations with the
   Kubewarden label. Every `caBundle` is equal to the CA bundle. It patches
   nothing.
3. **Cert controller.** It looks at the webhook server certificate and at each
   policy server certificate. One of them ends within 60 days. It signs a new
   certificate for that server with the current CA root, and writes the Secret
   of that server.
4. **Cert controller.** The Secret event starts one more pass. Every
   certificate is valid now. The pass writes nothing.
5. **Kubelet.** It updates the volume of the pod, about one minute later.
6. **Server.** It reloads the certificate.
7. **API server.** It accepts the new certificate, because the same CA signed
   it. No `caBundle` changed.

Result: a new certificate, no change of trust, no interruption.

### Rotation of the CA root

Trigger: a pass of the cert controller finds that the CA root ends within 60
days. This happens about once in 10 years.

1. **Cert controller.** The CA root Secret exists. It reads `kubewarden-ca` and
   finds that the CA root ends within 60 days. It creates a new CA root. It
   writes `ca.crt` (new), `ca.key` (new), and `old-ca.crt` (the previous CA)
   into `kubewarden-ca`.
2. **Cert controller.** It looks at `old-ca.crt`. The previous CA is still
   valid for up to 60 days, so it keeps it.
3. **Cert controller.** It builds the bundle `ca.crt + old-ca.crt`. It lists
   every webhook configuration with the Kubewarden label: the two of the
   controller and one per policy. It patches each `caBundle` that differs. If
   a patch fails, the pass stops here and returns the error. The work queue
   runs the pass again with a backoff, and no certificate is signed before the
   patch succeeds.
4. **API server.** A short time later, its cache holds the new bundle. It
   accepts a certificate from either CA.
5. **Cert controller.** It looks at the webhook server certificate and at each
   policy server certificate. The previous CA signed all of them, and the new
   CA root does not accept them. It signs each one again with the new CA and
   writes each Secret.
6. **Cert controller.** It looks at the audit scanner client certificate. The
   previous CA signed it. It signs it again with the new CA and writes the
   Secret.
7. **Cert controller.** The Secret and webhook configuration events start one
   more pass. Everything is correct. The pass writes nothing.
8. **Kubelet.** It updates the volumes, about one minute later.
9. **Servers.** They reload. Until then, a server presents the old
   certificate, and the API server accepts it, because `old-ca.crt` is in the
   bundle.

Result: every certificate comes from the new CA, and every `caBundle` holds
both CAs until the previous CA expires, up to 60 days later. One actor did all
the writes, in one function.

### Removal of the old CA

Trigger: a pass of the cert controller finds that `old-ca.crt` is past its end.
This happens up to 60 days after the rotation. The time is shorter if the
rotation ran late, for example after a long shutdown.

1. **Cert controller.** The CA root Secret exists. The CA root is valid for almost
   10 years, so there is no rotation.
2. **Cert controller.** It looks at `old-ca.crt` and finds it past its end. It
   deletes `old-ca.crt` from `kubewarden-ca`.
3. **Cert controller.** It builds the bundle `ca.crt` alone. It lists every
   webhook configuration with the Kubewarden label and patches each `caBundle`
   that still holds the previous CA.
4. **Cert controller.** It looks at every serving certificate and at the audit
   scanner client certificate. The current CA signed all of them. Nothing to
   sign.

Result: every `caBundle` holds the current CA alone. No server changed.

### Restart after a long shutdown

Trigger: the cluster was off for a long time. The controller pods start. The
init container finds the Secrets, so the controller container starts at once.
The informers deliver the create events, and the first pass of the cert
controller runs at once.

**Case 1: the serving certificates are past their end, the CA root is still
valid.** A shutdown of two years gives this case, because a certificate lives
for one year and the CA root for ten.

1. **Servers.** They start with the expired certificates.
2. **API server.** It rejects every call to the webhooks. Policies with
   `failurePolicy: Fail` reject the requests that they cover. Policies with
   `failurePolicy: Ignore` let them pass.
3. **Controller and policy server pods.** They are not blocked by that. A
   cluster-wide policy excludes the namespace of Kubewarden by default, and the
   controller webhooks intercept only Kubewarden CRDs.
4. **Cert controller.** The CA root Secret exists. The CA root ends in more than 60
   days, so there is no rotation. There is no `old-ca.crt`.
5. **Cert controller.** It lists the webhook configurations with the
   Kubewarden label. Every `caBundle` is equal to the CA bundle. It patches
   nothing.
6. **Cert controller.** It looks at the webhook server certificate and at each
   policy server certificate. All of them are past their end. It signs a new
   certificate for each server with the CA root, and writes each Secret.
7. **Cert controller.** It looks at the audit scanner client certificate. It
   is past its end. It signs it again and writes the Secret.
8. **Kubelet.** It updates the volumes, about one minute later.
9. **Servers.** They reload. The outage ends.

The outage lasts from the start of the pods until the servers reload: the
leader election, the first pass, and about one minute of kubelet delay.

**Case 2: the CA root is also past its end.** This needs a shutdown that
crosses the end of the ten-year CA root.

1. **Servers.** They start with the expired certificates.
2. **API server.** It rejects every call, as in case 1.
3. **Cert controller.** The CA root Secret exists. It reads `kubewarden-ca` and
   finds the CA root past its end. It creates a new CA root. It writes `ca.crt`
   (new), `ca.key` (new), and `old-ca.crt` (the expired CA) into
   `kubewarden-ca`.
4. **Cert controller.** It looks at `old-ca.crt` and finds it past its end. It
   deletes `old-ca.crt` from `kubewarden-ca`. The Secret holds the new CA
   alone.
5. **Cert controller.** It builds the bundle `ca.crt` alone. It lists every
   webhook configuration with the Kubewarden label and patches each
   `caBundle`, because all of them hold the expired CA.
6. **API server.** A short time later, its cache holds the new bundle. It
   accepts a certificate from the new CA, and nothing else.
7. **Cert controller.** It looks at the webhook server certificate and at each
   policy server certificate. All of them are past their end, and the expired
   CA signed them. It signs a new certificate for each server with the new CA,
   and writes each Secret.
8. **Cert controller.** It signs the audit scanner client certificate again
   with the new CA, and writes the Secret.
9. **Kubelet.** It updates the volumes, about one minute later.
10. **Servers.** They reload. The outage ends.

One pass does everything.

### Upgrade with `helm upgrade`

Trigger: a user runs `helm upgrade`. Flux and Fleet run Helm, so they behave
the same.

1. **Pre-upgrade hook.** The Job runs the pre-upgrade mode. It adds the keep
   annotations to the certificate Secrets and the webhook configurations of
   the controller that do not have them yet. After the first upgrade from a
   chart version that renders these objects, all of them have the
   annotations, and the hook writes nothing.
2. **Helm chart.** It updates the controller Deployment. If the previous
   chart version rendered the five objects, Helm reads their live versions,
   finds the keep annotation, and does not delete them. From then on, the
   release does not hold them.
3. **Init container of a new pod, step 1.** It finds the three Secrets and
   keeps them.
4. **Init container of a new pod, step 2.** It updates the webhooks of the two
   webhook configurations to the webhooks of the new version. A webhook that
   exists keeps its `caBundle`. A webhook that the new version adds gets the CA
   bundle of `kubewarden-ca`.
5. **Init container of a new pod, step 3.** It finds the files at once and
   ends.
6. **Cert controller of the new leader.** Its first pass finds everything
   correct, and writes nothing.

Result: the same CA, the same objects, no change of trust. The webhooks follow
the version of the controller.

### Install with Argo CD, or any render without cluster access

Argo CD renders the chart with `helm template`, with no access to the cluster.
The chart renders no certificate, no CA bundle, and no webhook configuration of
the controller, so the render is the same every time. Argo CD needs no
`ignoreDifferences` and no special sync option for the certificates.

Argo CD runs the pre-upgrade hook on every sync, as described in "The
pre-upgrade mode". On a sync from a chart version that renders the
certificate Secrets and the webhook configurations of the controller, the
hook adds `Prune=false` to them first, so Argo CD does not prune them.

A `Force` or `Replace` sync, a prune, or a manual delete of a chart object
creates that object again from the render. None of these objects holds a
certificate. If Argo CD replaces the controller Deployment, the new pods run
the init container, which finds the Secrets and the webhook configurations and
keeps them.

### A certificate Secret is deleted

Trigger: a user or a tool deletes one of the three certificate Secrets of the
controller.

**The Secret `kubewarden-webhook-server-cert`, or
`kubewarden-audit-scanner-client-cert`.**

1. **Cert controller.** The delete event starts a pass. It finds the CA root
   valid, no `old-ca.crt` to delete, and every `caBundle` correct.
2. **Cert controller.** It finds the Secret missing. It signs a new
   certificate with the CA root and creates the Secret. The new certificate is
   valid, so it signs nothing more.
3. **Kubelet.** It updates the volume, about one minute later. Until then, the
   server presents its previous certificate, which the API server still
   accepts.

Result: a new certificate from the same CA. No interruption.

**The Secret `kubewarden-ca`.**

1. **Cert controller.** The delete event starts a pass. It finds the Secret
   missing. It creates a new CA root and creates the Secret.
2. **Cert controller.** The new CA root is valid for 10 years, so there is no
   rotation. There is no `old-ca.crt`.
3. **Cert controller.** It builds the bundle: the new CA alone. It patches
   every `caBundle` with the Kubewarden label, because all of them hold the
   deleted CA.
4. **API server.** A short time later, its cache holds the new bundle. It
   trusts the new CA alone. Every server still presents a certificate from
   the deleted CA. The API server rejects every call until the servers reload.
5. **Cert controller.** It finds that the new CA did not sign any certificate.
   It signs every serving certificate and the audit scanner client certificate
   again, and writes each Secret.
6. **Kubelet.** It updates the volumes, about one minute later.
7. **Servers.** They reload. The outage ends.

Result: a new CA root, with an outage of about one minute.

### A human or another tool writes a wrong `caBundle`

Trigger: a write of `caBundle` into any webhook configuration with the
Kubewarden label, of the controller or of a policy.

1. **Cert controller.** The update event passes, because a `caBundle` changed.
   A pass runs. The CA root Secret exists and is valid, and there is
   nothing to delete. It lists every webhook configuration with the Kubewarden
   label. The `caBundle` of the changed object differs from the CA bundle. It
   patches the value back and logs `Injected the CA bundle`. Every certificate
   is valid, so it signs nothing.
2. **Policy reconcilers.** If a policy reconcile runs at the same time, it
   keeps the live value, whatever it is, and the cert controller repairs it.

Result: the repair takes seconds, for every webhook configuration.

### A rotation during a stalled rollout of a policy server

Trigger: a rotation of the CA root while a policy server has a new pod that
does not start, for example in `ImagePullBackOff`. The old pods still serve.

1. **Cert controller.** It rotates the CA root as in the normal case, and
   keeps the previous CA as `old-ca.crt`.
2. **Cert controller.** It writes `ca.crt + old-ca.crt` into every webhook
   configuration with the Kubewarden label, including the webhook
   configurations of the policies of the stalled policy server. It does not
   look at the readiness of the policy server.
3. **Cert controller.** It signs the certificate of that policy server again
   with the new CA. It does not wait for the readiness either.
4. **Kubelet and old pods.** The volume updates. The old pods reload the new
   certificate. The API server accepts them, because the bundle holds the new
   CA.
5. **Policy reconcilers.** The full write of a webhook configuration, with
   rules and selectors, still waits until the rollout ends. The `caBundle` is
   not part of that wait.

Result: the stalled rollout does not block the rotation, and the rotation does
not break the old pods.

### A policy changes between validating and mutating

Trigger: a user changes `spec.mutating` of a policy.

1. **Policy reconciler.** It deletes the webhook configuration of the previous
   kind and creates one of the new kind, with `caBundle` from `kubewarden-ca`.
2. **Cert controller.** The create event starts a pass. The `caBundle` of the
   new object is equal to the CA bundle, so it patches nothing. Every
   certificate is valid. The pass writes nothing.

Result: the new object starts with the correct bundle.

### Uninstall with `helm uninstall`

Trigger: a user runs `helm uninstall`.

1. **Pre-delete hook.** The Job runs the cleanup mode. It deletes the
   controller Deployment and waits until its pods are gone.
2. **Pre-delete hook.** It deletes every webhook configuration with the
   Kubewarden label: the two of the controller and the ones of the policies.
3. **Pre-delete hook.** It strips the Kubewarden finalizers, deletes the
   default policy server and policies of the chart, and the resources of the
   policy servers.
4. **Pre-delete hook.** It deletes the three certificate Secrets of the
   controller.
5. **Helm.** It deletes the objects of the chart.

Result: only the Kubewarden CRDs and the policies and policy servers of the
user stay.

## Timing

| Event | Time |
|---|---|
| A `caBundle` repair after a wrong write | seconds |
| A `caBundle` update after a change of `kubewarden-ca` | seconds |
| A deleted certificate Secret created again | seconds |
| A new certificate in the volume of the pod | about one minute, set by the kubelet |
| Start of the first controller pod of a fresh install | about one minute more, set by the kubelet |
| Detection of a certificate that ends soon | up to 12 hours, 60 days before the end |
| Detection of an expired certificate at startup | the first pass, at once |
| Life of `old-ca.crt` in the bundle | up to 60 days, until the previous CA expires |

## Known limits

This section is an analysis of the code. Unless a limit says otherwise, no
test confirms it.

1. **An uninstall with Argo CD before 3.3 leaves objects behind.** Argo CD
   before 3.3 does not run the pre-delete hook of the chart. After the
   deletion of the Application, the webhook configurations of the controller
   and of the policies, and the certificate Secrets, stay. A webhook
   configuration with `failurePolicy: Fail` that points at a deleted Service
   rejects the requests that it covers. The user must delete these objects, or
   run the controller image with `--mode=cleanup`. Argo CD 3.3 and later run a
   Helm pre-delete hook as a `PreDelete` hook, before they delete the other
   objects. So the cleanup can run there, but no test confirms it. A
   `PostDelete` hook with its own ServiceAccount and rules is another option,
   which nobody has evaluated.
2. **A deleted webhook configuration of the controller comes back at the next
   start of a pod.** The cert controller creates the certificate Secrets again,
   but not the webhook configurations. Until a controller pod restarts, the API
   server does not validate or default the Kubewarden CRDs.
3. **The webhooks change before the old pods stop.** On an upgrade, the init
   container of the first new pod writes the webhooks of the new version while
   the old pods still serve. A webhook that the new version adds fails until
   the old pods are gone.
4. **The audit scanner trusts `ca.crt` alone.** Its CronJob mounts `ca.crt`
   only. During the minute after a rotation, a policy server that still
   presents the old certificate is not trusted by a new run of the scanner. The
   next run works.

5. **An upgrade with `--no-hooks` loses the CA.** On an upgrade from a chart
   version that renders the certificate Secrets and the webhook configurations
   of the controller, `helm upgrade --no-hooks` skips the pre-upgrade hook.
   Helm deletes the five objects. The cert controller creates a new CA and new
   Secrets, and patches every `caBundle`, with an outage of about one minute
   until the servers reload. The webhook configurations of the controller come
   back at the next start of a controller pod, as in limit 2. A run of the
   upgrade test with `--no-hooks` shows the new CA.
6. **Argo CD can show the kept objects as out of sync.** After the upgrade,
   the five objects still carry the tracking label or annotation of the Argo CD
   Application, but they are not in the render anymore. Argo CD does not prune
   them, because of `Prune=false`, but it can list them as resources that need
   pruning. This is not tested.
7. **The init container does not wait for the CA bundle.** The init mode
   creates a missing certificate Secret with the current CA root, and does not
   check the `caBundle` of the webhook configurations. If an earlier pass
   rotated the CA root and failed to write the bundle, and a certificate Secret
   is deleted before a controller pod starts, that pod can present a
   certificate that the API server does not accept yet. The first pass of the
   cert controller writes the bundle a few seconds later.

## Files

| Topic | File |
|---|---|
| Modes of the controller binary | `cmd/controller/main.go`, `run.go`, `init.go`, `cleanup.go`, `preupgrade.go` |
| Init mode: Secrets, controller webhooks, wait | `internal/bootstrap/bootstrap.go` |
| Webhooks of the controller, generated by `make manifests` | `internal/bootstrap/manifests.yaml` |
| Cert controller: rotation, renewal, CA bundle | `internal/controller/cert_controller.go` |
| `CABundleFromSecret` | `internal/certs/secrets.go` |
| Policy webhook configurations | `internal/controller/policy_subreconciler_webhook.go`, `policy_subreconciler.go` |
| First policy server certificate | `internal/controller/policyserver_controller_cert_secret.go` |
| Cleanup on uninstall | `internal/cleanup/cleanup.go` |
| Chart: init container, volume | `charts/admission-controller/templates/controller/deployment.yaml` |
| Chart: pre-delete hook | `charts/admission-controller/templates/controller/pre-delete-hook.yaml` |
| Pre-upgrade mode: keep annotations | `cmd/controller/preupgrade.go`, `internal/upgrade/upgrade.go` |
| Chart: pre-upgrade hook and its RBAC rules | `charts/admission-controller/templates/controller/pre-upgrade-hook.yaml` |
| Upgrade test from the last release | `e2e/upgrade/upgrade_test.go` |
| Policy server certificate reload | `crates/policy-server/src/certs.rs` |
| Constants | `internal/constants/constants.go` |
