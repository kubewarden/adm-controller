{{/*
Expand the name of the chart.
*/}}
{{- define "admission-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "admission-controller.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create default fully qualified audit-scanner name
Truncate to 53 per CronJob docs, as k8s controller appends chars when spawning
the job Pods.
*/}}
{{- define "audit-scanner.fullname" -}}
{{- if .Values.fullnameOverride }}
{{-   .Values.fullnameOverride | trunc 53 | trimSuffix "-" }}
{{- else }}
{{-   $name := default "audit-scanner" .Values.nameOverride }}
{{-   if contains $name .Release.Name }}
{{-     .Release.Name | trunc 53 | trimSuffix "-" }}
{{-   else }}
{{-     $name | trunc 53 | trimSuffix "-" }}
{{-   end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "admission-controller.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Namespace for all namespaced resources of the chart.
It is namespaceOverride, or the release namespace when namespaceOverride is empty.
Helm does not give the computed namespace to the policy-reporter subchart.
So when namespaceOverride is set and policy-reporter is enabled,
policy-reporter.namespaceOverride must have the same value.
*/}}
{{- define "admission-controller.namespace" -}}
{{- $override := .Values.namespaceOverride | default "" -}}
{{- if and $override (.Values.auditScanner | default dict).policyReporter -}}
{{- $reporterOverride := (index .Values "policy-reporter" | default dict).namespaceOverride | default "" -}}
{{- if ne $override $reporterOverride -}}
{{- fail (printf "namespaceOverride (%q) and policy-reporter.namespaceOverride (%q) must have the same value when auditScanner.policyReporter is true" $override $reporterOverride) -}}
{{- end -}}
{{- end -}}
{{- $override | default .Release.Namespace -}}
{{- end -}}

{{/*
Base labels shared by every resource in the chart.
Does not include managed-by (varies: Helm vs kubewarden-controller)
or component (varies per resource type).
*/}}
{{- define "admission-controller.commonLabels" -}}
helm.sh/chart: {{ include "admission-controller.chart" . }}
{{ include "admission-controller.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- else }}
app.kubernetes.io/version: {{ .Chart.Version | quote }}
{{- end }}
app.kubernetes.io/part-of: kubewarden
{{- if .Values.additionalLabels }}
{{ toYaml .Values.additionalLabels }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "admission-controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "admission-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Selector labels for the controller Deployment and its Services.
Deliberately excludes app.kubernetes.io/name (which follows the chart name and
broke in-place adoption when the chart was renamed). Uses component (a fixed
string) and instance (follows the release name) so the immutable Deployment
selector is independent of the chart name.
*/}}
{{- define "admission-controller.controllerSelectorLabels" -}}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: controller
{{- end }}

{{/*
Labels for defaults resources (PolicyServer RBAC, hook Jobs, etc.)
No component label — callers add it inline when needed.
*/}}
{{- define "admission-controller.defaults.labels" -}}
{{ include "admission-controller.commonLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Labels for controller resources (Deployment, Services, RBAC, etc.)
*/}}
{{- define "admission-controller.labels" -}}
{{ include "admission-controller.commonLabels" . }}
app.kubernetes.io/component: controller
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Labels for embedded default ClusterAdmissionPolicy resources.
*/}}
{{- define "admission-controller.policyLabels" -}}
{{ include "admission-controller.commonLabels" . }}
app.kubernetes.io/component: policy
app.kubernetes.io/managed-by: kubewarden-controller
{{- end }}

{{/*
Annotations
*/}}
{{- define "admission-controller.annotations" -}}
{{- if .Values.additionalAnnotations }}
{{ toYaml .Values.additionalAnnotations }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use for kubewarden-controller
*/}}
{{- define "admission-controller.serviceAccountName" -}}
{{- include "admission-controller.fullname" . }}
{{- end }}

{{/*
Create the webhook service name, ensuring it doesn't exceed 63 characters.
The service name is fullname + "-webhook-service" (16 chars), so we need to
limit fullname to 47 chars to stay under the 63 char limit.
*/}}
{{- define "admission-controller.webhookServiceName" -}}
{{- if .Values.fullnameOverride }}
{{- printf "%s-webhook-service" (.Values.fullnameOverride | trunc 47 | trimSuffix "-") }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- printf "%s-webhook-service" (.Release.Name | trunc 47 | trimSuffix "-") }}
{{- else }}
{{- $fullname := printf "%s-%s" .Release.Name $name | trunc 47 | trimSuffix "-" }}
{{- printf "%s-webhook-service" $fullname }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Registry prefix for the chart images, with a trailing "/".
global.imageRegistry wins over the image.registry of the workload block.
It takes the workload context dict.
An empty registry gives no prefix.
When the image has no registry key, the registry is ghcr.io.
This happens with helm upgrade --reuse-values from a chart version
that had no image.registry keys.
*/}}
{{- define "system_default_registry" -}}
{{- $global := .root.Values.global | default dict -}}
{{- $image := include "admission-controller._image" . | fromYaml -}}
{{- $registry := "ghcr.io" -}}
{{- if hasKey $image "registry" -}}
{{- $registry = $image.registry -}}
{{- end -}}
{{- with $global.imageRegistry | default $registry -}}
{{- printf "%s/" . -}}
{{- end -}}
{{- end -}}

{{/*
admission-controller._image renders the image map of the workload block as YAML,
or an empty map when the block has no image.
It takes the context dict of the workload helpers.
*/}}
{{- define "admission-controller._image" -}}
{{- $block := index .root.Values .workload | default dict -}}
{{- toYaml ($block.image | default dict) -}}
{{- end -}}

{{- define "audit-scanner.command" -}}
{{- $parallelNamespaces := .Values.auditScanner.parallelNamespaces | int -}}
{{- $parallelResources := .Values.auditScanner.parallelResources | int -}}
{{- $parallelPolicies := .Values.auditScanner.parallelPolicies | int -}}
{{- $pageSize := .Values.auditScanner.pageSize| int -}}
- /audit-scanner
- --kubewarden-namespace
- {{ include "admission-controller.namespace" . | quote }}
- --loglevel
- {{ .Values.auditScanner.logLevel }}
{{- if gt $parallelNamespaces 0 }}
- --parallel-namespaces
- "{{ $parallelNamespaces }}"
{{- end }}
{{- if gt $parallelResources 0 }}
- --parallel-resources
- "{{ $parallelResources }}"
{{- end }}
{{- if gt $parallelPolicies 0 }}
- --parallel-policies
- "{{ $parallelPolicies }}"
{{- end }}
{{- if gt $pageSize 0 }}
- --page-size
- "{{ $pageSize }}"
{{- end }}
{{- if .Values.auditScanner.disableStore }}
- --disable-store
{{- end }}
- --extra-ca
- "/pki/ca.crt"
- --client-cert
- "/client-cert/tls.crt"
- --client-key
- "/client-cert/tls.key"
{{- if .Values.auditScanner.outputScan }}
- --output-scan
{{- end }}
{{- range .Values.global.skipNamespaces }}
- {{ printf "-i" }}
- {{ printf "%s" . }}
{{- end -}}
{{- range .Values.auditScanner.skipAdditionalNamespaces }}
- {{ printf "-i" }}
- {{ printf "%s" . }}
{{- end -}}
{{- if .Values.auditScanner.reportCRDsKind }}
- --report-kind
- {{ .Values.auditScanner.reportCRDsKind }}
{{- end -}}
{{- end -}}

{{/*
Compute the effective affinity for the controller deployment.
Uses the controller-specific affinity if set, otherwise falls back to
global.affinity for backward compatibility.

NOTE: When hostNetwork is enabled, users are responsible for setting
appropriate podAntiAffinity rules to prevent host-port conflicts between
controller replicas on the same node.
*/}}
{{- define "admission-controller.effectiveAffinity" -}}
{{- if .Values.affinity -}}
  {{- toYaml .Values.affinity -}}
{{- else if .Values.global.affinity -}}
  {{- toYaml .Values.global.affinity -}}
{{- end -}}
{{- end -}}

{{/*
Annotations for defaults resources.
*/}}
{{- define "admission-controller.defaults.annotations" -}}
{{- if .Values.additionalAnnotations }}
{{ toYaml .Values.additionalAnnotations }}
{{- end }}
{{- end }}

{{/*
Registry prefix for the recommended policies, with a trailing "/".
It is recommendedPolicies.defaultPoliciesRegistry, else global.imageRegistry,
else ghcr.io.
*/}}
{{- define "policy_default_registry" -}}
{{- $global := .Values.global | default dict -}}
{{- printf "%s/" (.Values.recommendedPolicies.defaultPoliciesRegistry | default $global.imageRegistry | default "ghcr.io") -}}
{{- end -}}

{{- define "policy_failure_policy" -}}
{{- if eq .Values.recommendedPolicies.defaultPolicyMode "protect" -}}
Fail
{{- else -}}
Ignore
{{- end -}}
{{- end -}}

{{- define "policy-namespace-selector" -}}
namespaceSelector:
  matchExpressions:
  - key: "kubernetes.io/metadata.name"
    operator: NotIn
    values:
{{- with .Values.global.skipNamespaces }}
      {{- toYaml . | nindent 4 }}
{{- end }}
{{- with .Values.recommendedPolicies.skipAdditionalNamespaces }}
      {{- toYaml . | nindent 4 }}
{{- end }}
{{- end -}}

{{- define "admission-controller.defaults.effectiveAffinity" -}}
{{- if .Values.policyServer.affinity -}}
  {{- toYaml .Values.policyServer.affinity -}}
{{- else if .Values.global.affinity -}}
  {{- toYaml .Values.global.affinity -}}
{{- end -}}
{{- end -}}

{{/*
Validate that hostNetwork and telemetry sidecar mode are not both enabled.
They are incompatible because multiple OTel sidecars on the same node would
cause port conflicts in host-network mode.
*/}}
{{- define "admission-controller.validateHostNetworkSidecar" -}}
{{- if and .Values.hostNetwork (eq .Values.telemetry.mode "sidecar") (or .Values.telemetry.metrics .Values.telemetry.tracing) -}}
{{- fail "hostNetwork and telemetry.mode=sidecar are incompatible: OpenTelemetry sidecar injection causes port conflicts in host-network mode. Use telemetry.mode=custom with a remote collector instead." -}}
{{- end -}}
{{- end -}}

{{/*
Values of the workloads

The workload templates read their values through the public helpers below.
Each public helper takes a context dict:
  root:      the root context ($)
  workload:  the name of the workload block in .Values: "controller",
             "auditScanner", "policyServer", "preDeleteJob" or "postInstallJob"
  component: the value of the app.kubernetes.io/component label, for example "audit-scanner"

A template builds the context dict once:
  {{- $ctx := dict "root" $ "workload" "controller" "component" "controller" }}

The image registry and the pull policy of a workload are in its image map:
  system_default_registry (above): global.imageRegistry, else the workload image.registry, else ghcr.io when the image has no registry key.
  admission-controller.imagePullPolicy: the workload image.pullPolicy, else common.imagePullPolicy,
                                        else global.imagePullPolicy.

Some keys of earlier chart versions are deprecated aliases of these keys.
admission-controller._alias resolves them. A deprecated key wins over the
contract keys when it is set.

The private helpers take dict "ctx" <context dict> "key" <key>.
A key with a dot reads a nested map.
Templates do not call the private helpers.
*/}}

{{/*
admission-controller._levels renders a YAML list with three items:
the value of the key in global, in common, and in the workload block.
The other private helpers decode this list, so they work on copies of .Values.
*/}}
{{- define "admission-controller._levels" -}}
{{- $values := .ctx.root.Values -}}
{{- $blocks := list ($values.global | default dict) ($values.common | default dict) (index $values .ctx.workload | default dict) -}}
{{- $out := list -}}
{{- range $block := $blocks -}}
{{- $value := $block -}}
{{- range $part := splitList "." $.key -}}
{{- $value = index ($value | default dict) $part -}}
{{- end -}}
{{- $out = append $out $value -}}
{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{/*
admission-controller._field renders "<name>:" and the value as YAML.
It renders nothing when the value is empty.
It takes dict "name" <field name> "value" <value>.
*/}}
{{- define "admission-controller._field" -}}
{{- with .value -}}
{{ $.name }}:
  {{- toYaml . | nindent 2 }}
{{- end -}}
{{- end -}}

{{/*
admission-controller._legacy resolves deprecated keys. A deprecated key wins
over the contract keys when it is set.
It takes dict "root" <root context> "paths" <list of dotted paths> "mode" <mode>,
and "new" <resolved contract value> in the map mode.
It renders "value: <value>" with the first deprecated key that is set,
or {} when no deprecated key is set.
Callers test the result with hasKey, so 0 and false count as set.
The modes:
  presence: set means not null. For booleans and integers.
  string:   set means not empty.
  map:      set means a non-empty map. The value is the new value with the
            deprecated map merged on top, so the missing leaves come from the
            new key. A null leaf of the deprecated map removes the leaf.
*/}}
{{- define "admission-controller._legacy" -}}
{{- $out := dict -}}
{{- range $path := .paths -}}
{{- if not (hasKey $out "value") -}}
{{- $value := $.root.Values -}}
{{- range $part := splitList "." $path -}}
{{- if kindIs "map" $value -}}
{{- $value = index $value $part -}}
{{- else -}}
{{- $value = index (dict) "missing" -}}
{{- end -}}
{{- end -}}
{{- $set := false -}}
{{- if eq $.mode "presence" -}}
{{- $set = not (kindIs "invalid" $value) -}}
{{- else if eq $.mode "map" -}}
{{- $set = and (kindIs "map" $value) (not (empty $value)) -}}
{{- else -}}
{{- $set = not (empty $value) -}}
{{- end -}}
{{- if $set -}}
{{- if eq $.mode "map" -}}
{{- $merged := deepCopy ($.new | default dict) -}}
{{- $_ := include "admission-controller._mergeLegacyMap" (dict "dst" $merged "src" (deepCopy $value)) -}}
{{- $value = $merged -}}
{{- end -}}
{{- $_ := set $out "value" $value -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{/*
admission-controller._mergeLegacyMap merges the map src into the map dst, in place.
A value of src wins over the value of dst, and nested maps merge.
A null value in src removes the key from dst,
the same way as Helm removes a default value when the user sets it to null.
*/}}
{{- define "admission-controller._mergeLegacyMap" -}}
{{- $dst := .dst -}}
{{- range $key, $value := .src -}}
{{- if kindIs "invalid" $value -}}
{{- $_ := unset $dst $key -}}
{{- else if and (kindIs "map" $value) (kindIs "map" (index $dst $key)) -}}
{{- $_ := include "admission-controller._mergeLegacyMap" (dict "dst" (index $dst $key) "src" $value) -}}
{{- else -}}
{{- $_ := set $dst $key $value -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
admission-controller._aliases lists the deprecated keys of each workload key.
*/}}
{{- define "admission-controller._aliases" -}}
controller:
  imagePullPolicy: {paths: [image.pullPolicy], mode: string}
  replicas: {paths: [replicas], mode: presence}
  resources: {paths: [resources.controller], mode: map}
  podSecurityContext: {paths: [podSecurityContext], mode: map}
  containerSecurityContext: {paths: [containerSecurityContext], mode: map}
auditScanner:
  enabled: {paths: [auditScanner.enable], mode: presence}
  resources: {paths: [resources.auditScanner], mode: map}
  podSecurityContext: {paths: [podSecurityContext], mode: map}
  containerSecurityContext: {paths: [containerSecurityContext], mode: map}
preDeleteJob:
  resources: {paths: [resources.preDeleteJob], mode: map}
  podSecurityContext: {paths: [preDeleteHook.podSecurityContext], mode: map}
  containerSecurityContext: {paths: [preDeleteHook.containerSecurityContext], mode: map}
postInstallJob:
  resources: {paths: [resources.postInstallJob], mode: map}
  podSecurityContext: {paths: [preDeleteHook.podSecurityContext], mode: map}
  containerSecurityContext: {paths: [preDeleteHook.containerSecurityContext], mode: map}
policyServer:
  replicas: {paths: [policyServer.replicaCount], mode: presence}
{{- end -}}

{{/*
admission-controller._alias resolves the deprecated keys of one workload key
with admission-controller._legacy.
It takes dict "ctx" <context dict> "key" <key>, and "new" <value> in the map mode.
It renders {} when the key has no deprecated alias.
*/}}
{{- define "admission-controller._alias" -}}
{{- $table := include "admission-controller._aliases" . | fromYaml -}}
{{- $alias := index (index $table .ctx.workload | default dict) .key | default dict -}}
{{- if $alias -}}
{{- include "admission-controller._legacy" (dict "root" .ctx.root "paths" $alias.paths "mode" $alias.mode "new" .new) -}}
{{- else -}}
{}
{{- end -}}
{{- end -}}

{{/*
admission-controller._workload renders "value: <value>" with a key that only
the workload block has, for example replicas or resources.
A deprecated alias wins when it is set.
*/}}
{{- define "admission-controller._workload" -}}
{{- $block := index .ctx.root.Values .ctx.workload | default dict -}}
{{- $new := index $block .key -}}
{{- $old := include "admission-controller._alias" (dict "ctx" .ctx "key" .key "new" $new) | fromYaml -}}
{{- if hasKey $old "value" -}}
{{- toYaml $old -}}
{{- else -}}
{{- toYaml (dict "value" $new) -}}
{{- end -}}
{{- end -}}

{{/*
admission-controller._pullSecrets renders the YAML list of the image pull
secrets: global, common, the deprecated top-level imagePullSecrets, and the
workload, in this order.
Each item is a Secret name or a map with a name key. The helper renders a
name as a map. It skips an item with an empty or missing name.
It keeps an item of any other type, and Kubernetes rejects it.
*/}}
{{- define "admission-controller._pullSecrets" -}}
{{- $l := include "admission-controller._levels" (dict "ctx" . "key" "imagePullSecrets") | fromYamlArray -}}
{{- $secrets := list -}}
{{- range concat (index $l 0 | default list) (index $l 1 | default list) (.root.Values.imagePullSecrets | default list) (index $l 2 | default list) -}}
{{- if kindIs "string" . -}}
{{- if . -}}
{{- $secrets = append $secrets (dict "name" .) -}}
{{- end -}}
{{- else if kindIs "map" . -}}
{{- if .name -}}
{{- $secrets = append $secrets . -}}
{{- end -}}
{{- else -}}
{{- $secrets = append $secrets . -}}
{{- end -}}
{{- end -}}
{{- toYaml $secrets -}}
{{- end -}}

{{/* Public helpers that render a bare value. */}}

{{- define "admission-controller.imagePullPolicy" -}}
{{- $old := include "admission-controller._alias" (dict "ctx" . "key" "imagePullPolicy") | fromYaml -}}
{{- if hasKey $old "value" -}}
{{- $old.value -}}
{{- else -}}
{{- $l := include "admission-controller._levels" (dict "ctx" . "key" "imagePullPolicy") | fromYamlArray -}}
{{- (include "admission-controller._image" . | fromYaml).pullPolicy | default (index $l 1) | default (index $l 0) | default "" -}}
{{- end -}}
{{- end -}}

{{/*
admission-controller.replicas renders the replicas of the workload,
or 1 when no value is set.
*/}}
{{- define "admission-controller.replicas" -}}
{{- $value := (include "admission-controller._workload" (dict "ctx" . "key" "replicas") | fromYaml).value -}}
{{- if kindIs "invalid" $value -}}
1
{{- else -}}
{{- $value -}}
{{- end -}}
{{- end -}}

{{/*
admission-controller.enabled renders "true" when the workload is enabled,
or nothing. A workload without a value is enabled.
*/}}
{{- define "admission-controller.enabled" -}}
{{- $value := (include "admission-controller._workload" (dict "ctx" . "key" "enabled") | fromYaml).value -}}
{{- if or (kindIs "invalid" $value) $value -}}
true
{{- end -}}
{{- end -}}

{{/*
admission-controller.policyServerImagePullSecretNames renders the
comma-separated names of the image pull secrets of the policy servers,
for the controller --image-pull-secrets flag.
It reads global, common, the deprecated top-level imagePullSecrets, and
policyServer. It takes the root context ($).
*/}}
{{- define "admission-controller.policyServerImagePullSecretNames" -}}
{{- $names := list -}}
{{- range include "admission-controller._pullSecrets" (dict "root" . "workload" "policyServer" "component" "policy-server") | fromYamlArray -}}
{{- if kindIs "map" . -}}
{{- $names = append $names .name -}}
{{- end -}}
{{- end -}}
{{- join "," $names -}}
{{- end -}}

{{/* Public helpers that render a whole field, or nothing when the value is empty. */}}

{{/*
admission-controller.imagePullSecrets renders "imagePullSecrets:" with the
list of admission-controller._pullSecrets.
*/}}
{{- define "admission-controller.imagePullSecrets" -}}
{{- include "admission-controller._field" (dict "name" "imagePullSecrets" "value" (include "admission-controller._pullSecrets" . | fromYamlArray)) -}}
{{- end -}}

{{/*
Public helpers for the keys that only the workload block has.
A deprecated alias wins when it is set.
*/}}

{{- define "admission-controller.resources" -}}
{{- include "admission-controller._field" (dict "name" "resources" "value" (include "admission-controller._workload" (dict "ctx" . "key" "resources") | fromYaml).value) -}}
{{- end -}}

{{- define "admission-controller.podSecurityContext" -}}
{{- include "admission-controller._field" (dict "name" "securityContext" "value" (include "admission-controller._workload" (dict "ctx" . "key" "podSecurityContext") | fromYaml).value) -}}
{{- end -}}

{{/*
admission-controller.containerSecurityContext renders the security context of
the containers. When it is not empty and ctx.fixedContainerSecurityContext is
set, the helper puts the fixed fields on top, so a user value cannot replace them.
*/}}
{{- define "admission-controller.containerSecurityContext" -}}
{{- $value := (include "admission-controller._workload" (dict "ctx" . "key" "containerSecurityContext") | fromYaml).value -}}
{{- if and $value .fixedContainerSecurityContext -}}
{{- $value = mergeOverwrite (deepCopy $value) .fixedContainerSecurityContext -}}
{{- end -}}
{{- include "admission-controller._field" (dict "name" "securityContext" "value" $value) -}}
{{- end -}}
