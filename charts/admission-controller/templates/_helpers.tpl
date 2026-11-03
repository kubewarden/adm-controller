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
Print the image pull secrets in the expected format (an array of objects with one possible field, "name").
*/}}
{{- define "imagePullSecrets" }}
    {{- $imagePullSecrets := list }}
    {{- range . }}
        {{- if kindIs "string" . }}
            {{- $imagePullSecrets = append $imagePullSecrets (dict "name" .) }}
        {{- else }}
            {{- $imagePullSecrets = append $imagePullSecrets . }}
        {{- end }}
    {{- end }}
    {{- toYaml $imagePullSecrets }}
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

{{- define "system_default_registry" -}}
{{- if .Values.global.cattle.systemDefaultRegistry -}}
{{- printf "%s/" .Values.global.cattle.systemDefaultRegistry -}}
{{- else -}}
{{- "" -}}
{{- end -}}
{{- end -}}

{{/*
Build a comma-separated list of Secret names from .Values.imagePullSecrets,
for use with the controller --image-pull-secrets flag. Handles both string
entries and {name: ...} objects. Returns an empty string when no secrets
are configured.
*/}}
{{- define "policyServerImagePullSecretNames" -}}
{{- $names := list -}}
{{- range .Values.imagePullSecrets -}}
  {{- if kindIs "string" . -}}
    {{- $names = append $names . -}}
  {{- else -}}
    {{- $names = append $names .name -}}
  {{- end -}}
{{- end -}}
{{- join "," $names -}}
{{- end -}}

{{- define "audit-scanner.command" -}}
{{- $parallelNamespaces := .Values.auditScanner.parallelNamespaces | int -}}
{{- $parallelResources := .Values.auditScanner.parallelResources | int -}}
{{- $parallelPolicies := .Values.auditScanner.parallelPolicies | int -}}
{{- $pageSize := .Values.auditScanner.pageSize| int -}}
- /audit-scanner
- --kubewarden-namespace
- {{ .Release.Namespace }}
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

{{- define "policy_default_registry" -}}
{{- if .Values.recommendedPolicies.defaultPoliciesRegistry -}}
{{- printf "%s/" .Values.recommendedPolicies.defaultPoliciesRegistry -}}
{{- else -}}
{{- printf "%s/" .Values.global.cattle.systemDefaultRegistry -}}
{{- end -}}
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
