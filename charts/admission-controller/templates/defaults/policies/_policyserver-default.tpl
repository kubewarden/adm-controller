{{- define "kubewarden.defaults.policyserverDefault" -}}
{{- $ctx := dict "root" $ "workload" "policyServer" "component" "policy-server" "managedBy" "kubewarden-controller" -}}
{{- $ps := .Values.policyServer -}}
{{- $resources := $ps.resources | default dict -}}
apiVersion: {{ $.Values.crdVersion }}
kind: PolicyServer
metadata:
  name: default
  {{- include "admission-controller.workloadLabels" $ctx | nindent 2 }}
  {{- with include "admission-controller.workloadAnnotations" $ctx }}{{ . | nindent 2 }}{{ end }}
  finalizers:
    - kubewarden.io/finalizer
spec:
  image: {{ template "system_default_registry" $ctx }}{{ $ps.image.repository }}:{{ $ps.image.tag }}
  serviceAccountName: {{ $ps.serviceAccountName }}
  {{- /* The deprecated replicaCount keeps its old rule: 0 becomes 1. */}}
  {{- if not (kindIs "invalid" $ps.replicaCount) }}
  replicas: {{ $ps.replicaCount | default 1 }}
  {{- else }}
  replicas: {{ include "admission-controller.replicas" $ctx }}
  {{- end }}
  {{- if $ps.minAvailable }}
  minAvailable: {{ $ps.minAvailable }}
  {{- end }}
  {{- if $ps.maxUnavailable }}
  maxUnavailable: {{ $ps.maxUnavailable }}
  {{- end }}
  {{- with include "admission-controller.affinity" $ctx }}{{ . | nindent 2 }}{{ end }}
  {{- with include "admission-controller.tolerations" $ctx }}{{ . | nindent 2 }}{{ end }}
  {{- with include "admission-controller.priorityClassName" $ctx }}{{ . | nindent 2 }}{{ end }}
  {{- with $ps.limits | default $resources.limits }}
  limits: {{ . | toYaml | nindent 4 }}
  {{- end }}
  {{- with $ps.requests | default $resources.requests }}
  requests: {{ . | toYaml | nindent 4 }}
  {{- end }}
  {{- if $ps.verificationConfig }}
  verificationConfig: {{ $ps.verificationConfig }}
  {{- end }}
  {{- if $ps.sigstoreTrustConfig }}
  sigstoreTrustConfig: {{ $ps.sigstoreTrustConfig }}
  {{- end }}
  {{- with include "admission-controller.podLabelsMap" $ctx | fromYaml }}
  labels:
    {{- range $key, $value := . }}
    {{ $key | quote }}: {{ $value | quote }}
    {{- end }}
  {{- end }}
  {{- with include "admission-controller.podAnnotationsMap" $ctx | fromYaml }}
  annotations:
    {{- range $key, $value := . }}
    {{ $key | quote }}: {{ $value | quote }}
    {{- end }}
  {{- end }}
  {{- $userEnv := concat (include "admission-controller.extraEnv" $ctx | fromYamlArray) ($ps.env | default list) }}
  {{- $env := list }}
  {{- $logLevel := include "admission-controller.logLevel" $ctx }}
  {{- $hasLogLevel := false }}
  {{- range $userEnv }}
  {{- if eq (toString .name) "KUBEWARDEN_LOG_LEVEL" }}
  {{- $hasLogLevel = true }}
  {{- end }}
  {{- end }}
  {{- if and $logLevel (not $hasLogLevel) }}
  {{- $env = append $env (dict "name" "KUBEWARDEN_LOG_LEVEL" "value" $logLevel) }}
  {{- end }}
  {{- $env = concat $env $userEnv }}
  {{- if $env }}
  env:
    {{- range $env }}
    - name: {{ .name | quote }}
      {{- if or (hasKey . "value") (not (hasKey . "valueFrom")) }}
      value: {{ .value | quote }}
      {{- end }}
      {{- with .valueFrom }}
      valueFrom:
        {{- toYaml . | nindent 8 }}
      {{- end }}
    {{- end }}
  {{- end }}
  {{- if $ps.imagePullSecret }}
  imagePullSecret: {{ $ps.imagePullSecret | quote }}
  {{- end }}
  {{- if $ps.insecureSources }}
  insecureSources:
  {{- range $source := $ps.insecureSources }}
    - {{ $source | quote }}
  {{- end }}
  {{- end }}
  {{- if $ps.sourceAuthorities }}
  sourceAuthorities:
  {{- range $ps.sourceAuthorities }}
  {{- if .certs }}
    {{ .uri }}:
  {{- range .certs }}
      - {{ . | quote }}
  {{- end }}
  {{- end }}
  {{- end }}
  {{- end }}
  {{- if $ps.namespacedPoliciesCapabilities }}
  namespacedPoliciesCapabilities:
  {{- range $ps.namespacedPoliciesCapabilities }}
    - {{ . | quote }}
  {{- end }}
  {{- end }}
  {{- if $ps.securityContexts }}
  securityContexts: {{ toYaml $ps.securityContexts | nindent 4 }}
  {{- else }}
  {{- $securityContexts := dict }}
  {{- with $ps.podSecurityContext }}
  {{- $_ := set $securityContexts "pod" . }}
  {{- end }}
  {{- with $ps.containerSecurityContext }}
  {{- $_ := set $securityContexts "container" . }}
  {{- end }}
  {{- with $securityContexts }}
  securityContexts: {{ toYaml . | nindent 4 }}
  {{- end }}
  {{- end }}
  {{- if $ps.webhookPort }}
  webhookPort: {{ $ps.webhookPort }}
  {{- end }}
  {{- if $ps.readinessProbePort }}
  readinessProbePort: {{ $ps.readinessProbePort }}
  {{- end }}
  {{- if $ps.metricsPort }}
  metricsPort: {{ $ps.metricsPort }}
  {{- end }}
{{- end -}}
