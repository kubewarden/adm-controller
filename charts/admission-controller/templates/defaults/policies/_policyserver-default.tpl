{{- define "kubewarden.defaults.policyserverDefault" -}}
{{- $ctx := dict "root" $ "workload" "policyServer" "component" "policy-server" -}}
{{- $ps := .Values.policyServer -}}
{{- $resources := $ps.resources | default dict -}}
apiVersion: {{ $.Values.crdVersion }}
kind: PolicyServer
metadata:
  name: default
  labels:
    {{- include "admission-controller.commonLabels" . | nindent 4 }}
    app.kubernetes.io/component: policy-server
    app.kubernetes.io/managed-by: kubewarden-controller
  annotations:
    {{- include "admission-controller.defaults.annotations" . | nindent 4 }}
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
  {{- $affinity := include "admission-controller.defaults.effectiveAffinity" . -}}
  {{- if $affinity }}
  affinity: {{ $affinity | nindent 4 }}
  {{- end }}
  {{- if .Values.global.tolerations }}
  tolerations: {{ .Values.global.tolerations | toYaml | nindent 4 }}
  {{- end }}
  {{- if .Values.global.priorityClassName }}
  priorityClassName: {{ .Values.global.priorityClassName | toYaml | nindent 4 }}
  {{- end }}
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
  {{- if $ps.annotations }}
  annotations:
    {{- range $key, $value := $ps.annotations }}
    {{ $key | quote }}: {{ $value | quote }}
    {{- end }}
  {{- end }}
  {{- if $ps.env }}
  env:
    {{- range $ps.env }}
    - name: {{ .name | quote }}
      value: {{ .value | quote }}
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
