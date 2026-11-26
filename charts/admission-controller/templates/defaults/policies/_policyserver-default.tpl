{{- define "kubewarden.defaults.policyserverDefault" -}}
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
  image: {{ template "system_default_registry" . }}{{ .Values.policyServer.image.repository }}:{{ .Values.policyServer.image.tag }}
  serviceAccountName: {{ .Values.policyServer.serviceAccountName }}
  replicas: {{ .Values.policyServer.replicaCount | default 1 }}
  {{- if .Values.policyServer.minAvailable }}
  minAvailable: {{ .Values.policyServer.minAvailable }}
  {{- end }}
  {{- if .Values.policyServer.maxUnavailable }}
  maxUnavailable: {{ .Values.policyServer.maxUnavailable }}
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
  {{- if .Values.policyServer.limits }}
  limits: {{ .Values.policyServer.limits | toYaml | nindent 4 }}
  {{- end }}
  {{- if .Values.policyServer.requests }}
  requests: {{ .Values.policyServer.requests | toYaml | nindent 4 }}
  {{- end }}
  {{- if .Values.policyServer.verificationConfig }}
  verificationConfig: {{ .Values.policyServer.verificationConfig }}
  {{- end }}
  {{- if .Values.policyServer.sigstoreTrustConfig }}
  sigstoreTrustConfig: {{ .Values.policyServer.sigstoreTrustConfig }}
  {{- end }}
  {{- if .Values.policyServer.annotations }}
  annotations:
    {{- range $key, $value := .Values.policyServer.annotations }}
    {{ $key | quote }}: {{ $value | quote }}
    {{- end }}
  {{- end }}
  {{- if .Values.policyServer.env }}
  env:
    {{- range .Values.policyServer.env }}
    - name: {{ .name | quote }}
      value: {{ .value | quote }}
    {{- end }}
  {{- end }}
  {{- if .Values.policyServer.imagePullSecret }}
  imagePullSecret: {{ .Values.policyServer.imagePullSecret | quote }}
  {{- end }}
  {{- if .Values.policyServer.insecureSources }}
  insecureSources:
  {{- range $source := .Values.policyServer.insecureSources }}
    - {{ $source | quote }}
  {{- end }}
  {{- end }}
  {{- if .Values.policyServer.sourceAuthorities }}
  sourceAuthorities:
  {{- range .Values.policyServer.sourceAuthorities }}
  {{- if .certs }}
    {{ .uri }}:
  {{- range .certs }}
      - {{ . | quote }}
  {{- end }}
  {{- end }}
  {{- end }}
  {{- end }}
  {{- /* Not set (null): leave the field out to allow all host capabilities. */}}
  {{- /* Empty list: denies all, so keep it. */}}
  {{- if ne .Values.policyServer.namespacedPoliciesCapabilities nil }}
  namespacedPoliciesCapabilities: {{ toJson .Values.policyServer.namespacedPoliciesCapabilities }}
  {{- end }}
  {{- if .Values.policyServer.securityContexts }}
  securityContexts: {{ toYaml .Values.policyServer.securityContexts | nindent 4 }}
  {{- end }}
  {{- if .Values.policyServer.webhookPort }}
  webhookPort: {{ .Values.policyServer.webhookPort }}
  {{- end }}
  {{- if .Values.policyServer.readinessProbePort }}
  readinessProbePort: {{ .Values.policyServer.readinessProbePort }}
  {{- end }}
  {{- if .Values.policyServer.metricsPort }}
  metricsPort: {{ .Values.policyServer.metricsPort }}
  {{- end }}
{{- end -}}
