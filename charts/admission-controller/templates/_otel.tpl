{{/*
OTel exporter wiring for the instrumented workloads.
The helpers take the workload context dict (root, workload, component) and
read the telemetry configuration from the top-level otel block first,
then the workload otel block, then common.otel, then global.otel.
An empty value counts as unset.
All templates render nothing when the resolved endpoint is empty.
The TLS environment variables point at the mounts rendered by
admission-controller.otelVolumeMounts / admission-controller.otelVolumes.
*/}}

{{/*
admission-controller._otel renders a YAML map with the resolved endpoint,
caSecretName, and clientCertificateSecretName.
*/}}
{{- define "admission-controller._otel" -}}
{{- $values := .root.Values -}}
{{- $global := ($values.global | default dict).otel | default dict -}}
{{- $common := ($values.common | default dict).otel | default dict -}}
{{- $workload := (index $values .workload | default dict).otel | default dict -}}
{{- $chart := $values.otel | default dict -}}
{{- $out := dict -}}
{{- range $key := list "endpoint" "caSecretName" "clientCertificateSecretName" -}}
{{- $_ := set $out $key (index $chart $key | default (index $workload $key) | default (index $common $key) | default (index $global $key) | default "") -}}
{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{- define "admission-controller.otelEnv" -}}
{{- $otel := include "admission-controller._otel" . | fromYaml -}}
{{- if $otel.endpoint -}}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ $otel.endpoint | quote }}
- name: K8S_POD_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: K8S_POD_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
{{- if $otel.caSecretName }}
- name: OTEL_EXPORTER_OTLP_CERTIFICATE
  value: /otel/tls/ca/ca.crt
{{- end }}
{{- if $otel.clientCertificateSecretName }}
- name: OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE
  value: /otel/tls/client/tls.crt
- name: OTEL_EXPORTER_OTLP_CLIENT_KEY
  value: /otel/tls/client/tls.key
{{- end }}
{{- end -}}
{{- end -}}

{{- define "admission-controller.otelVolumeMounts" -}}
{{- $otel := include "admission-controller._otel" . | fromYaml -}}
{{- $mounts := list -}}
{{- if $otel.endpoint -}}
{{- if $otel.caSecretName -}}
{{- $mounts = append $mounts (dict "name" "otel-ca" "mountPath" "/otel/tls/ca" "readOnly" true) -}}
{{- end -}}
{{- if $otel.clientCertificateSecretName -}}
{{- $mounts = append $mounts (dict "name" "otel-client-tls" "mountPath" "/otel/tls/client" "readOnly" true) -}}
{{- end -}}
{{- end -}}
{{- with $mounts -}}
{{- toYaml . -}}
{{- end -}}
{{- end -}}

{{- define "admission-controller.otelVolumes" -}}
{{- $otel := include "admission-controller._otel" . | fromYaml -}}
{{- $volumes := list -}}
{{- if $otel.endpoint -}}
{{- if $otel.caSecretName -}}
{{- $volumes = append $volumes (dict "name" "otel-ca" "secret" (dict "secretName" $otel.caSecretName)) -}}
{{- end -}}
{{- if $otel.clientCertificateSecretName -}}
{{- $volumes = append $volumes (dict "name" "otel-client-tls" "secret" (dict "secretName" $otel.clientCertificateSecretName)) -}}
{{- end -}}
{{- end -}}
{{- with $volumes -}}
{{- toYaml . -}}
{{- end -}}
{{- end -}}
