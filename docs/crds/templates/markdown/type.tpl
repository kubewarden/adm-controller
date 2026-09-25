{{- define "type" -}}
{{- $type := . -}}
{{- if markdownShouldRenderType $type -}}

#### {{ $type.Name }}

{{ if $type.IsAlias }}_Underlying type:_ _{{ markdownRenderTypeLink $type.UnderlyingType  }}_{{ end }}

{{ $type.Doc }}

{{ if $type.Validation -}}
_Validation:_
{{- range $type.Validation }}
- {{ . }}
{{- end }}
{{- end }}

{{ if $type.References -}}
_Appears in:_
{{- range $type.SortedReferences }}
{{- if markdownShouldRenderType . }}
- {{ markdownRenderTypeLink . }}
{{- end }}
{{- end }}
{{- end }}

{{ if $type.Members -}}
{{ if $type.GVK -}}
##### `apiVersion`

**Type:** _string_

`{{ $type.GVK.Group }}/{{ $type.GVK.Version }}`

##### `kind`

**Type:** _string_

`{{ $type.GVK.Kind }}`
{{ end -}}

{{ range $type.Members -}}
##### `{{ .Name }}`

**Type:** _{{ markdownRenderType .Type }}_

{{ if .Default -}}
**Default:** {{ markdownRenderDefault .Default }}

{{ end -}}
{{ if .Validation -}}
**Validation:**
{{- range .Validation }}
- {{ markdownRenderFieldDoc . }}
{{- end }}

{{ end -}}
{{ template "type_members" . }}
{{ end -}}

{{ end -}}

{{ if $type.EnumValues -}}
| Field | Description |
| --- | --- |
{{ range $type.EnumValues -}}
| `{{ .Name }}` | {{ markdownRenderFieldDoc .Doc }} |
{{ end -}}
{{ end -}}


{{- end -}}
{{- end -}}
