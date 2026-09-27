{{- define "neurawall.fullname" -}}{{ .Release.Name }}-neurawall{{- end -}}
{{- define "neurawall.image" -}}{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}{{- end -}}
{{- define "neurawall.labels" -}}
app.kubernetes.io/name: neurawall
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}
{{- define "neurawall.secretName" -}}{{ .Values.controlPlane.existingSecret | default (printf "%s-secrets" (include "neurawall.fullname" .)) }}{{- end -}}
