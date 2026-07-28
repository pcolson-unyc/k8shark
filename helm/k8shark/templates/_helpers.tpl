{{- define "k8shark.labels" -}}
app.kubernetes.io/part-of: k8shark
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "k8shark.binaryImage" -}}
{{ .Values.image.registry }}/{{ .Values.image.binary }}:{{ .Values.image.tag }}
{{- end -}}

{{- define "k8shark.frontImage" -}}
{{ .Values.image.registry }}/{{ .Values.image.front }}:{{ .Values.image.tag }}
{{- end -}}

{{/*
k8shark.enrichClusterRoleName: the enrichment ClusterRole/Binding are
cluster-scoped, so their names must be unique per release — a second release
in another namespace would otherwise fail on a Helm ownership conflict over
the same fixed-name object.
*/}}
{{- define "k8shark.enrichClusterRoleName" -}}
k8shark-hub-enrich-{{ .Release.Name }}
{{- end -}}

{{/*
k8shark.imagePullPolicy: .Values.image.pullPolicy wins when explicitly set;
otherwise Always for a mutable "latest"/empty tag (so `helm upgrade` actually
re-pulls instead of a node's cached "latest" silently no-op'ing) and
IfNotPresent for a pinned immutable tag.
*/}}
{{- define "k8shark.imagePullPolicy" -}}
{{- if .Values.image.pullPolicy -}}
{{ .Values.image.pullPolicy }}
{{- else if or (not .Values.image.tag) (eq .Values.image.tag "latest") -}}
Always
{{- else -}}
IfNotPresent
{{- end -}}
{{- end -}}

{{/*
k8shark.hubGoMemLimit: the hub container's GOMEMLIMIT, in bytes, as 80% of
hub.resources.limits.memory. GOMEMLIMIT is a *soft* ceiling — the GC ramps up
as the heap nears it instead of the kernel OOMKilling the pod at the hard
cgroup limit — and the 20% headroom covers what counts against the cgroup but
not against the Go heap: goroutine stacks, runtime metadata, and read buffers.

Renders empty when no memory limit is set, so the caller omits the env var
entirely and an unlimited container stays unlimited. That is also why this is
templated instead of read via a downward-API resourceFieldRef: with no limit
set, resourceFieldRef on limits.memory silently reports the node's allocatable
memory, which would give a limitless hub a GOMEMLIMIT of the whole node.

Accepts every quantity form Kubernetes actually allows for memory: a decimal
number, optionally with a k/M/G/T/Ki/Mi/Gi/Ti suffix, *or* in exponent form
(128e6, 1e9 — legal plain byte counts, and rejecting them would abort the whole
render for a values file that installed fine before). Anything else fails
loudly rather than quietly rendering a bogus limit. Note the suffix is stripped
before the numeric check, so a garbage mantissa ("abcMi") still fails instead of
being cast to 0 — otherwise it would be indistinguishable from a genuine 0 and
silently swallowed by the guard below.

Also renders empty when the computed ceiling rounds to less than one byte
(limits.memory: 0, or an exponent so small it degenerates). GOMEMLIMIT=0 is not
"no limit" to the Go runtime — it is a zero-byte soft heap ceiling that pins the
GC at its 50%-CPU limiter forever, which is exactly the bogus limit this helper
exists to prevent. Omitting the env var is the honest rendering of "no usable
limit".
*/}}
{{- define "k8shark.hubGoMemLimit" -}}
{{- /* default dict: hub.resources may be nulled out wholesale, and dig panics on a nil map. */ -}}
{{- $q := dig "limits" "memory" "" (.Values.hub.resources | default dict) | toString | trim -}}
{{- if $q -}}
{{- $mult := 1.0 -}}
{{- $n := $q -}}
{{- if hasSuffix "Ki" $q -}}{{- $mult = 1024.0 -}}{{- $n = trimSuffix "Ki" $q -}}
{{- else if hasSuffix "Mi" $q -}}{{- $mult = 1048576.0 -}}{{- $n = trimSuffix "Mi" $q -}}
{{- else if hasSuffix "Gi" $q -}}{{- $mult = 1073741824.0 -}}{{- $n = trimSuffix "Gi" $q -}}
{{- else if hasSuffix "Ti" $q -}}{{- $mult = 1099511627776.0 -}}{{- $n = trimSuffix "Ti" $q -}}
{{- else if hasSuffix "k" $q -}}{{- $mult = 1000.0 -}}{{- $n = trimSuffix "k" $q -}}
{{- else if hasSuffix "M" $q -}}{{- $mult = 1000000.0 -}}{{- $n = trimSuffix "M" $q -}}
{{- else if hasSuffix "G" $q -}}{{- $mult = 1000000000.0 -}}{{- $n = trimSuffix "G" $q -}}
{{- else if hasSuffix "T" $q -}}{{- $mult = 1000000000000.0 -}}{{- $n = trimSuffix "T" $q -}}
{{- end -}}
{{- /* float64 (cast.ToFloat64 → strconv.ParseFloat) parses the exponent form as-is, so widening the regex is the whole fix — the arithmetic below is unchanged. */ -}}
{{- if not (regexMatch "^[0-9]+(\\.[0-9]+)?([eE][+-]?[0-9]+)?$" $n) -}}
{{- fail (printf "hub.resources.limits.memory: unsupported quantity %q — use plain bytes (1073741824, or exponent form 1e9) or a k/M/G/T/Ki/Mi/Gi/Ti suffix (the chart derives GOMEMLIMIT from it)." $q) -}}
{{- end -}}
{{- $bytes := mulf (float64 $n) $mult 0.8 -}}
{{- if ge $bytes 1.0 -}}
{{- printf "%.0f" $bytes -}}
{{- end -}}
{{- end -}}
{{- end -}}
