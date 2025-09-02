package metrics

import (
	"fmt"
	"sort"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/kuadrant/authorino/pkg/expressions/cel"
	"github.com/kuadrant/authorino/pkg/log"
)

var (
	// Global switch for deep per-evaluator metrics (when the evaluator doesn't enable its own metrics)
	DeepMetricsEnabled = false

	// currentBundle holds the active set of metrics and custom label definitions.
	currentBundle atomic.Value // *MetricsBundle
)

// Object represents an entity that can contribute evaluator labels.
type Object interface {
	GetType() string
	GetName() string
	MetricsEnabled() bool
}

// MetricsBundle holds the metric collectors and metadata for label evaluation.
type MetricsBundle struct {
	// Custom label definitions
	CustomLabels        map[string]*cel.Expression
	CustomLabelsEnabled bool
	customLabelNames    []string

	// Evaluator metrics
	EvaluatorTotal     *prometheus.CounterVec
	EvaluatorCancelled *prometheus.CounterVec
	EvaluatorIgnored   *prometheus.CounterVec
	EvaluatorDenied    *prometheus.CounterVec
	EvaluatorDuration  *prometheus.HistogramVec

	// AuthConfig metrics
	AuthConfigTotal          *prometheus.CounterVec
	AuthConfigResponseStatus *prometheus.CounterVec
	AuthConfigDuration       *prometheus.HistogramVec

	// HTTP/GRPC server level metrics (no custom labels)
	AuthServerResponseStatus  *prometheus.CounterVec
	HTTPServerHandledTotal    *prometheus.CounterVec
	HTTPServerHandlingSeconds *prometheus.HistogramVec

	// OIDC service metrics (no custom labels based on authJSON)
	OIDCRequestsTotal  *prometheus.CounterVec
	OIDCResponseStatus *prometheus.CounterVec
}

// ReinitializeMetrics rebuilds the metrics with the provided custom label config
// and atomically swaps the active registry and collectors.
func ReinitializeMetrics(labelsConfig map[string]string) error {
	logger := log.WithName("metrics")
	logger.Info("reinitializing metrics with custom labels")

	// 1) Compile CEL expressions for custom labels and create a stable label order
	customLabels := make(map[string]*cel.Expression)
	customLabelNames := make([]string, 0, len(labelsConfig))
	for labelName, celExpr := range labelsConfig {
		if expr, err := cel.NewExpression(celExpr); err != nil {
			return fmt.Errorf("failed to compile CEL expression for label %s: %w", labelName, err)
		} else {
			customLabels[labelName] = expr
			customLabelNames = append(customLabelNames, labelName)
		}
	}
	sort.Strings(customLabelNames) // stable order for label names

	// 2) Define label sets
	authConfigBase := []string{"namespace", "authconfig"}
	evaluatorBase := append(append([]string{}, authConfigBase...), "evaluator_type", "evaluator_name")

	// Append custom label names (in sorted order) to each base set
	evaluatorLabels := append(append([]string{}, evaluatorBase...), customLabelNames...)
	authConfigLabels := append(append([]string{}, authConfigBase...), customLabelNames...)
	authConfigStatusLabels := append(append([]string{}, authConfigLabels...), "status")

	// 3) Create fresh collectors
	newBundle := &MetricsBundle{
		CustomLabels:        customLabels,
		CustomLabelsEnabled: len(customLabels) > 0,
		customLabelNames:    customLabelNames,

		// Evaluator metrics
		EvaluatorTotal:     NewCounterMetric("auth_server_evaluator_total", "Total number of evaluations of individual authconfig rule performed by the auth server.", evaluatorLabels...),
		EvaluatorCancelled: NewCounterMetric("auth_server_evaluator_cancelled", "Number of evaluations of individual authconfig rule cancelled by the auth server.", evaluatorLabels...),
		EvaluatorIgnored:   NewCounterMetric("auth_server_evaluator_ignored", "Number of evaluations of individual authconfig rule ignored by the auth server.", evaluatorLabels...),
		EvaluatorDenied:    NewCounterMetric("auth_server_evaluator_denied", "Number of denials from individual authconfig rule evaluated by the auth server.", evaluatorLabels...),
		EvaluatorDuration:  NewDurationMetric("auth_server_evaluator_duration_seconds", "Response latency of individual authconfig rule evaluated by the auth server (in seconds).", evaluatorLabels...),

		// AuthConfig metrics
		AuthConfigTotal:          NewCounterMetric("auth_server_authconfig_total", "Total number of authconfigs enforced by the auth server, partitioned by authconfig.", authConfigLabels...),
		AuthConfigResponseStatus: NewCounterMetric("auth_server_authconfig_response_status", "Response status of authconfigs sent by the auth server, partitioned by authconfig.", authConfigStatusLabels...),
		AuthConfigDuration:       NewDurationMetric("auth_server_authconfig_duration_seconds", "Response latency of authconfig enforced by the auth server (in seconds).", authConfigLabels...),

		// Server metrics (no custom labels)
		AuthServerResponseStatus:  NewCounterMetric("auth_server_response_status", "Response status of authconfigs sent by the auth server.", "status"),
		HTTPServerHandledTotal:    NewCounterMetric("http_server_handled_total", "Total number of calls completed on the raw HTTP authorization server, regardless of success or failure.", "status"),
		HTTPServerHandlingSeconds: NewDurationMetric("http_server_handling_seconds", "Response latency (seconds) of raw HTTP authorization request that had been application-level handled by the server."),

		// OIDC metrics (no custom labels)
		OIDCRequestsTotal:  NewCounterMetric("oidc_server_requests_total", "Number of get requests received on the OIDC (Festival Wristband) server.", append(append([]string{}, authConfigBase...), "wristband", "path")...),
		OIDCResponseStatus: NewCounterMetric("oidc_server_response_status", "Status of HTTP response sent by the OIDC (Festival Wristband) server.", "status"),
	}

	// 4) Register in a fresh registry
	registry := prometheus.NewRegistry()
	registry.MustRegister(
		newBundle.EvaluatorTotal,
		newBundle.EvaluatorCancelled,
		newBundle.EvaluatorIgnored,
		newBundle.EvaluatorDenied,
		newBundle.EvaluatorDuration,
		newBundle.AuthConfigTotal,
		newBundle.AuthConfigResponseStatus,
		newBundle.AuthConfigDuration,
		newBundle.AuthServerResponseStatus,
		newBundle.HTTPServerHandledTotal,
		newBundle.HTTPServerHandlingSeconds,
		newBundle.OIDCRequestsTotal,
		newBundle.OIDCResponseStatus,
	)

	// 5) Atomically swap the active bundle and metrics HTTP handler
	currentBundle.Store(newBundle)
	Handler.Swap(registry)

	logger.Info("metrics reinitialized")
	return nil
}

// EvaluateCustomLabels evaluates CEL-based custom labels over the given authorization JSON.
func EvaluateCustomLabels(authJSON string, defs map[string]*cel.Expression) (map[string]string, error) {
	customLabels := make(map[string]string, len(defs))

	for labelName, expr := range defs {
		if value, err := expr.ResolveFor(authJSON); err != nil {
			// Use empty on failure to avoid breaking metric emission
			customLabels[labelName] = ""
		} else if strValue, ok := value.(string); ok {
			customLabels[labelName] = strValue
		} else {
			customLabels[labelName] = fmt.Sprintf("%v", value)
		}
	}

	return customLabels, nil
}

// buildFinalLabels constructs the final label values by combining base labels with custom labels.
func buildFinalLabels(b *MetricsBundle, authJSON string, baseLabels ...string) []string {
	labels := make([]string, len(baseLabels))
	copy(labels, baseLabels)

	if b != nil && b.CustomLabelsEnabled && authJSON != "" {
		if customValues, err := EvaluateCustomLabels(authJSON, b.CustomLabels); err == nil {
			for _, name := range b.customLabelNames {
				labels = append(labels, customValues[name])
			}
		} else {
			for range b.customLabelNames {
				labels = append(labels, "")
			}
		}
	}

	return labels
}

func NewCounterMetric(name, help string, labels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: name,
			Help: help,
		},
		labels,
	)
}

func NewDurationMetric(name, help string, labels ...string) *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    name,
			Help:    help,
			Buckets: prometheus.LinearBuckets(0.001, 0.05, 20),
		},
		labels,
	)
}

// Generic helpers (kept for backward compatibility with call sites that pass explicit metric vectors)

func ReportMetric(metric *prometheus.CounterVec, authJSON string, labels ...string) {
	b, _ := currentBundle.Load().(*MetricsBundle)
	finalLabels := buildFinalLabels(b, authJSON, labels...)
	metric.WithLabelValues(finalLabels...).Inc()
}

func ReportMetricWithStatus(metric *prometheus.CounterVec, status string, authJSON string, labels ...string) {
	baseLabels := extendLabelValuesWithStatus(status, labels...)
	ReportMetric(metric, authJSON, baseLabels...)
}

func ReportMetricWithObject(metric *prometheus.CounterVec, obj Object, authJSON string, labels ...string) {
	if extendedLabels, err := extendLabelValuesWithObject(obj, labels...); err == nil {
		ReportMetric(metric, authJSON, extendedLabels...)
	}
}

func ReportTimedMetric(metric *prometheus.HistogramVec, f func(), authJSON string, labels ...string) {
	b, _ := currentBundle.Load().(*MetricsBundle)
	finalLabels := buildFinalLabels(b, authJSON, labels...)

	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(value float64) {
		metric.WithLabelValues(finalLabels...).Observe(value)
	}))

	defer func() {
		timer.ObserveDuration()
	}()

	f()
}

func ReportTimedMetricWithStatus(metric *prometheus.HistogramVec, f func(), status string, authJSON string, labels ...string) {
	baseLabels := extendLabelValuesWithStatus(status, labels...)
	ReportTimedMetric(metric, f, authJSON, baseLabels...)
}

func ReportTimedMetricWithObject(metric *prometheus.HistogramVec, f func(), obj Object, authJSON string, labels ...string) {
	if extendedLabels, err := extendLabelValuesWithObject(obj, labels...); err == nil {
		ReportTimedMetric(metric, f, authJSON, extendedLabels...)
	} else {
		f()
	}
}

func extendLabelValuesWithStatus(status string, baseLabels ...string) []string {
	labels := make([]string, len(baseLabels))
	copy(labels, baseLabels)
	labels = append(labels, status)
	return labels
}

func extendLabelValuesWithObject(obj Object, baseLabels ...string) ([]string, error) {
	if obj == nil || (!obj.MetricsEnabled() && !DeepMetricsEnabled) {
		return nil, fmt.Errorf("metrics are disabled")
	}

	labels := make([]string, len(baseLabels))
	copy(labels, baseLabels)
	labels = append(labels, obj.GetType(), obj.GetName())
	return labels, nil
}

// High-level reporting helpers that always target the live bundle collectors

// Evaluator metrics
func ReportEvaluatorTotal(obj Object, authJSON string, labels ...string) {
	b, _ := currentBundle.Load().(*MetricsBundle)
	if b == nil {
		return
	}
	if extended, err := extendLabelValuesWithObject(obj, labels...); err == nil {
		final := buildFinalLabels(b, authJSON, extended...)
		b.EvaluatorTotal.WithLabelValues(final...).Inc()
	}
}

func ReportEvaluatorCancelled(obj Object, authJSON string, labels ...string) {
	b, _ := currentBundle.Load().(*MetricsBundle)
	if b == nil {
		return
	}
	if extended, err := extendLabelValuesWithObject(obj, labels...); err == nil {
		final := buildFinalLabels(b, authJSON, extended...)
		b.EvaluatorCancelled.WithLabelValues(final...).Inc()
	}
}

func ReportEvaluatorIgnored(obj Object, authJSON string, labels ...string) {
	b, _ := currentBundle.Load().(*MetricsBundle)
	if b == nil {
		return
	}
	if extended, err := extendLabelValuesWithObject(obj, labels...); err == nil {
		final := buildFinalLabels(b, authJSON, extended...)
		b.EvaluatorIgnored.WithLabelValues(final...).Inc()
	}
}

func ReportEvaluatorDenied(obj Object, authJSON string, labels ...string) {
	b, _ := currentBundle.Load().(*MetricsBundle)
	if b == nil {
		return
	}
	if extended, err := extendLabelValuesWithObject(obj, labels...); err == nil {
		final := buildFinalLabels(b, authJSON, extended...)
		b.EvaluatorDenied.WithLabelValues(final...).Inc()
	}
}

func ReportTimedEvaluatorDuration(f func(), obj Object, authJSON string, labels ...string) {
	b, _ := currentBundle.Load().(*MetricsBundle)
	if b == nil {
		f()
		return
	}

	if extended, err := extendLabelValuesWithObject(obj, labels...); err == nil {
		final := buildFinalLabels(b, authJSON, extended...)
		timer := prometheus.NewTimer(prometheus.ObserverFunc(func(value float64) {
			b.EvaluatorDuration.WithLabelValues(final...).Observe(value)
		}))
		defer timer.ObserveDuration()
		f()
	} else {
		f()
	}
}

// AuthConfig metrics
func ReportAuthConfigTotal(authJSON string, labels ...string) {
	b, _ := currentBundle.Load().(*MetricsBundle)
	if b == nil {
		return
	}
	final := buildFinalLabels(b, authJSON, labels...)
	b.AuthConfigTotal.WithLabelValues(final...).Inc()
}

func ReportAuthConfigResponseStatus(status string, authJSON string, labels ...string) {
	b, _ := currentBundle.Load().(*MetricsBundle)
	if b == nil {
		return
	}
	base := extendLabelValuesWithStatus(status, labels...)
	final := buildFinalLabels(b, authJSON, base...)
	b.AuthConfigResponseStatus.WithLabelValues(final...).Inc()
}

func ReportTimedAuthConfigDuration(f func(), authJSON string, labels ...string) {
	b, _ := currentBundle.Load().(*MetricsBundle)
	if b == nil {
		f()
		return
	}
	final := buildFinalLabels(b, authJSON, labels...)
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		b.AuthConfigDuration.WithLabelValues(final...).Observe(v)
	}))
	defer timer.ObserveDuration()
	f()
}

// Server-level helpers (no custom labels used)
func ReportAuthServerResponseStatus(status string) {
	b, _ := currentBundle.Load().(*MetricsBundle)
	if b == nil {
		return
	}
	b.AuthServerResponseStatus.WithLabelValues(status).Inc()
}

func ReportHTTPServerHandledTotal(status string) {
	b, _ := currentBundle.Load().(*MetricsBundle)
	if b == nil {
		return
	}
	b.HTTPServerHandledTotal.WithLabelValues(status).Inc()
}

func ReportTimedHTTPServerDuration(f func()) {
	b, _ := currentBundle.Load().(*MetricsBundle)
	if b == nil {
		f()
		return
	}
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		b.HTTPServerHandlingSeconds.WithLabelValues().Observe(v)
	}))
	defer timer.ObserveDuration()
	f()
}

// OIDC helpers
func ReportOIDCRequestsTotal(namespace, authconfig, wristband, path string) {
	b, _ := currentBundle.Load().(*MetricsBundle)
	if b == nil {
		return
	}
	b.OIDCRequestsTotal.WithLabelValues(namespace, authconfig, wristband, path).Inc()
}

func ReportOIDCResponseStatus(status string) {
	b, _ := currentBundle.Load().(*MetricsBundle)
	if b == nil {
		return
	}
	b.OIDCResponseStatus.WithLabelValues(status).Inc()
}
