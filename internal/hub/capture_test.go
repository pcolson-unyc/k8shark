package hub

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func captureTestManager(t *testing.T) (*captureManager, *[]string) {
	t.Helper()
	var patches []string
	ds := `{"metadata":{"annotations":{"k8shark.io/capture-state":"stopped"}},"spec":{"template":{"spec":{"schedulingGates":[{"name":"k8shark.io/capture-stopped"},{"name":"user-gate"}]}}},"status":{"desiredNumberScheduled":2,"numberReady":0,"currentNumberScheduled":0}}`
	m := &captureManager{api: "https://kube.test", token: "token", namespace: "ns", name: "k8shark-worker", defaultDuration: 15 * time.Minute, maxDuration: time.Hour}
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPatch {
			b, _ := io.ReadAll(r.Body)
			patches = append(patches, string(b))
			return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(ds)), Header: make(http.Header)}, nil
	})}
	return m, &patches
}

func TestCaptureStartPatchesOnlyRuntimeGateAndAnnotations(t *testing.T) {
	m, patches := captureTestManager(t)
	s, err := m.start(context.Background(), 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if s.State != "stopped" {
		t.Fatalf("state after patch read = %q, want stopped fake status", s.State)
	}
	if len(*patches) != 1 {
		t.Fatalf("patches = %d", len(*patches))
	}
	p := (*patches)[0]
	if !strings.Contains(p, `"k8shark.io/capture-state":"running"`) || !strings.Contains(p, `"schedulingGates":[{"name":"user-gate"}]`) {
		t.Fatalf("unexpected start patch: %s", p)
	}
}

func TestCaptureStopAddsGateAndClearsExpiry(t *testing.T) {
	m, patches := captureTestManager(t)
	ds := daemonSet{}
	ds.Spec.Template.Spec.SchedulingGates = []struct {
		Name string `json:"name"`
	}{{Name: "user-gate"}}
	if err := m.patch(context.Background(), ds, "stopped", nil, true); err != nil {
		t.Fatal(err)
	}
	p := (*patches)[0]
	if !strings.Contains(p, `"k8shark.io/capture-state":"stopped"`) || !strings.Contains(p, `"k8shark.io/capture-expiry":null`) || !strings.Contains(p, captureGate) || !strings.Contains(p, "user-gate") {
		t.Fatalf("unexpected stop patch: %s", p)
	}
}

func TestCaptureStartBoundsDuration(t *testing.T) {
	m, _ := captureTestManager(t)
	if _, err := m.start(context.Background(), 2*time.Hour); err == nil {
		t.Fatal("expected max-duration error")
	}
}

func TestCaptureSessionReportsUnavailableKubernetesAccess(t *testing.T) {
	s := New(slog.Default(), Options{OnDemandCapture: true})
	// The unit-test process has no ServiceAccount token, which is precisely the
	// actionable failure a chart-installed hub must surface instead of faking a
	// stopped/healthy session.
	rec := httptest.NewRecorder()
	s.handleCaptureSession(rec, httptest.NewRequest(http.MethodGet, "/api/capture/session", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "kubernetes access is unavailable") {
		t.Fatalf("session response = %d %s", rec.Code, rec.Body.String())
	}
}
