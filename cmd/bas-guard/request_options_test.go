// SPDX-License-Identifier: MIT
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestE2E_RequestOptionsReachTheEndpointAndTheBlock (P-107): llm.request_options join every request `scan`,
// `check` and `llm test` send, and the judge block, the usage line and the preview record them; without
// them no request and no block carries anything new.
func TestE2E_RequestOptionsReachTheEndpointAndTheBlock(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(raw))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"flagged\": false}"}}]}`))
	}))
	defer srv.Close()
	root := buildTestRunnerSkill(t, false)
	plain := writeJudgeConfig(t, srv.URL, "advisory")
	with := filepath.Join(t.TempDir(), "config.yaml")
	mustWriteFile(t, with, "llm:\n  enabled: true\n  provider: openai_compatible\n  base_url: "+srv.URL+"\n  model: fake\n"+
		"  request_options:\n    thinking:\n      type: disabled\n")
	const opts = `{"thinking":{"type":"disabled"}}`
	for name, cfg := range map[string]string{"with": with, "plain": plain} {
		mu.Lock()
		bodies = nil
		mu.Unlock()
		scanned, err := scanEnv(root, scanOpts{cfgPath: cfg, llm: true, quiet: true})
		if err != nil {
			t.Fatal(err)
		}
		checked, err := checkTarget(filepath.Join(root, "skills", "test-runner"), scanOpts{cfgPath: cfg, llm: true, quiet: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := runLLMTest(io.Discard, cfg); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		sent := append([]string(nil), bodies...)
		mu.Unlock()
		if len(sent) < 3 {
			t.Fatalf("%s: %d request(s), want the scan's, the check's and llm test's", name, len(sent))
		}
		for i, b := range sent {
			has := strings.Contains(b, `,"thinking":{"type":"disabled"}}`)
			if has != (name == "with") {
				t.Errorf("%s: request %d carries the option = %v:\n%s", name, i, has, b)
			}
		}
		for entry, j := range map[string]string{"scan": scanned.Judge.RequestOptions, "check": checked.Judge.RequestOptions} {
			want := ""
			if name == "with" {
				want = opts
			}
			if j != want {
				t.Errorf("%s/%s: judge block request_options %q, want %q", name, entry, j, want)
			}
		}
		raw, _ := json.Marshal(scanned.Judge)
		if strings.Contains(string(raw), "request_options") != (name == "with") {
			t.Errorf("%s: judge block %s", name, raw)
		}
		if line := usageLineFor("scan", "environment", scanned.ToolVersion, scanned.RulesVersion, "now", scanned.Judge); line.RequestOptions != scanned.Judge.RequestOptions {
			t.Errorf("%s: usage line request_options %q, block %q", name, line.RequestOptions, scanned.Judge.RequestOptions)
		}
		var preview strings.Builder
		if err := runLLMPreview(&preview, previewOpts{cfgPath: cfg, target: filepath.Join(root, "skills", "test-runner"), json: true}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(preview.String(), `"request_options"`) != (name == "with") {
			t.Errorf("%s: preview does not say what every request carries:\n%.300s", name, preview.String())
		}
	}
}
