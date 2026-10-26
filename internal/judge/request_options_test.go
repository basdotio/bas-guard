// SPDX-License-Identifier: MIT
package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/basdotio/bas-guard/internal/config"
)

// bodyServer answers every call "not flagged" and keeps the raw request bodies.
func bodyServer(t *testing.T) (*httptest.Server, func() [][]byte) {
	t.Helper()
	var mu sync.Mutex
	var got [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, raw)
		mu.Unlock()
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"{\"flagged\": false}"}}]}`)
	}))
	t.Cleanup(srv.Close)
	return srv, func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		return append([][]byte(nil), got...)
	}
}

// TestHTTP_RequestOptionsJoinEveryRequest (P-107): the options are added to every request body — a judge
// question and the connectivity check alike — after the members the judge sets, in key order; the rest of
// the body is byte for byte what a client without options sends.
func TestHTTP_RequestOptionsJoinEveryRequest(t *testing.T) {
	req := Request{Mode: ModeInjection, Declared: "d <x>", Behavior: "b & c", Nonce: strings.Repeat("ab", 16)}
	send := func(opts map[string]any) [][]byte {
		srv, bodies := bodyServer(t)
		c := NewHTTP(srv.URL, "", "m", srv.Client())
		if opts != nil {
			if err := c.SetRequestOptions(opts); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := c.Judge(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Ping(context.Background()); err != nil {
			t.Fatal(err)
		}
		return bodies()
	}
	plain := send(nil)
	with := send(map[string]any{"thinking": map[string]any{"type": "disabled"}, "max_tokens": 800})
	const tail = `,"max_tokens":800,"thinking":{"type":"disabled"}}`
	for i := range plain {
		p := bytes.TrimRight(plain[i], "\n")
		w := bytes.TrimRight(with[i], "\n")
		if !bytes.HasSuffix(w, []byte(tail)) {
			t.Errorf("call %d: body does not end with the options in key order:\n%s", i, w)
			continue
		}
		if base := append(append([]byte(nil), bytes.TrimSuffix(w, []byte(tail))...), '}'); !bytes.Equal(base, p) {
			t.Errorf("call %d: the rest of the body moved:\n with %s\n plain %s", i, base, p)
		}
		var decoded map[string]any
		if err := json.Unmarshal(w, &decoded); err != nil {
			t.Errorf("call %d: not one JSON object: %v", i, err)
		}
	}
	if !bytes.Contains(plain[0], []byte("<x>")) {
		t.Error("the plain body escaped HTML; the comparison above is against the wrong bytes")
	}
}

// TestRequestOptions_ReservedCoversTheRequest (P-107): every member the judge sets is one config refuses to
// take from request_options, so an option can never sit beside — or after, and win over — a member the
// judge decided. config holds the one list; this test keeps it from falling behind chatRequest.
func TestRequestOptions_ReservedCoversTheRequest(t *testing.T) {
	reserved := map[string]bool{}
	for _, k := range config.ReservedRequestOptions {
		reserved[k] = true
	}
	typ := reflect.TypeOf(chatRequest{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if name != "-" && !reserved[name] {
			t.Errorf("chatRequest member %q is not in config.ReservedRequestOptions", name)
		}
	}
	srv, _ := bodyServer(t)
	c := NewHTTP(srv.URL, "", "m", srv.Client())
	for _, k := range config.ReservedRequestOptions {
		if err := c.SetRequestOptions(map[string]any{k: 1}); err == nil {
			t.Errorf("SetRequestOptions took %q", k)
		}
	}
}
