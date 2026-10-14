package authproxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/agentauth"
)

func TestProxyRequestsIdentityEncodingForErrorInspection(t *testing.T) {
	stubUpstream(t, "zen", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept-Encoding"); got != "identity" {
			t.Errorf("upstream encoding = %q; want identity", got)
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":{"message":"model not available"}}`)
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/opencode/zen/chat/completions", nil)
	r.Header.Set("Accept-Encoding", "br, gzip")
	New(agentauth.NewStore(t.TempDir()), nil).ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "model not available") {
		t.Fatalf("plain permanent error not normalized: %d %s", w.Code, w.Body.String())
	}
}

func TestProxyPreservesUnexpectedCompressedErrors(t *testing.T) {
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	_, _ = io.WriteString(z, `{"error":{"message":"access denied"}}`)
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	for _, encoding := range []string{"gzip", "br"} {
		t.Run(encoding, func(t *testing.T) {
			// The br case checks byte preservation without adding a Brotli codec.
			// A proxy must not turn encoded bytes into plaintext labelled "br".
			body := compressed.Bytes()
			stubUpstream(t, "zen", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Encoding", encoding)
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write(body)
			})
			r := httptest.NewRequest("POST", "/opencode/zen/chat/completions", nil)
			r.Header.Set("Accept-Encoding", "br, gzip")
			w := httptest.NewRecorder()
			New(agentauth.NewStore(t.TempDir()), nil).ServeHTTP(w, r)
			if w.Code != http.StatusForbidden || w.Header().Get("Content-Encoding") != encoding || !bytes.Equal(w.Body.Bytes(), body) {
				t.Fatalf("compressed response changed: status=%d encoding=%q bytes=%d", w.Code, w.Header().Get("Content-Encoding"), w.Body.Len())
			}
			if encoding == "gzip" {
				reader, err := gzip.NewReader(w.Body)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				decoded, err := io.ReadAll(reader)
				if err != nil || !strings.Contains(string(decoded), "access denied") {
					t.Fatalf("invalid gzip: %v", err)
				}
			}
		})
	}
}

func TestProxyDoesNotTruncateLargeErrors(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			body := strings.Repeat("upstream diagnostic ", 1024)
			stubUpstream(t, "zen", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				w.WriteHeader(status)
				_, _ = io.WriteString(w, body)
			})
			w := httptest.NewRecorder()
			New(agentauth.NewStore(t.TempDir()), nil).ServeHTTP(w, httptest.NewRequest("POST", "/opencode/zen/chat/completions", nil))
			if w.Code != status || w.Body.String() != body || w.Header().Get("Content-Length") != strconv.Itoa(len(body)) {
				t.Fatalf("large response changed: status=%d bytes=%d", w.Code, w.Body.Len())
			}
		})
	}
}
