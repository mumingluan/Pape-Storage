package server

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"pape-storage/internal/config"
)

func testServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{
		DataDir: t.TempDir(), PublicBaseURL: "https://storage.example.test", Bucket: "pape",
		Region: "cn-hangzhou", AccessKeyID: "LTAI-local", AccessKeySecret: "local-secret",
		MaxUploadBytes: 1024,
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.now = func() time.Time { return time.Date(2026, 9, 3, 8, 30, 0, 0, time.UTC) }
	httpServer := httptest.NewServer(srv.Handler())
	t.Cleanup(httpServer.Close)
	return srv, httpServer
}

func postFields(t *testing.T, srv *Server, key string, maxBytes int64) map[string]string {
	t.Helper()
	now := srv.now().UTC()
	date := now.Format("20060102")
	timestamp := now.Format("20060102T150405Z")
	credential := srv.cfg.AccessKeyID + "/" + date + "/" + srv.cfg.Region + "/oss/aliyun_v4_request"
	policyJSON, err := json.Marshal(map[string]any{
		"expiration": now.Add(20 * time.Minute).Format("2006-01-02T15:04:05.000Z"),
		"conditions": []any{
			map[string]string{"bucket": srv.cfg.Bucket}, map[string]string{"key": key},
			map[string]string{"x-oss-signature-version": ossV4SignatureVersion},
			map[string]string{"x-oss-credential": credential}, map[string]string{"x-oss-date": timestamp},
			[]any{"content-length-range", 0, maxBytes}, map[string]string{"success_action_status": "200"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := base64.StdEncoding.EncodeToString(policyJSON)
	return map[string]string{
		"key": key, "policy": policy, "success_action_status": "200",
		"x-oss-signature-version": ossV4SignatureVersion, "x-oss-credential": credential,
		"x-oss-date": timestamp, "x-oss-signature": hex.EncodeToString(signPostPolicy(srv.cfg.AccessKeySecret, date, srv.cfg.Region, policy)),
	}
}

func upload(t *testing.T, endpoint string, fields map[string]string, content []byte) *http.Response {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	part, err := writer.CreateFormFile("file", "object.bin")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(content)
	_ = writer.Close()
	request, _ := http.NewRequest(http.MethodPost, endpoint+"/", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestAliyunOSSPostObjectV4UploadAndPublicRead(t *testing.T) {
	srv, endpoint := testServer(t)
	key := "photo/a/object.bin"
	content := []byte("0123456789")
	response := upload(t, endpoint.URL, postFields(t, srv, key, 32), content)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("ETag") != `"781E5E245D69B566979B86E28D23F2C7"` || response.Header.Get("x-oss-request-id") == "" {
		t.Fatalf("upload status=%d headers=%v", response.StatusCode, response.Header)
	}

	request, _ := http.NewRequest(http.MethodGet, endpoint.URL+"/"+key, nil)
	request.Header.Set("Range", "bytes=2-5")
	download, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer download.Body.Close()
	body, _ := io.ReadAll(download.Body)
	if download.StatusCode != http.StatusPartialContent || string(body) != "2345" {
		t.Fatalf("download status=%d body=%q", download.StatusCode, body)
	}
	head, err := http.Head(endpoint.URL + "/" + key)
	if err != nil {
		t.Fatal(err)
	}
	head.Body.Close()
	if head.StatusCode != http.StatusOK || head.ContentLength != int64(len(content)) {
		t.Fatalf("head status=%d length=%d", head.StatusCode, head.ContentLength)
	}
}

func TestPostObjectRejectsTamperedKeyAndSignature(t *testing.T) {
	srv, endpoint := testServer(t)
	fields := postFields(t, srv, "logs/a.bin", 32)
	fields["key"] = "logs/b.bin"
	response := upload(t, endpoint.URL, fields, []byte("data"))
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || !bytes.Contains(body, []byte("SignatureDoesNotMatch")) {
		t.Fatalf("tampered key status=%d body=%s", response.StatusCode, body)
	}
	fields = postFields(t, srv, "logs/a.bin", 32)
	fields["x-oss-signature"] = strings.Repeat("0", 64)
	response = upload(t, endpoint.URL, fields, []byte("data"))
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("tampered signature status=%d", response.StatusCode)
	}
}

func TestPrivateTokenAPIIsNotExposedAndTraversalIsRejected(t *testing.T) {
	_, endpoint := testServer(t)
	response, err := http.Post(endpoint.URL+"/admin/v1/upload-tokens", "application/json", strings.NewReader(`{"category":"logs"}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("private API status=%d", response.StatusCode)
	}
	escaped := url.PathEscape("../private")
	response, err = http.Get(endpoint.URL + "/" + escaped)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("traversal status=%d", response.StatusCode)
	}
}
