package server

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"pape-storage/internal/config"
)

func TestAcquireUploadAndDownload(t *testing.T) {
	cfg := &config.Config{
		DataDir: "objects", BaseDir: t.TempDir(), PublicBaseURL: "https://storage.example.test",
		AdminToken: "admin-secret", SigningKey: "0123456789abcdef0123456789abcdef",
		TokenTTLSeconds: 1200, MaxUploadBytes: 1024,
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.randomKey = func() (string, error) { return "00112233445566778899aabbccddeeff", nil }
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()

	requestBody := `{"channel_id":"Photos","category":"photo/a222af2f","original_filename":"capture.bin","max_bytes":32}`
	request, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/admin/v1/upload-tokens", strings.NewReader(requestBody))
	request.Header.Set("Authorization", "Bearer admin-secret")
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("acquire status=%d body=%s", response.StatusCode, body)
	}
	var acquired AcquireResponse
	if err := json.NewDecoder(response.Body).Decode(&acquired); err != nil {
		t.Fatal(err)
	}
	wantKey := "photo/a222af2f/00112233445566778899aabbccddeeff"
	if acquired.AddForm["key"] != wantKey || acquired.URL != "https://storage.example.test/"+wantKey {
		t.Fatalf("acquired = %+v", acquired)
	}

	content := []byte("0123456789")
	var uploadBody bytes.Buffer
	writer := multipart.NewWriter(&uploadBody)
	for key, value := range acquired.AddForm {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	part, err := writer.CreateFormFile("file", "capture.bin")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(content)
	_ = writer.Close()
	uploadRequest, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/", &uploadBody)
	uploadRequest.Header.Set("Content-Type", writer.FormDataContentType())
	uploadResponse, err := http.DefaultClient.Do(uploadRequest)
	if err != nil {
		t.Fatal(err)
	}
	uploadResponse.Body.Close()
	if uploadResponse.StatusCode != http.StatusOK {
		t.Fatalf("upload status = %d", uploadResponse.StatusCode)
	}
	if uploadResponse.Header.Get("ETag") != `"781E5E245D69B566979B86E28D23F2C7"` || uploadResponse.Header.Get("Content-MD5") == "" {
		t.Fatalf("upload checksum headers = %v", uploadResponse.Header)
	}
	stored, err := filepath.Abs(filepath.Join(cfg.BaseDir, cfg.DataDir, filepath.FromSlash(wantKey)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, cfg.BaseDir) {
		t.Fatalf("stored path escaped temp directory: %s", stored)
	}

	downloadRequest, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/"+wantKey, nil)
	downloadRequest.Header.Set("Range", "bytes=2-5")
	downloadResponse, err := http.DefaultClient.Do(downloadRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer downloadResponse.Body.Close()
	downloaded, _ := io.ReadAll(downloadResponse.Body)
	if downloadResponse.StatusCode != http.StatusPartialContent || string(downloaded) != "2345" {
		t.Fatalf("range status=%d body=%q", downloadResponse.StatusCode, downloaded)
	}

	headResponse, err := http.Head(httpServer.URL + "/" + wantKey)
	if err != nil {
		t.Fatal(err)
	}
	headResponse.Body.Close()
	if headResponse.StatusCode != http.StatusOK || headResponse.ContentLength != int64(len(content)) {
		t.Fatalf("head status=%d length=%d", headResponse.StatusCode, headResponse.ContentLength)
	}
	optionsRequest, _ := http.NewRequest(http.MethodOptions, httpServer.URL+"/anything", nil)
	optionsResponse, err := http.DefaultClient.Do(optionsRequest)
	if err != nil {
		t.Fatal(err)
	}
	optionsResponse.Body.Close()
	if optionsResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("options status = %d", optionsResponse.StatusCode)
	}
}

func TestAcquirePreservesRequestedObjectName(t *testing.T) {
	cfg := &config.Config{
		DataDir: t.TempDir(), PublicBaseURL: "https://storage.example.test",
		AdminToken: "admin-secret", SigningKey: "0123456789abcdef0123456789abcdef",
		TokenTTLSeconds: 1200, MaxUploadBytes: 1024,
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/upload-tokens", strings.NewReader(
		`{"channel_id":"LocalDataRecord","category":"CommonBiz/account","object_name":"HandBook_2_82797752.bin"}`))
	request.Header.Set("Authorization", "Bearer admin-secret")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response AcquireResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.AddForm["key"] != "CommonBiz/account/HandBook_2_82797752.bin" {
		t.Fatalf("key = %q", response.AddForm["key"])
	}
}

func TestRejectsUnauthorizedAcquireAndTraversal(t *testing.T) {
	cfg := &config.Config{
		DataDir: t.TempDir(), PublicBaseURL: "https://storage.example.test",
		AdminToken: "admin-secret", SigningKey: "0123456789abcdef0123456789abcdef",
		TokenTTLSeconds: 1200, MaxUploadBytes: 1024,
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/admin/v1/upload-tokens", strings.NewReader(`{"category":"../private"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", recorder.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/admin/v1/upload-tokens", strings.NewReader(`{"category":"../private"}`))
	request.Header.Set("Authorization", "Bearer admin-secret")
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("traversal status = %d", recorder.Code)
	}

	escaped := url.PathEscape("../private")
	request = httptest.NewRequest(http.MethodGet, "/"+escaped, nil)
	recorder = httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("download traversal status = %d", recorder.Code)
	}
}
