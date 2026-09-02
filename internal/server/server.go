package server

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pape-storage/internal/config"
	"pape-storage/internal/token"
)

type Server struct {
	cfg       *config.Config
	objects   string
	signer    *token.Signer
	now       func() time.Time
	randomKey func() (string, error)
}

type acquireRequest struct {
	ChannelID        string `json:"channel_id"`
	Category         string `json:"category"`
	OriginalFilename string `json:"original_filename"`
	ObjectName       string `json:"object_name"`
	Extension        string `json:"extension"`
	MaxBytes         int64  `json:"max_bytes"`
}

type AcquireResponse struct {
	Address   string            `json:"address"`
	URL       string            `json:"url"`
	AddForm   map[string]string `json:"add_form"`
	AddHeader map[string]string `json:"add_header"`
}

func New(cfg *config.Config) (*Server, error) {
	objects := cfg.ObjectDir()
	if err := os.MkdirAll(objects, 0o755); err != nil {
		return nil, err
	}
	return &Server{
		cfg: cfg, objects: objects, signer: token.New(cfg.SigningKey), now: time.Now,
		randomKey: randomObjectID,
	}, nil
}

func Run(cfg *config.Config) error {
	srv, err := New(cfg)
	if err != nil {
		return err
	}
	address := fmt.Sprintf("%s:%d", cfg.BindHost, cfg.BindPort)
	return http.ListenAndServe(address, srv.Handler())
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		switch {
		case r.URL.Path == "/healthz" && r.Method == http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		case r.URL.Path == "/admin/v1/upload-tokens" && r.Method == http.MethodPost:
			s.acquire(w, r)
		case r.URL.Path == "/" && r.Method == http.MethodPost:
			s.upload(w, r)
		case r.Method == http.MethodGet || r.Method == http.MethodHead:
			s.download(w, r)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})
}

func (s *Server) acquire(w http.ResponseWriter, r *http.Request) {
	provided := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if !hmac.Equal([]byte(provided), []byte(s.cfg.AdminToken)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var request acquireRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid JSON request", http.StatusBadRequest)
		return
	}
	category, err := cleanObjectKey(request.Category)
	if err != nil || category == "" {
		http.Error(w, "invalid category", http.StatusBadRequest)
		return
	}
	id, err := s.randomKey()
	if err != nil {
		http.Error(w, "could not generate object key", http.StatusInternalServerError)
		return
	}
	objectName := request.ObjectName
	if objectName != "" {
		objectName, err = cleanObjectName(objectName)
		if err != nil {
			http.Error(w, "invalid object_name", http.StatusBadRequest)
			return
		}
	} else {
		objectName = id + safeExtension(request.Extension)
	}
	objectKey := category + "/" + objectName
	maxBytes := request.MaxBytes
	if maxBytes <= 0 || maxBytes > s.cfg.MaxUploadBytes {
		maxBytes = s.cfg.MaxUploadBytes
	}
	expires := s.now().Add(time.Duration(s.cfg.TokenTTLSeconds) * time.Second)
	uploadToken, err := s.signer.Sign(token.Claims{Key: objectKey, Expires: expires.Unix(), MaxBytes: maxBytes})
	if err != nil {
		http.Error(w, "could not sign upload token", http.StatusInternalServerError)
		return
	}
	policyJSON, _ := json.Marshal(map[string]any{
		"expiration": expires.UTC().Format(time.RFC3339Nano),
		"conditions": []any{map[string]string{"key": objectKey}, []any{"content-length-range", 0, maxBytes}},
	})
	now := s.now().UTC()
	date := now.Format("20060102T150405Z")
	credential := "PAPE/" + now.Format("20060102") + "/local/storage/pape_v1_request"
	response := AcquireResponse{
		Address: s.cfg.PublicBaseURL,
		URL:     objectURL(s.cfg.PublicBaseURL, objectKey),
		AddForm: map[string]string{
			"key": objectKey, "policy": base64.StdEncoding.EncodeToString(policyJSON),
			"success_action_status": "200", "x-oss-credential": credential,
			"x-oss-date": date, "x-oss-security-token": uploadToken,
			"x-oss-signature":         s.formSignature(uploadToken),
			"x-oss-signature-version": "OSS4-HMAC-SHA256", "x:extend": "",
		},
		AddHeader: map[string]string{"Date": now.Format(http.TimeFormat)},
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes+(2<<20))
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		http.Error(w, "invalid multipart upload", http.StatusBadRequest)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	value := r.FormValue("x-oss-security-token")
	claims, err := s.signer.Verify(value)
	if err != nil {
		http.Error(w, "invalid or expired upload token", http.StatusForbidden)
		return
	}
	key, err := cleanObjectKey(r.FormValue("key"))
	if err != nil || key != claims.Key {
		http.Error(w, "object key does not match upload token", http.StatusForbidden)
		return
	}
	if signature := r.FormValue("x-oss-signature"); signature != "" && !hmac.Equal([]byte(signature), []byte(s.formSignature(value))) {
		http.Error(w, "invalid form signature", http.StatusForbidden)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file field is required", http.StatusBadRequest)
		return
	}
	defer file.Close()
	destination, err := s.objectPath(key)
	if err != nil {
		http.Error(w, "invalid object key", http.StatusBadRequest)
		return
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		http.Error(w, "could not create object directory", http.StatusInternalServerError)
		return
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".upload-*")
	if err != nil {
		http.Error(w, "could not create object", http.StatusInternalServerError)
		return
	}
	temporaryName := temporary.Name()
	succeeded := false
	defer func() {
		_ = temporary.Close()
		if !succeeded {
			_ = os.Remove(temporaryName)
		}
	}()
	digest := md5.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, digest), io.LimitReader(file, claims.MaxBytes+1))
	if copyErr != nil || written > claims.MaxBytes {
		http.Error(w, "object exceeds upload limit", http.StatusRequestEntityTooLarge)
		return
	}
	if err := temporary.Close(); err != nil {
		http.Error(w, "could not finish object", http.StatusInternalServerError)
		return
	}
	if err := replaceFile(temporaryName, destination); err != nil {
		http.Error(w, "could not commit object", http.StatusInternalServerError)
		return
	}
	succeeded = true
	checksum := digest.Sum(nil)
	w.Header().Set("ETag", "\""+strings.ToUpper(hex.EncodeToString(checksum))+"\"")
	w.Header().Set("Content-MD5", base64.StdEncoding.EncodeToString(checksum))
	requestID, _ := randomObjectID()
	w.Header().Set("x-oss-request-id", strings.ToUpper(requestID))
	w.WriteHeader(successStatus(r.FormValue("success_action_status")))
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	key, err := cleanObjectKey(strings.TrimPrefix(r.URL.Path, "/"))
	if err != nil || key == "" {
		http.NotFound(w, r)
		return
	}
	objectPath, err := s.objectPath(key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	file, err := os.Open(objectPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "could not open object", http.StatusInternalServerError)
		}
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("ETag", fmt.Sprintf("W/\"%x-%x\"", info.Size(), info.ModTime().UnixNano()))
	if contentType := mime.TypeByExtension(path.Ext(key)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	http.ServeContent(w, r, path.Base(key), info.ModTime(), file)
}

func (s *Server) objectPath(key string) (string, error) {
	clean, err := cleanObjectKey(key)
	if err != nil || clean == "" {
		return "", errors.New("invalid object key")
	}
	result := filepath.Join(s.objects, filepath.FromSlash(clean))
	relative, err := filepath.Rel(s.objects, result)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("object key escapes data directory")
	}
	return result, nil
}

func cleanObjectKey(value string) (string, error) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" || strings.HasPrefix(value, "/") || strings.ContainsRune(value, '\x00') {
		return "", errors.New("invalid object key")
	}
	clean := path.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", errors.New("invalid object key")
	}
	return clean, nil
}

func safeExtension(filename string) string {
	filename = strings.TrimSpace(filename)
	if filename != "" && !strings.Contains(filename, ".") {
		filename = "." + filename
	}
	extension := strings.ToLower(path.Ext(strings.ReplaceAll(filename, "\\", "/")))
	if len(extension) < 2 || len(extension) > 16 {
		return ""
	}
	for _, character := range extension[1:] {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				return ""
			}
		}
	}
	return extension
}

func cleanObjectName(value string) (string, error) {
	value = strings.TrimSpace(value)
	clean, err := cleanObjectKey(value)
	if err != nil || strings.Contains(clean, "/") || clean != value {
		return "", errors.New("invalid object name")
	}
	return clean, nil
}

func objectURL(baseURL, key string) string {
	segments := strings.Split(key, "/")
	for index := range segments {
		segments[index] = url.PathEscape(segments[index])
	}
	return strings.TrimRight(baseURL, "/") + "/" + strings.Join(segments, "/")
}

func randomObjectID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func (s *Server) formSignature(uploadToken string) string {
	mac := hmac.New(sha256.New, []byte(s.cfg.SigningKey))
	_, _ = mac.Write([]byte(uploadToken))
	return hex.EncodeToString(mac.Sum(nil))
}

func replaceFile(source, destination string) error {
	if err := os.Rename(source, destination); err == nil {
		return nil
	}
	if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(source, destination)
}

func successStatus(value string) int {
	status, err := strconv.Atoi(value)
	if err == nil && (status == http.StatusOK || status == http.StatusCreated || status == http.StatusNoContent) {
		return status
	}
	return http.StatusOK
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Range")
	w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Range, ETag")
}
