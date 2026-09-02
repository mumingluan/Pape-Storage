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

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
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
	gin.SetMode(gin.ReleaseMode)
	binding.EnableDecoderDisallowUnknownFields = true
	router := gin.New()
	router.Use(gin.Recovery(), s.cors())
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.POST("/admin/v1/upload-tokens", s.acquire)
	router.POST("/", s.upload)
	router.NoRoute(func(c *gin.Context) {
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead {
			s.download(c)
			return
		}
		c.String(http.StatusNotFound, "not found")
	})
	return router
}

func (s *Server) acquire(c *gin.Context) {
	provided := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
	if !hmac.Equal([]byte(provided), []byte(s.cfg.AdminToken)) {
		c.String(http.StatusUnauthorized, "unauthorized")
		return
	}
	var request acquireRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 64<<10)
	if err := c.ShouldBindJSON(&request); err != nil {
		c.String(http.StatusBadRequest, "invalid JSON request")
		return
	}
	category, err := cleanObjectKey(request.Category)
	if err != nil || category == "" {
		c.String(http.StatusBadRequest, "invalid category")
		return
	}
	id, err := s.randomKey()
	if err != nil {
		c.String(http.StatusInternalServerError, "could not generate object key")
		return
	}
	objectName := request.ObjectName
	if objectName != "" {
		objectName, err = cleanObjectName(objectName)
		if err != nil {
			c.String(http.StatusBadRequest, "invalid object_name")
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
		c.String(http.StatusInternalServerError, "could not sign upload token")
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
	c.JSON(http.StatusOK, response)
}

func (s *Server) upload(c *gin.Context) {
	r := c.Request
	r.Body = http.MaxBytesReader(c.Writer, r.Body, s.cfg.MaxUploadBytes+(2<<20))
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		c.String(http.StatusBadRequest, "invalid multipart upload")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	value := c.PostForm("x-oss-security-token")
	claims, err := s.signer.Verify(value)
	if err != nil {
		c.String(http.StatusForbidden, "invalid or expired upload token")
		return
	}
	key, err := cleanObjectKey(c.PostForm("key"))
	if err != nil || key != claims.Key {
		c.String(http.StatusForbidden, "object key does not match upload token")
		return
	}
	if signature := c.PostForm("x-oss-signature"); signature != "" && !hmac.Equal([]byte(signature), []byte(s.formSignature(value))) {
		c.String(http.StatusForbidden, "invalid form signature")
		return
	}
	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.String(http.StatusBadRequest, "file field is required")
		return
	}
	file, err := fileHeader.Open()
	if err != nil {
		c.String(http.StatusBadRequest, "file field is invalid")
		return
	}
	defer file.Close()
	destination, err := s.objectPath(key)
	if err != nil {
		c.String(http.StatusBadRequest, "invalid object key")
		return
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		c.String(http.StatusInternalServerError, "could not create object directory")
		return
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".upload-*")
	if err != nil {
		c.String(http.StatusInternalServerError, "could not create object")
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
		c.String(http.StatusRequestEntityTooLarge, "object exceeds upload limit")
		return
	}
	if err := temporary.Close(); err != nil {
		c.String(http.StatusInternalServerError, "could not finish object")
		return
	}
	if err := replaceFile(temporaryName, destination); err != nil {
		c.String(http.StatusInternalServerError, "could not commit object")
		return
	}
	succeeded = true
	checksum := digest.Sum(nil)
	c.Header("ETag", "\""+strings.ToUpper(hex.EncodeToString(checksum))+"\"")
	c.Header("Content-MD5", base64.StdEncoding.EncodeToString(checksum))
	requestID, _ := randomObjectID()
	c.Header("x-oss-request-id", strings.ToUpper(requestID))
	c.Status(successStatus(c.PostForm("success_action_status")))
}

func (s *Server) download(c *gin.Context) {
	r := c.Request
	key, err := cleanObjectKey(strings.TrimPrefix(c.Request.URL.Path, "/"))
	if err != nil || key == "" {
		c.Status(http.StatusNotFound)
		return
	}
	objectPath, err := s.objectPath(key)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	file, err := os.Open(objectPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.Status(http.StatusNotFound)
		} else {
			c.String(http.StatusInternalServerError, "could not open object")
		}
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		c.Status(http.StatusNotFound)
		return
	}
	c.Header("Cache-Control", "public, max-age=31536000, immutable")
	c.Header("ETag", fmt.Sprintf("W/\"%x-%x\"", info.Size(), info.ModTime().UnixNano()))
	if contentType := mime.TypeByExtension(path.Ext(key)); contentType != "" {
		c.Header("Content-Type", contentType)
	}
	http.ServeContent(c.Writer, r, path.Base(key), info.ModTime(), file)
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

func (s *Server) cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Range")
		c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Range, ETag")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
