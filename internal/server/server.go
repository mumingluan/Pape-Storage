package server

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pape-storage/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

type Server struct {
	cfg     *config.Config
	objects string
	now     func() time.Time
}

func New(cfg *config.Config) (*Server, error) {
	objects := cfg.ObjectDir()
	if err := os.MkdirAll(objects, 0o755); err != nil {
		return nil, err
	}
	return &Server{
		cfg: cfg, objects: objects, now: time.Now,
	}, nil
}

func Run(cfg *config.Config) error {
	srv, err := New(cfg)
	if err != nil {
		return err
	}
	address := fmt.Sprintf("%s:%d", cfg.BindHost, cfg.BindPort)
	log.Printf("[storage] listening on http://%s (public=%s, objects=%s)", address, cfg.PublicBaseURL, cfg.ObjectDir())
	return http.ListenAndServe(address, srv.Handler())
}

func (s *Server) Handler() http.Handler {
	gin.SetMode(gin.ReleaseMode)
	binding.EnableDecoderDisallowUnknownFields = true
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery(), s.cors())
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
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
	key, err := cleanObjectKey(c.PostForm("key"))
	if err != nil {
		s.ossError(c, http.StatusBadRequest, "InvalidObjectName", "The specified object name is invalid.")
		return
	}
	limits, err := s.verifyPostPolicy(c, key)
	if err != nil {
		s.ossError(c, http.StatusForbidden, "SignatureDoesNotMatch", err.Error())
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
	written, copyErr := io.Copy(io.MultiWriter(temporary, digest), io.LimitReader(file, limits.max+1))
	if copyErr != nil || written > limits.max || written < limits.min {
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

func randomObjectID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
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
