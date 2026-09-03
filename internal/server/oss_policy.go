package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const ossV4SignatureVersion = "OSS4-HMAC-SHA256"

type postPolicy struct {
	Expiration string            `json:"expiration"`
	Conditions []json.RawMessage `json:"conditions"`
}

type postPolicyLimits struct {
	min int64
	max int64
}

func (s *Server) verifyPostPolicy(c *gin.Context, objectKey string) (postPolicyLimits, error) {
	var limits postPolicyLimits
	version := c.PostForm("x-oss-signature-version")
	credential := c.PostForm("x-oss-credential")
	timestamp := c.PostForm("x-oss-date")
	policyEncoded := c.PostForm("policy")
	signature := c.PostForm("x-oss-signature")
	if version != ossV4SignatureVersion || credential == "" || timestamp == "" || policyEncoded == "" || signature == "" {
		return limits, errors.New("missing required OSS V4 POST form fields")
	}
	parts := strings.Split(credential, "/")
	if len(parts) != 5 || parts[0] != s.cfg.AccessKeyID || parts[2] != s.cfg.Region || parts[3] != "oss" || parts[4] != "aliyun_v4_request" {
		return limits, errors.New("invalid x-oss-credential scope")
	}
	requestTime, err := time.Parse("20060102T150405Z", timestamp)
	if err != nil || requestTime.Format("20060102") != parts[1] {
		return limits, errors.New("invalid x-oss-date")
	}
	now := s.now().UTC()
	if requestTime.After(now.Add(15*time.Minute)) || requestTime.Before(now.Add(-7*24*time.Hour)) {
		return limits, errors.New("x-oss-date is outside the permitted time window")
	}
	wantSignature := signPostPolicy(s.cfg.AccessKeySecret, parts[1], s.cfg.Region, policyEncoded)
	providedSignature, err := hex.DecodeString(signature)
	if err != nil || !hmac.Equal(providedSignature, wantSignature) {
		return limits, errors.New("the request signature does not match")
	}
	rawPolicy, err := base64.StdEncoding.DecodeString(policyEncoded)
	if err != nil {
		return limits, errors.New("policy is not valid Base64")
	}
	var policy postPolicy
	decoder := json.NewDecoder(bytes.NewReader(rawPolicy))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return limits, errors.New("policy is not valid JSON")
	}
	expires, err := time.Parse(time.RFC3339Nano, policy.Expiration)
	if err != nil || !expires.After(now) || expires.After(requestTime.Add(7*24*time.Hour)) {
		return limits, errors.New("policy has expired or has an invalid expiration")
	}

	required := map[string]string{
		"key": objectKey, "x-oss-signature-version": version,
		"x-oss-credential": credential, "x-oss-date": timestamp,
	}
	if token := c.PostForm("x-oss-security-token"); token != "" {
		required["x-oss-security-token"] = token
	}
	matched := make(map[string]bool, len(required))
	for _, condition := range policy.Conditions {
		if err := s.evaluateCondition(c, condition, required, matched, &limits); err != nil {
			return limits, err
		}
	}
	for field := range required {
		if !matched[field] {
			return limits, fmt.Errorf("policy does not constrain %s", field)
		}
	}
	if limits.max <= 0 || limits.max > s.cfg.MaxUploadBytes {
		return limits, errors.New("policy content-length-range exceeds the server limit")
	}
	return limits, nil
}

func (s *Server) evaluateCondition(c *gin.Context, raw json.RawMessage, required map[string]string, matched map[string]bool, limits *postPolicyLimits) error {
	var exact map[string]string
	if err := json.Unmarshal(raw, &exact); err == nil && exact != nil {
		for field, want := range exact {
			got := postField(c, s.cfg.Bucket, field)
			if got != want {
				return fmt.Errorf("policy condition failed for %s", field)
			}
			if required[field] == want {
				matched[field] = true
			}
		}
		return nil
	}
	var values []any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&values); err != nil || len(values) < 3 {
		return errors.New("policy contains an invalid condition")
	}
	operator, ok := values[0].(string)
	if !ok {
		return errors.New("policy condition operator is invalid")
	}
	if operator == "content-length-range" {
		if len(values) != 3 {
			return errors.New("content-length-range condition is invalid")
		}
		min, err1 := jsonNumberInt64(values[1])
		max, err2 := jsonNumberInt64(values[2])
		if err1 != nil || err2 != nil || min < 0 || max < min {
			return errors.New("content-length-range condition is invalid")
		}
		limits.min, limits.max = min, max
		return nil
	}
	field, ok := values[1].(string)
	if !ok || !strings.HasPrefix(field, "$") {
		return errors.New("policy condition field is invalid")
	}
	field = strings.TrimPrefix(field, "$")
	got := postField(c, s.cfg.Bucket, field)
	switch operator {
	case "eq":
		want, ok := values[2].(string)
		if !ok || got != want {
			return fmt.Errorf("policy condition failed for %s", field)
		}
		if required[field] == want {
			matched[field] = true
		}
	case "starts-with":
		prefix, ok := values[2].(string)
		if !ok || !strings.HasPrefix(got, prefix) {
			return fmt.Errorf("policy condition failed for %s", field)
		}
	case "in", "not-in":
		items, ok := values[2].([]any)
		if !ok {
			return errors.New("policy membership condition is invalid")
		}
		contains := false
		for _, item := range items {
			if text, ok := item.(string); ok && text == got {
				contains = true
			}
		}
		if (operator == "in" && !contains) || (operator == "not-in" && contains) {
			return fmt.Errorf("policy condition failed for %s", field)
		}
	default:
		return fmt.Errorf("unsupported policy condition %q", operator)
	}
	return nil
}

func postField(c *gin.Context, bucket, field string) string {
	if strings.EqualFold(field, "bucket") {
		return bucket
	}
	return c.PostForm(field)
}

func jsonNumberInt64(value any) (int64, error) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, errors.New("not a number")
	}
	return strconv.ParseInt(number.String(), 10, 64)
}

func signPostPolicy(secret, date, region, policy string) []byte {
	dateKey := ossHMAC([]byte("aliyun_v4"+secret), date)
	regionKey := ossHMAC(dateKey, region)
	serviceKey := ossHMAC(regionKey, "oss")
	signingKey := ossHMAC(serviceKey, "aliyun_v4_request")
	return ossHMAC(signingKey, policy)
}

func ossHMAC(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func (s *Server) ossError(c *gin.Context, status int, code, message string) {
	requestID, _ := randomObjectID()
	requestID = strings.ToUpper(requestID)
	c.Header("x-oss-request-id", requestID)
	c.XML(status, struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string   `xml:"Code"`
		Message   string   `xml:"Message"`
		RequestID string   `xml:"RequestId"`
		HostID    string   `xml:"HostId"`
	}{Code: code, Message: message, RequestID: requestID, HostID: c.Request.Host})
}
