package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/ua-parser/uap-go/uaparser"
	"crypto/rand"
	"encoding/base64"
	"regexp"
)

func VerifyCodeVerifier(code_verifier string, code_challenge string) bool{
	hash:=sha256.Sum256([]byte(code_verifier))
	computed:=base64.RawURLEncoding.EncodeToString(hash[:])
	return computed == code_challenge
}

func PasswordValidator(password string) bool {
	if len(password) < 12 || len(password) > 36 {
		return false
	}
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[-!@#$%^&*(),.?":{}|<>]`).MatchString(password)
	return hasLower && hasUpper && hasDigit && hasSpecial
}

func AuthorizationCodeGenerator() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}


type Fingerprint struct {
	AcceptLanguage string
	AcceptEncoding string
	AcceptCharset  string
	DeviceBrand    string
	OSName         string
	OSVersion      string
	Browser        string
	BrowserVersion string
}

func GenerateFingerprint(r *http.Request) (string, Fingerprint) {
	uaString := r.Header.Get("User-Agent")
	parser := uaparser.NewFromSaved()
	client := parser.Parse(uaString)

	fp := Fingerprint{
		AcceptLanguage: r.Header.Get("Accept-Language"),
		AcceptEncoding: r.Header.Get("Accept-Encoding"),
		AcceptCharset:  r.Header.Get("Accept-Charset"),
		DeviceBrand:    client.Device.Brand,
		OSName:         client.Os.Family,
		OSVersion:      client.Os.ToVersionString(),
		Browser:        client.UserAgent.Family,
		BrowserVersion: client.UserAgent.ToVersionString(),
	}

	if fp.DeviceBrand == "" { fp.DeviceBrand = "Unknown" }
	if fp.OSVersion == "" { fp.OSVersion = "Unknown" }
	if fp.BrowserVersion == "" { fp.BrowserVersion = "Unknown" }

	return fingerprintize(fp), fp
}

func fingerprintize(fp Fingerprint) string {
	data := map[string]string{
		"accept_language": fp.AcceptLanguage,
		"device_brand":    fp.DeviceBrand,
		"os_name":         fp.OSName,
		"os_version":      fp.OSVersion,
		"browser":         fp.Browser,
		"browser_version": fp.BrowserVersion,
		"accept_encoding": fp.AcceptEncoding,
		"accept_charset":  fp.AcceptCharset,
	}

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(fmt.Sprintf("%s:%s", k, data[k]))
	}

	hash := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(hash[:])
}