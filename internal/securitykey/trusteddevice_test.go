package securitykey

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func newTrustedDeviceClient(t *testing.T, status func(path, code string) int, steps *[]string) *GrandSlamClient {
	t.Helper()

	client, err := NewGrandSlamClient(&http.Client{Transport: grandSlamRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		*steps = append(*steps, r.Method+" "+r.URL.Path)

		if r.Header.Get("X-Apple-Identity-Token") != base64.StdEncoding.EncodeToString([]byte("dsid:idms")) {
			t.Fatal("missing identity token")
		}

		if r.Header.Get("Content-Type") != grandSlamContentType || r.Header.Get("Accept") != grandSlamContentType {
			t.Fatal("unexpected content negotiation headers")
		}

		code := r.Header.Get("security-code")
		if r.URL.Path == "/auth/verify/trusteddevice" && code != "" {
			t.Fatal("code sent before it was requested")
		}

		return &http.Response{StatusCode: status(r.URL.Path, code), Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}, nil)
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func TestTrustedDeviceCodeFlow(t *testing.T) {
	var steps []string

	client := newTrustedDeviceClient(t, func(path, code string) int {
		if path == "/auth/verify/trusteddevice/securitycode" && code != "123456" {
			return http.StatusForbidden
		}

		return http.StatusOK
	}, &steps)

	err := client.VerifyTrustedDeviceCode(context.Background(), &GrandSlamChallenge{ADSID: "dsid", IDMSToken: "idms"}, CodeInteraction{
		// Spaces are tolerated because Apple displays the code as "123 456".
		Code: func(context.Context) (string, error) { return " 123 456 ", nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(steps, ","); got != "GET /auth/verify/trusteddevice,GET /auth/verify/trusteddevice/securitycode" {
		t.Fatal(got)
	}
}

func TestTrustedDeviceRejectedCodeIsNotRetried(t *testing.T) {
	var steps []string

	client := newTrustedDeviceClient(t, func(path, _ string) int {
		if path == "/auth/verify/trusteddevice/securitycode" {
			return http.StatusUnauthorized
		}

		return http.StatusOK
	}, &steps)

	err := client.VerifyTrustedDeviceCode(context.Background(), &GrandSlamChallenge{ADSID: "dsid", IDMSToken: "idms"}, CodeInteraction{
		Code: func(context.Context) (string, error) { return "000000", nil },
	})
	if !errors.Is(err, ErrInvalidVerificationCode) {
		t.Fatalf("expected rejected code, got %v", err)
	}

	if len(steps) != 2 {
		t.Fatalf("a rejected code must not be retried: %v", steps)
	}
}

func TestTrustedDeviceMalformedCodeNeverReachesApple(t *testing.T) {
	for _, code := range []string{"", "12345", "1234567", "12345a", "١٢٣٤٥٦"} {
		var steps []string

		client := newTrustedDeviceClient(t, func(string, string) int { return http.StatusOK }, &steps)

		err := client.VerifyTrustedDeviceCode(context.Background(), &GrandSlamChallenge{ADSID: "dsid", IDMSToken: "idms"}, CodeInteraction{
			Code: func(context.Context) (string, error) { return code, nil },
		})
		if err == nil {
			t.Fatalf("code %q was accepted", code)
		}

		for _, step := range steps {
			if strings.Contains(step, "securitycode") {
				t.Fatalf("malformed code %q was submitted", code)
			}
		}
	}
}

func TestTrustedDeviceServerErrorIsNotReportedAsBadCode(t *testing.T) {
	var steps []string

	client := newTrustedDeviceClient(t, func(path, _ string) int {
		if path == "/auth/verify/trusteddevice/securitycode" {
			return http.StatusServiceUnavailable
		}

		return http.StatusOK
	}, &steps)

	err := client.VerifyTrustedDeviceCode(context.Background(), &GrandSlamChallenge{ADSID: "dsid", IDMSToken: "idms"}, CodeInteraction{
		Code: func(context.Context) (string, error) { return "123456", nil },
	})
	if err == nil || errors.Is(err, ErrInvalidVerificationCode) {
		t.Fatalf("a 503 must not be reported as a rejected code: %v", err)
	}
}

func TestTrustedDeviceRequiresPromptAndChallenge(t *testing.T) {
	var steps []string

	client := newTrustedDeviceClient(t, func(string, string) int { return http.StatusOK }, &steps)

	if err := client.VerifyTrustedDeviceCode(context.Background(), &GrandSlamChallenge{ADSID: "dsid", IDMSToken: "idms"}, CodeInteraction{}); err == nil {
		t.Fatal("missing prompt was accepted")
	}

	if err := client.VerifyTrustedDeviceCode(context.Background(), nil, CodeInteraction{Code: func(context.Context) (string, error) { return "123456", nil }}); err == nil {
		t.Fatal("missing challenge was accepted")
	}

	if len(steps) != 0 {
		t.Fatalf("invalid input reached the network: %v", steps)
	}
}
