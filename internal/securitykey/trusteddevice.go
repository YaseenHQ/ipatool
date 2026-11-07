package securitykey

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const (
	trustedDeviceEndpoint     = "https://gsa.apple.com/auth/verify/trusteddevice"
	trustedDeviceCodeEndpoint = "https://gsa.apple.com/auth/verify/trusteddevice/securitycode"
)

// CodeInteraction supplies the verification code once Apple has asked the
// user's trusted devices to display it.
type CodeInteraction struct {
	Code   func(context.Context) (string, error)
	Status func(string)
}

func (i CodeInteraction) status(message string) {
	if i.Status != nil {
		i.Status(message)
	}
}

// ErrInvalidVerificationCode reports a rejected or malformed code. It is never
// retried automatically so that a typo cannot consume attempts unattended.
var ErrInvalidVerificationCode = errors.New("verification code was rejected by Apple")

func normalizeVerificationCode(code string) (string, error) {
	code = strings.TrimSpace(strings.ReplaceAll(code, " ", ""))
	if len(code) != 6 {
		return "", errors.New("verification code must be 6 digits")
	}

	for _, r := range code {
		if r < '0' || r > '9' {
			return "", errors.New("verification code must be 6 digits")
		}
	}

	return code, nil
}

func (c *GrandSlamClient) trustedDeviceHeaders(auth *GrandSlamChallenge) (http.Header, error) {
	headers, err := c.twoFactorHeaders(auth)
	if err != nil {
		return nil, err
	}

	headers.Set("Content-Type", grandSlamContentType)
	headers.Set("Accept", grandSlamContentType)
	headers.Set("Accept-Language", "en-us")
	headers.Set("X-Apple-App-Info", "com.apple.gs.xcode.auth")
	headers.Set("X-Xcode-Version", "11.2 (11B41)")

	return headers, nil
}

// VerifyTrustedDeviceCode asks Apple to show a verification code on the
// account's trusted devices, then submits the code the user types in.
func (c *GrandSlamClient) VerifyTrustedDeviceCode(ctx context.Context, auth *GrandSlamChallenge, interaction CodeInteraction) error {
	if interaction.Code == nil {
		return errors.New("verification code prompt is not configured")
	}

	headers, err := c.trustedDeviceHeaders(auth)
	if err != nil {
		return err
	}

	interaction.status("gsa: asking Apple to show a verification code on your trusted devices")

	if _, err := c.request(ctx, http.MethodGet, trustedDeviceEndpoint, headers, nil); err != nil {
		return fmt.Errorf("request trusted-device code: %w", err)
	}

	raw, err := interaction.Code(ctx)
	if err != nil {
		return fmt.Errorf("read verification code: %w", err)
	}

	code, err := normalizeVerificationCode(raw)
	if err != nil {
		return err
	}

	headers.Set("security-code", code)
	interaction.status("gsa: submitting verification code")

	_, err = c.request(ctx, http.MethodGet, trustedDeviceCodeEndpoint, headers, nil)
	if err != nil {
		var httpErr *GrandSlamHTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode >= http.StatusBadRequest && httpErr.StatusCode < http.StatusInternalServerError {
			return fmt.Errorf("%w (HTTP %d)", ErrInvalidVerificationCode, httpErr.StatusCode)
		}

		return fmt.Errorf("submit verification code: %w", err)
	}
	// As with security keys, success here is not a session: the caller must
	// repeat SRP afterwards to obtain the PET.
	return nil
}
