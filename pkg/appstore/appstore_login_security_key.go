package appstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/majd/ipatool/v2/internal/securitykey"
	storehttp "github.com/majd/ipatool/v2/pkg/http"
	"howett.net/plist"
)

var ErrSecurityKeyLoginRequired = errors.New("security-key session requires interactive login; run 'ipatool auth login --security-key --anisette-url <URL>'")

type SecurityKeyInteraction struct {
	AnisetteURL string
	Context     context.Context
	PIN         func(context.Context) (string, error)
	Status      func(string)
}

func (t *appstore) loginSecurityKey(input LoginInput) (LoginOutput, error) {
	if input.AuthCode != "" {
		return LoginOutput{}, errors.New("security-key login cannot be combined with an auth code")
	}

	if input.SecurityKeyInteraction == nil {
		return LoginOutput{}, ErrSecurityKeyLoginRequired
	}

	if t.cookieJar == nil {
		return LoginOutput{}, errors.New("store cookie storage is not configured")
	}

	interaction := input.SecurityKeyInteraction

	ctx := interaction.Context
	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	status := func(message string) {
		if interaction.Status != nil {
			interaction.Status(message)
		}
	}

	if err := securitykey.CheckSupport(); err != nil {
		return LoginOutput{}, fmt.Errorf("check security-key support: %w", err)
	}

	status("security-key: fetching anisette headers from service")

	headers, err := securitykey.Headers(ctx, interaction.AnisetteURL)
	if err != nil {
		return LoginOutput{}, fmt.Errorf("fetch anisette headers: %w", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return LoginOutput{}, fmt.Errorf("create authentication cookie jar: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	gsa, err := securitykey.NewGrandSlamClient(client, headers)
	if err != nil {
		return LoginOutput{}, fmt.Errorf("create GrandSlam client: %w", err)
	}

	status("security-key: authenticating with GrandSlam")

	session, err := gsa.Login(ctx, input.Email, input.Password)

	var challenge *securitykey.GrandSlamChallenge

	if errors.As(err, &challenge) {
		err = gsa.VerifySecurityKey(ctx, challenge, securitykey.Interaction{PIN: interaction.PIN, Status: interaction.Status})
		if err != nil {
			return LoginOutput{}, fmt.Errorf("security-key verification: %w", err)
		}
		// Anisette OTPs are short-lived; regenerate after the user's touch/PIN.
		headers, err = securitykey.Headers(ctx, interaction.AnisetteURL)
		if err != nil {
			return LoginOutput{}, fmt.Errorf("refresh anisette headers: %w", err)
		}

		gsa, err = securitykey.NewGrandSlamClient(client, headers)
		if err != nil {
			return LoginOutput{}, fmt.Errorf("create GrandSlam client: %w", err)
		}

		status("security-key: obtaining GrandSlam PET after verification")

		session, err = gsa.LoginAfterVerification(ctx, input.Email, input.Password, securitykey.Interaction{Status: interaction.Status})
	}

	if err != nil {
		return LoginOutput{}, fmt.Errorf("security-key GrandSlam login: %w", err)
	}

	status("security-key: preparing signed legacy Store PET exchange")

	mac, err := t.machine.MacAddress()
	if err != nil {
		return LoginOutput{}, fmt.Errorf("get machine address: %w", err)
	}

	guid, machineID, err := machineIdentity(mac)
	if err != nil {
		return LoginOutput{}, err
	}

	bag, err := t.bag(ctx, guid)
	if err != nil {
		return LoginOutput{}, fmt.Errorf("security-key Store bag: %w", err)
	}

	if t.actionSignerFactory == nil {
		return LoginOutput{}, errors.New("SAP action signer is not configured")
	}

	signer, err := t.actionSignerFactory(ctx, bag.SAPConfig, machineID)
	if err != nil {
		return LoginOutput{}, fmt.Errorf("security-key SAP setup: %w", err)
	}

	if signer == nil {
		return LoginOutput{}, errors.New("SAP action signer factory returned nil")
	}
	// Isolate Store cookies from GSA cookies so GSA session cookies are neither sent to Store nor persisted.
	storeJar, err := cookiejar.New(nil)
	if err != nil {
		return LoginOutput{}, fmt.Errorf("create Store cookie jar: %w", err)
	}

	cookies := &securityKeyStoreCookies{CookieJar: storeJar}
	client.Jar = cookies
	acc, exchangeErr := t.exchangeSecurityKeySession(ctx, client, input.Email, guid, bag.AuthEndpoint, session, signer, status)
	closeErr := signer.Close()

	if exchangeErr != nil {
		return LoginOutput{}, errors.Join(fmt.Errorf("security-key Store exchange: %w", exchangeErr), closeErr)
	}

	if closeErr != nil {
		return LoginOutput{}, fmt.Errorf("security-key SAP close: %w", closeErr)
	}

	if err := ctx.Err(); err != nil {
		return LoginOutput{}, fmt.Errorf("security-key login cancelled: %w", err)
	}

	acc, err = t.saveSecurityKeyAccount(acc, cookies)
	if err != nil {
		return LoginOutput{}, err
	}

	status("security-key: Store credentials and cookies saved")

	return LoginOutput{Account: acc}, nil
}

type securityKeyStoreCookies struct {
	http.CookieJar
	responses []struct {
		origin  url.URL
		cookies []*http.Cookie
	}
}

func (j *securityKeyStoreCookies) SetCookies(origin *url.URL, cookies []*http.Cookie) {
	j.CookieJar.SetCookies(origin, cookies)
	j.responses = append(j.responses, struct {
		origin  url.URL
		cookies []*http.Cookie
	}{*origin, cookies})
}

func (t *appstore) saveSecurityKeyAccount(acc Account, cookies *securityKeyStoreCookies) (Account, error) {
	// Hardware-key accounts never silently fall back to password/OTP on expiry.
	acc.SecurityKey = true
	acc.Password = ""

	data, err := json.Marshal(acc)
	if err != nil {
		return Account{}, fmt.Errorf("encode security-key account: %w", err)
	}

	jar, ok := t.cookieJar.(interface {
		CommitCookies(func(http.CookieJar), func() error) error
	})
	if !ok {
		return Account{}, errors.New("store cookie storage does not support transactional login")
	}

	err = jar.CommitCookies(func(jar http.CookieJar) {
		for _, response := range cookies.responses {
			jar.SetCookies(&response.origin, response.cookies)
		}
	}, func() error {
		if err := t.keychain.Set("account", data); err != nil {
			return fmt.Errorf("save security-key account: %w", err)
		}

		return nil
	})
	if err != nil {
		return Account{}, fmt.Errorf("commit security-key account: %w", err)
	}

	return acc, nil
}

func (t *appstore) exchangeSecurityKeySession(ctx context.Context, client *http.Client, email, guid, authEndpoint string, session *securitykey.GrandSlamSession, signer ActionSigner, status func(string)) (Account, error) {
	if session == nil || session.PET == "" || session.ADSID == "" {
		return Account{}, errors.New("GrandSlam returned no PET or ADSID")
	}

	if err := validateAuthenticationEndpoint(authEndpoint); err != nil {
		return Account{}, err
	}
	// Use the ordinary Store request shape, but only the GSA PET as its password.
	request := t.loginRequest(email, session.PET, "", guid, authEndpoint, 1, signer)

	body, err := plist.Marshal(request.Payload.(*storehttp.XMLPayload).Content, plist.XMLFormat)
	if err != nil {
		return Account{}, fmt.Errorf("encode Store request: %w", err)
	}

	defer clear(body)

	endpoint, _ := url.Parse(authEndpoint)
	bounded := *client
	bounded.Timeout = 30 * time.Second
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	if status == nil {
		status = func(string) {}
	}

	redirects, attempt := 0, 1
	for redirects <= maxAuthenticationRedirects {
		if err := ctx.Err(); err != nil {
			return Account{}, fmt.Errorf("store exchange cancelled: %w", err)
		}

		signature, err := signer.Sign(body)
		if err != nil {
			return Account{}, errors.New("store request signing failed")
		}

		if len(signature) == 0 {
			return Account{}, errors.New("store request signature is empty")
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
		if err != nil {
			return Account{}, fmt.Errorf("create Store request: %w", err)
		}

		for key, value := range request.Headers {
			req.Header.Set(key, value)
		}

		req.Header.Set("User-Agent", storehttp.DefaultUserAgent)
		req.Header.Set("X-Apple-ActionSignature", base64.StdEncoding.EncodeToString(signature))

		res, err := bounded.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return Account{}, fmt.Errorf("store exchange cancelled: %w", ctx.Err())
			}

			return Account{}, errors.New("store credential exchange transport failed")
		}

		data, readErr := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
		res.Body.Close()

		contentType, _, mimeErr := mime.ParseMediaType(res.Header.Get("Content-Type"))
		if mimeErr != nil {
			contentType = "unknown"
		}

		correlation := res.Header.Get("X-Apple-Jingle-Correlation-Key")
		if len(correlation) > 128 || strings.IndexFunc(correlation, func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("-_:.", r)
		}) >= 0 {
			correlation = "redacted"
		}

		metadata := fmt.Sprintf("HTTP %d, content-type=%q, bytes=%d, correlation-id=%q, endpoint=%s%s, redirects=%d, attempt=%d/%d", res.StatusCode, contentType, len(data), correlation, endpoint.Hostname(), endpoint.Path, redirects, attempt, maxAuthenticationRequestAttempts)
		status("security-key: Store response: " + metadata)

		if readErr != nil || len(data) > 1<<20 {
			return Account{}, errors.New("store credential response unreadable or too large")
		}

		if res.StatusCode >= 300 && res.StatusCode < 400 {
			if !storehttp.IsAuthenticationRedirect(res.StatusCode) {
				return Account{}, errors.New("unsupported legacy Store redirect status")
			}

			destination, redirectErr := resolveAuthenticationRedirect(endpoint.String(), res.Header.Get("Location"))
			if redirectErr != nil {
				return Account{}, errors.New("refusing untrusted legacy Store redirect")
			}

			endpoint, _ = url.Parse(destination)
			redirects++

			continue
		}

		var result loginResult
		parseErr := storehttp.DecodePropertyList(data, &result)

		format := "plist"
		if len(bytes.TrimSpace(data)) == 0 {
			format = "empty"
		} else if parseErr != nil {
			format = "undecodable-plist"
		}

		responseErr := &storehttp.UnexpectedResponseError{StatusCode: res.StatusCode, ContentType: contentType, BodyLength: len(data), CorrelationID: correlation, Reason: "Store PET exchange response: " + format, RetryAfter: res.Header.Get("Retry-After")}
		_, retryable := retryableAuthenticationError(responseErr)
		// Share the ordinary login's status policy, without replaying decoded credential errors.
		unexpected := parseErr != nil || len(data) == 0 || res.StatusCode/100 == 5
		if unexpected && retryable && result.FailureType == "" && result.PasswordToken == "" {
			status("security-key: Store response format: " + format)

			if attempt == maxAuthenticationRequestAttempts {
				return Account{}, fmt.Errorf("store exchange exhausted %d attempts (%s): %w", attempt, metadata, responseErr)
			}

			delay := min(authenticationRetryDelay<<(attempt-1), maxAuthenticationRetryDelay)

			if requested, ok := authenticationRetryAfter(responseErr.RetryAfter, time.Now()); ok {
				if requested > maxAuthenticationRetryDelay {
					return Account{}, fmt.Errorf("server requested a wait longer than %s; try again later (%s): %w", maxAuthenticationRetryDelay, metadata, responseErr)
				}

				delay = max(requested, time.Second)
			}

			status(fmt.Sprintf("security-key: retrying Store exchange in %s (attempt %d/%d; no new key touch)", delay, attempt+1, maxAuthenticationRequestAttempts))
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()

				return Account{}, fmt.Errorf("store retry cancelled: %w", ctx.Err())
			case <-timer.C:
			}

			attempt++

			continue
		}

		if parseErr != nil {
			return Account{}, fmt.Errorf("store response could not be decoded (%s): %w", metadata, responseErr)
		}

		if result.CustomerMessage == CustomerMessageBadLogin && result.FailureType == "" {
			return Account{}, fmt.Errorf("store returned generic Configurator bad-login response after PET exchange (%s); no Store credentials issued", metadata)
		}

		if res.StatusCode != http.StatusOK || result.FailureType != "" || result.PasswordToken == "" || result.DirectoryServicesID == "" {
			return Account{}, fmt.Errorf("store rejected PET exchange (%s, failure present: %t, token present: %t)", metadata, result.FailureType != "", result.PasswordToken != "")
		}

		if session.DSID > 0 && result.DirectoryServicesID != strconv.FormatInt(session.DSID, 10) {
			return Account{}, errors.New("store account identity does not match GrandSlam")
		}

		storefront := res.Header.Get("X-Set-Apple-Store-Front")
		if storefront == "" {
			storefront = res.Header.Get(HTTPHeaderStoreFront)
		}

		if storefront == "" {
			return Account{}, errors.New("store credential response has no storefront")
		}

		accountEmail := result.Account.Email
		if accountEmail == "" {
			accountEmail = email
		}

		return Account{Email: accountEmail, Name: strings.TrimSpace(result.Account.Address.FirstName + " " + result.Account.Address.LastName), PasswordToken: result.PasswordToken, DirectoryServicesID: result.DirectoryServicesID, StoreFront: storefront, Pod: res.Header.Get(HTTPHeaderPod)}, nil
	}

	return Account{}, errors.New("too many legacy Store authentication redirects")
}
