# Apple Account security-key login

## Prerequisites and limitations

This experimental feature requires macOS, Homebrew libfido2, one enrolled USB
security key, and an explicitly selected anisette-v1 service.

A successful real-account download with the current fixes remains unverified.
Compatibility with other accounts, macOS versions and key models is experimental.
NFC, Bluetooth and multi-key selection are not supported. Expired sessions require
another interactive security-key login, including when using MCP.

## Quick start

From the source checkout, build and log in using a remote HTTPS service:

```sh
brew install libfido2
CGO_ENABLED=1 go build -o /tmp/ipatool-security-key .
/tmp/ipatool-security-key auth login --security-key --anisette-url https://ani.sidestore.io --email you@example.com
/tmp/ipatool-security-key auth info
```

Enter your password at the hidden prompt, then insert and touch the enrolled key.
Enter its local PIN if requested. Ctrl-C cancels. Use the same build for subsequent
commands. The password, PET and PIN are not saved.

For an existing local anisette-v1 service, replace the URL with
`http://127.0.0.1:6969` (or its configured loopback address and port).

## Code-based login (`--gsa-code`)

Accounts that verify with a 6-digit code on a trusted device can use the same
GrandSlam flow without a hardware key:

```sh
CGO_ENABLED=1 go build -o /tmp/ipatool-gsa .
/tmp/ipatool-gsa auth login --gsa-code --anisette-url https://ani.sidestore.io --email you@example.com
```

Enter your password at the hidden prompt. If Apple requires secondary
authentication it shows a code on your trusted devices; type it when asked. A
rejected code is never retried automatically. SMS verification is not
implemented, and this mode needs no libfido2. The code endpoints follow public
GrandSlam reference implementations and have only been exercised against mocks
and a made-up account, not a real one. Like security-key sessions, expired
sessions require another interactive login.

## Troubleshooting

- **Service URL rejected:** use HTTPS, or HTTP on `127.0.0.1` or `[::1]`.
  Credentials, query parameters, fragments and redirects are not accepted.
- **Key not detected:** connect only the enrolled USB key. Insertion and touch
  each have a 60-second timeout.
- **Incorrect PIN:** it is not retried automatically. Verify the PIN before
  starting another login.
- **Session expired:** rerun the interactive login command outside MCP.

## Authentication and storage

1. GrandSlam SRP authenticates the password and verifies the server proof before
   decrypting session data. Both `s2k` and `s2k_fo` are supported.
2. When Apple requests secondary authentication, establish the GSA `/auth`
   session, fetch the `/auth/verify/security/key` challenge, and submit a libfido2
   assertion. The RP ID is `apple.com`; the PIN is used only by the local device.
3. Refresh anisette headers and repeat SRP to obtain the PET. HTTP 503 permits
   one delayed retry at this stage, without repeating the key operation.
4. Exchange the PET through the bag-selected legacy Store endpoint using the
   existing login payload and SAP signer. Validate every redirect destination
   and sign every POST. Transient Store responses permit at most three attempts,
   honoring bounded Retry-After and cancellation.
5. Require a Store token, DSID and storefront, and compare the DSID with GSA when
   present before saving the account and Store cookies. A malformed GSA DSID
   is rejected. Signer cleanup failure prevents saving; a keychain write error
   restores the cookie file.

The account records `SecurityKey=true` and no password or PET. GSA cookies stay
in memory; only Store response cookies are committed. Cookie rollback covers
returned errors, not a process crash between cookie and keychain writes.
Diagnostics omit response bodies, tokens, PINs and Cookie values.

The anisette request sends no account credentials and accepts only allowlisted
headers. Device provisioning and state belong to the service; ipatool does not
call local AOSKit or implement anisette-v3 provisioning.

## Developer verification

The security-key package works without CGO. Building the CLI on macOS requires
CGO for its existing 1Password dependency.

```sh
go test ./internal/securitykey/... ./pkg/http ./pkg/appstore ./cmd ./internal/store/emulator
IPATOOL_TEST_LOCAL_SECURITY_KEY=1 IPATOOL_TEST_ANISETTE_URL=http://127.0.0.1:6969 \
  go test ./internal/securitykey -run '^TestLocalSecurityKeyPrerequisites$' -count=1 -v
```

The default tests use synthetic credentials. The optional prerequisite check
loads libfido2 and contacts the configured service without logging in or opening a key.

The recorded 2026-10-29 check completed GSA/PET and legacy Store login for one
account. Later download testing exposed a missing emulator `setQuery:` method
and missing Store cookie persistence; both now have regression tests. These
tests do not establish a successful real-account download.

Protocol sources and retained licenses are in
[NOTICE.md](../internal/securitykey/NOTICE.md). Developer Portal/iCloud sessions
are not Store credentials; a PET must be exchanged for a Store passwordToken.
