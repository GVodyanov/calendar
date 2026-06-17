# Security Vulnerabilities Report — Nextcloud Calendar App

**Repository:** [GVodyanov/calendar](https://github.com/GVodyanov/calendar)  
**Nextcloud Server Integration:** [GVodyanov/nextcloud-server](https://github.com/GVodyanov/nextcloud-server)  
**App Version:** 6.3.0-dev.0  
**Date of Review:** 2026-03-12  

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Critical Vulnerabilities](#critical-vulnerabilities)
3. [Medium Vulnerabilities](#medium-vulnerabilities)
4. [Low Vulnerabilities](#low-vulnerabilities)
5. [Informational Findings](#informational-findings)
6. [Security Best Practices (Passed)](#security-best-practices-passed)
7. [Nextcloud Server Integration Analysis](#nextcloud-server-integration-analysis)
8. [Dependency Review](#dependency-review)
9. [Remediation Roadmap](#remediation-roadmap)

---

## Executive Summary

| Severity  | Count | Status      |
|-----------|-------|-------------|
| 🔴 Critical | 1   | Open        |
| 🟠 Medium   | 2   | Open        |
| 🟡 Low      | 2   | Open        |
| ℹ️ Info     | 1   | Acknowledged|

The Nextcloud Calendar app is generally well-engineered and leverages the Nextcloud security framework effectively. However, one critical vulnerability was identified in the proposal (meeting poll) feature — the use of the cryptographically broken MD5 algorithm for generating participant tokens. Two medium-severity issues were also identified: an overly permissive Content Security Policy and a missing authorization check on a public voting endpoint. Two low-severity issues complete the findings.

---

## Critical Vulnerabilities

### VULN-01 — Weak Token Generation Using MD5 for Proposal Participants

| Field       | Details                                            |
|-------------|----------------------------------------------------|
| **Severity**   | 🔴 Critical                                     |
| **CWE**        | CWE-327: Use of a Broken or Risky Cryptographic Algorithm |
| **CVSS Score** | 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| **Files**      | `lib/Service/Proposal/ProposalService.php`      |
| **Lines**      | 187, 237                                        |

#### Description

Participant tokens for meeting proposals are generated using MD5, which is a cryptographically broken hash function. Although the input to MD5 is `random_bytes(32)` (a cryptographically secure source), passing it through MD5 reduces the output to 128 bits *and* produces output in hexadecimal (only lowercase a-f and 0-9), significantly reducing entropy and the character set.

These tokens are used as the sole authentication mechanism for external participants to vote on meeting date proposals via the public API endpoint `POST /calendar/api/v1/proposal/response`. If a token is compromised, an attacker can vote on behalf of any participant.

#### Vulnerable Code

```php
// lib/Service/Proposal/ProposalService.php, line 187
$entry->setToken(md5(random_bytes(32)));

// lib/Service/Proposal/ProposalService.php, line 237
$mutatedParticipantEntry->setToken(md5(random_bytes(32)));
```

The same token is then used publicly to authenticate votes at:

```php
// lib/Controller/ProposalController.php, lines 206–222
#[PublicPage]
#[NoCSRFRequired]
#[NoAdminRequired]
#[AnonRateLimit(limit: 10, period: 300)]
#[UserRateLimit(limit: 10, period: 300)]
public function response(array $response): JSONResponse {
    $proposalResponse = new ProposalResponseObject();
    $proposalResponse->fromJson($response);
    $this->proposalService->storeResponse($proposalResponse);
    return new JSONResponse([], Http::STATUS_OK);
}
```

#### Impact

- An attacker can enumerate or brute-force participant tokens to vote on meeting proposals on behalf of legitimate participants.
- The rate limit is 10 requests per 300 seconds (per IP), making large-scale brute-force slow but not infeasible against MD5-based tokens.
- Allows unauthorized manipulation of poll results, which can lead to incorrect meeting times being selected.

#### Recommendation

Replace `md5(random_bytes(32))` with `bin2hex(random_bytes(32))` or, preferably, use Nextcloud's `ISecureRandom` service (already used in `BookingService` and `AppointmentConfigService`):

```php
// Correct approach, consistent with the rest of the codebase:
use OCP\Security\ISecureRandom;

// In constructor:
private ISecureRandom $random;

// When generating token:
$entry->setToken($this->random->generate(64, ISecureRandom::CHAR_ALPHANUMERIC));
```

**Comparison of token security:**

| Method                          | Entropy | Notes                       |
|---------------------------------|---------|-----------------------------|
| `md5(random_bytes(32))`         | ~128 bits | MD5 is broken; hex only   |
| `bin2hex(random_bytes(32))`     | 256 bits  | Safe; hex-encoded          |
| `ISecureRandom::generate(64)`   | ~379 bits | Best; uses full alphanumeric charset |

---

## Medium Vulnerabilities

### VULN-02 — Overly Permissive Content Security Policy for Calendar Embedding

| Field       | Details                                              |
|-------------|------------------------------------------------------|
| **Severity**   | 🟠 Medium                                         |
| **CWE**        | CWE-1021: Improper Restriction of Rendered UI Layers |
| **CVSS Score** | 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) |
| **Files**      | `lib/Controller/PublicViewController.php`         |
| **Lines**      | 81–91                                             |

#### Description

The `publicIndexForEmbedding` action, used to allow embedding of public calendars in iframes, explicitly allows any domain to embed the calendar by using the CSP wildcard `*` in `frame-ancestors`:

```php
// lib/Controller/PublicViewController.php, lines 81–91
#[PublicPage]
#[NoCSRFRequired]
#[NoSameSiteCookieRequired]  // <-- SameSite cookie protection disabled
public function publicIndexForEmbedding(string $token): PublicTemplateResponse {
    $response = $this->publicIndex($token);
    $response->setFooterVisible(false);
    $response->addHeader('X-Frame-Options', 'ALLOW');

    $csp = new ContentSecurityPolicy();
    $csp->addAllowedFrameAncestorDomain('*');  // <-- Any site can embed
    $response->setContentSecurityPolicy($csp);
    // ...
}
```

Additionally, `@NoSameSiteCookieRequired` disables SameSite cookie protection for this route, removing a key defense against cross-site request forgery.

#### Impact

- **Clickjacking**: Any malicious website can embed the authenticated calendar in a transparent iframe and trick users into interacting with it (e.g., accepting meeting invitations, changing settings, deleting events).
- **UI Redressing**: Overlaying the embedded calendar with deceptive UI elements to manipulate user actions.
- Combined with `@NoSameSiteCookieRequired`, authenticated users visiting a malicious site could unknowingly perform actions on their calendar.

#### Recommendation

The embedding feature is intentional; however, the wildcard should be replaced with Nextcloud server's own origin to restrict embedding to trusted contexts, and ideally allow operators to configure allowed domains:

```php
// Use the server's own base URL or a configured whitelist
$csp->addAllowedFrameAncestorDomain($this->urlGenerator->getBaseUrl());
// Or read from admin-configurable setting:
// $allowedOrigins = $this->config->getAppValue('calendar', 'embed_allowed_origins', '');
```

---

### VULN-03 — Missing Input Validation on Public Proposal Voting Endpoint

| Field       | Details                                              |
|-------------|------------------------------------------------------|
| **Severity**   | 🟠 Medium                                         |
| **CWE**        | CWE-284: Improper Access Control                  |
| **CVSS Score** | 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N) |
| **Files**      | `lib/Controller/ProposalController.php`, `lib/Service/Proposal/ProposalService.php` |
| **Lines**      | 206–222 (controller), 406–449 (service)           |

#### Description

The public proposal response endpoint (`POST /calendar/api/v1/proposal/response`) accepts a `token` and stores votes without validating the token format or enforcing any strict size constraints before database lookup. There is no mechanism to lock or invalidate a token after a response has already been submitted.

```php
// lib/Controller/ProposalController.php, lines 206–222
#[PublicPage]
#[NoCSRFRequired]
public function response(array $response): JSONResponse {
    try {
        $proposalResponse = new ProposalResponseObject();
        $proposalResponse->fromJson($response);
        $this->proposalService->storeResponse($proposalResponse);
        return new JSONResponse([], Http::STATUS_OK);
    } catch (\Exception $e) {
        return new JSONResponse(['error' => $e->getMessage()], Http::STATUS_INTERNAL_SERVER_ERROR);
    }
}
```

The catch-all `\Exception` handler also returns the raw exception message to the client, which may leak internal implementation details.

#### Impact

- An attacker with a valid token can submit multiple responses (vote multiple times), overwriting previous votes without any check for duplicate submissions.
- The exception message is returned directly in the JSON response, potentially disclosing internal server details (e.g., database table names, query structure) if a lower-level exception is thrown.

#### Recommendation

1. **Prevent double voting**: Check whether a response already exists for the participant token before storing a new one.
2. **Sanitize exception messages**: Replace the bare `$e->getMessage()` in the catch block with a generic error message, logging the detailed exception server-side only.
3. **Validate token format**: Reject tokens that do not match the expected format (e.g., exactly 64 hex characters) before performing any database lookup.

```php
// Example improvement:
} catch (\Exception $e) {
    $this->logger->error('Failed to store proposal response', ['exception' => $e]);
    return new JSONResponse(['error' => 'An error occurred processing your response'], Http::STATUS_INTERNAL_SERVER_ERROR);
}
```

---

## Low Vulnerabilities

### VULN-04 — XSS Risk from `innerHTML` Assignment in Event Rendering

| Field       | Details                                            |
|-------------|----------------------------------------------------|
| **Severity**   | 🟡 Low                                          |
| **CWE**        | CWE-79: Improper Neutralization of Input During Web Page Generation (XSS) |
| **Files**      | `src/fullcalendar/rendering/eventDidMount.js`   |
| **Lines**      | 141                                             |

#### Description

An SVG icon is prepended to the event title using direct `innerHTML` assignment:

```javascript
// src/fullcalendar/rendering/eventDidMount.js, line 141
titleElement.innerHTML = svgString + titleElement.innerHTML
```

While `svgString` is a hardcoded static SVG string, `titleElement.innerHTML` reads back the existing inner HTML content of the element, which is populated by the FullCalendar library from calendar event data. If FullCalendar ever passes unsanitized HTML event titles to the DOM, or if the `titleElement.innerHTML` read includes injected content, this concatenation would amplify an XSS attack.

#### Impact

- Low probability of direct exploitation in current form since FullCalendar sanitizes event title output.
- If FullCalendar's sanitization were bypassed (e.g., via a malicious CalDAV event title), the combined `innerHTML` assignment could execute arbitrary JavaScript.

#### Recommendation

Use DOM API methods instead of `innerHTML` to safely insert the SVG:

```javascript
// Safe alternative using DOM API:
const svgTemplate = document.createElement('template')
svgTemplate.innerHTML = svgString  // svgString is hardcoded, safe to use here
const svgNode = svgTemplate.content.firstChild
titleElement.insertBefore(svgNode, titleElement.firstChild)
```

---

### VULN-05 — Unvalidated Token Used in Server-Side Redirect

| Field       | Details                                              |
|-------------|------------------------------------------------------|
| **Severity**   | 🟡 Low                                            |
| **CWE**        | CWE-601: URL Redirection to Untrusted Site (Open Redirect) |
| **Files**      | `lib/Controller/PublicViewController.php`         |
| **Lines**      | 69                                                |

#### Description

The `publicIndexWithBranding` action uses the user-supplied `$token` parameter directly in a redirect URL:

```php
// lib/Controller/PublicViewController.php, line 69
return new RedirectResponse(
    $this->urlGenerator->linkTo('', 'remote.php') . '/dav/public-calendars/' . $token . '/?export'
);
```

The `$token` value comes directly from the URL path segment and is appended to an internal DAV redirect URL without sanitization. PHP's string type declaration enforces it is a string, but it does not prevent path traversal sequences like `../`.

#### Impact

- A crafted token value such as `../../etc/passwd` could cause unexpected path traversal on the server-side DAV handler, though the actual impact is constrained by the DAV layer's own access controls.
- The token is constrained by route matching in `routes.php`, but no explicit character-set validation is enforced at the controller level.

#### Recommendation

Add explicit token format validation before use:

```php
// Validate token before using in redirect:
if (!preg_match('/^[a-zA-Z0-9_-]+$/', $token)) {
    return new Response('', Http::STATUS_BAD_REQUEST);
}
return new RedirectResponse(
    $this->urlGenerator->linkTo('', 'remote.php') . '/dav/public-calendars/' . $token . '/?export'
);
```

---

## Informational Findings

### INFO-01 — Debug Mode Exposes Full Exception Traces in API Responses

| Field       | Details                                            |
|-------------|----------------------------------------------------|
| **Severity**   | ℹ️ Informational                                |
| **Files**      | `lib/Controller/BookingController.php`          |
| **Lines**      | 184–188                                         |

#### Description

When Nextcloud debug mode is enabled (`'debug' => true` in `config.php`), full exception stack traces are returned in API responses to the client:

```php
// lib/Controller/BookingController.php, lines 184–188
if ($this->systemConfig->getSystemValue('debug', false)) {
    return JsonResponse::errorFromThrowable($e, $e->getHttpCode() ?? Http::STATUS_INTERNAL_SERVER_ERROR,
        ['debug' => true,]
    );
}
```

This is an accepted pattern for development environments. However, if a staging or production server accidentally has debug mode enabled, attackers could learn file paths, class names, database schema details, and exception messages.

#### Recommendation

- Ensure debug mode is disabled in all production and staging environments.
- Consider adding a warning in the app's admin documentation.

---

## Security Best Practices (Passed)

The following security controls were reviewed and found to be correctly implemented:

| Control                         | Status | Notes                                          |
|---------------------------------|--------|------------------------------------------------|
| SQL Injection Prevention        | ✅ Pass | All queries use Nextcloud's QueryBuilder with parameterized inputs |
| Output Escaping (PHP Templates) | ✅ Pass | All template output uses `p()` and `e()` helpers |
| Authentication Checks           | ✅ Pass | Authenticated routes use `IUserSession::isLoggedIn()` |
| Authorization Checks            | ✅ Pass | ProposalController validates user ownership before mutation |
| Secure Token Generation (Appointments) | ✅ Pass | Uses `ISecureRandom::generate(32, CHAR_ALPHANUMERIC)` |
| Input Validation (Settings)     | ✅ Pass | View names are validated against an explicit allowlist |
| Rate Limiting                   | ✅ Pass | Public endpoints use `#[AnonRateLimit]` and `#[UserRateLimit]` |
| Email Validation                | ✅ Pass | `IMailer::validateMailAddress()` used before sending |
| Command Injection               | ✅ Pass | No shell execution functions (`exec`, `system`, etc.) present |
| File Path Traversal             | ✅ Pass | No direct file operations with user-controlled paths |
| Insecure Deserialization        | ✅ Pass | No `unserialize()` with user input found |
| Hardcoded Credentials           | ✅ Pass | No hardcoded secrets or credentials found |
| SSRF                            | ✅ Pass | No direct HTTP client calls with user-controlled URLs |

---

## Nextcloud Server Integration Analysis

The Calendar app integrates deeply with the [GVodyanov/nextcloud-server](https://github.com/GVodyanov/nextcloud-server) via the following mechanisms:

### CalDAV Integration

The app uses the server's built-in DAV application (`apps/dav`) through the `OCA\DAV` namespace:

```php
// lib/Service/Proposal/ProposalService.php, line 28, 683
use OCA\DAV\CalDAV\InvitationResponse\InvitationResponseServer;

$calendarHome = (new InvitationResponseServer(false))
    ->getServer()
    ->tree
    ->getNodeForPath('/calendars/' . $user->getUID());
```

**Security Concern**: `InvitationResponseServer` is instantiated directly with internal Nextcloud paths. If user-supplied calendar URI strings (`$calendarUri`) are passed to `$calendarHome->getChild($calendarUri)` without validation, path traversal within the DAV tree is theoretically possible. The DAV layer itself applies access controls, but the app does not independently validate URI values before calling `getChild()`.

### Public Calendar Redirect

```
GET /p/{token}  →  /remote.php/dav/public-calendars/{token}/?export
```

The calendar sharing token is passed from a URL segment directly into a DAV redirect (see VULN-05 above). The DAV layer validates the token's existence, but the app should validate the token format itself.

### API Endpoint Exposure Summary

| Endpoint | Auth Required | Rate Limited | State-Changing |
|----------|--------------|--------------|----------------|
| `GET /appointments/{userId}` | No | No | No |
| `GET /appointment/{token}` | No | No | No |
| `GET /appointment/{token}/slots` | No | No | No |
| `POST /appointment/{token}/book` | No | Yes (AnonRateLimit) | **Yes** |
| `GET /appointment/confirm/{token}` | No | No | **Yes** |
| `GET /p/{token}` | No | No | No |
| `GET /embed/{token}` | No | No | No |
| `POST /calendar/api/v1/proposal/fetch` | No | Yes | No |
| `POST /calendar/api/v1/proposal/response` | No | Yes | **Yes** |
| `POST /calendar/api/v1/proposal/create` | **Yes** | Yes | **Yes** |
| `POST /calendar/api/v1/proposal/modify` | **Yes** | Yes | **Yes** |
| `POST /calendar/api/v1/proposal/destroy` | **Yes** | Yes | **Yes** |
| `POST /calendar/api/v1/proposal/convert` | **Yes** | Yes | **Yes** |
| `POST /v1/config/{key}` | **Yes** | No | **Yes** |
| `POST /v1/public/sendmail` | **Yes** | No | **Yes** |

### Permissions and Capabilities

Declared in `appinfo/info.xml`:

```xml
<dependencies>
    <php min-version="8.1" max-version="8.5" />
    <nextcloud min-version="32" max-version="34" />
    <backend>caldav</backend>
</dependencies>
```

The app requires the CalDAV backend and inherits all Nextcloud user-level permissions. It does not declare granular permission scopes; access control relies entirely on Nextcloud's session management and CalDAV authorization layer.

---

## Dependency Review

### PHP Dependencies (`composer.json`)

| Package                          | Version  | Known Vulnerabilities |
|----------------------------------|----------|-----------------------|
| bamarni/composer-bin-plugin      | ^1.9.1   | None known            |
| PHP Runtime                      | 8.1–8.5  | Ensure latest patch   |

No vulnerable PHP dependencies were identified.

### JavaScript Dependencies (`package.json`)

| Package                          | Version  | Known Vulnerabilities |
|----------------------------------|----------|-----------------------|
| @fullcalendar/*                  | 6.1.20   | None known            |
| @nextcloud/* (various)           | Latest   | Maintained by Nextcloud |
| vue                              | 3.5.28   | None known            |
| webdav                           | 5.9.0    | None known            |
| @vueuse/core                     | 12.8.0   | None known            |

**Recommendation**: Run `npm audit` and `composer audit` regularly as part of the CI/CD pipeline to catch newly disclosed vulnerabilities in dependencies.

---

## Remediation Roadmap

### Immediate Priority (Before Next Release)

1. **[VULN-01] Replace MD5 token generation**
   - **File**: `lib/Service/Proposal/ProposalService.php`, lines 187 and 237
   - **Fix**: Use `ISecureRandom::generate(64, ISecureRandom::CHAR_ALPHANUMERIC)`
   - **Effort**: ~30 minutes

2. **[VULN-03] Sanitize exception messages in public endpoint**
   - **File**: `lib/Controller/ProposalController.php`, line 220
   - **Fix**: Replace raw `$e->getMessage()` with a generic error string; log exception server-side
   - **Effort**: ~15 minutes

### Short-Term (Next Release)

3. **[VULN-02] Restrict CSP frame-ancestors for embedded calendars**
   - **File**: `lib/Controller/PublicViewController.php`, line 87
   - **Fix**: Replace `*` with server base URL; provide admin-configurable allowlist
   - **Effort**: ~1 hour

4. **[VULN-03] Prevent double-voting on proposals**
   - **File**: `lib/Service/Proposal/ProposalService.php`
   - **Fix**: Check for existing response before storing; reject duplicates
   - **Effort**: ~2 hours

### Best Practice (Backlog)

5. **[VULN-04] Replace `innerHTML` with safe DOM API methods**
   - **File**: `src/fullcalendar/rendering/eventDidMount.js`, line 141
   - **Fix**: Use `document.createElement` and `insertBefore`
   - **Effort**: ~30 minutes

6. **[VULN-05] Validate token format before use in redirect**
   - **File**: `lib/Controller/PublicViewController.php`, line 69
   - **Fix**: Add regex validation for token format
   - **Effort**: ~15 minutes

7. **[Ongoing] Automate dependency vulnerability scanning**
   - Add `npm audit` and `composer audit` steps to CI pipeline
   - Integrate Renovate or Dependabot for automated dependency updates

---

*This report was generated through manual code review and static analysis of the repository at commit `8ff1817`.*
