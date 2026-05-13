# Header-Based MFA Credentials for REST Clients

**Date:** 2026-05-13  
**Status:** Approved  
**Scope:** `TotpAuthenticationScheme`, `SecretQuestionAuthenticationScheme`

---

## Problem

The module supports multi-factor authentication (MFA) via a servlet filter that walks the user through a series of web pages. For REST clients, the primary factor (`BasicWebAuthenticationScheme`) already works statelessly via the standard `Authorization: Basic ...` header. However, all secondary factors (TOTP, SecretQuestion, Email) accept credentials only through form POST parameters, making it impossible for a headless REST client to complete MFA in a single stateless request.

`EmailAuthenticationScheme` is excluded from this change: it is inherently session-stateful (the server generates a code and stores it between requests), so it cannot be made stateless via headers.

---

## Goal

Enable a REST client to complete the full MFA flow — primary + secondary factor — in a **single HTTP request** by supplying all credentials as request headers, with no session state required.

---

## Architecture

No orchestration changes are needed. `TwoFactorAuthenticationScheme.getCredentials()` already processes both the primary and secondary factors within a single method call: after primary auth succeeds, it immediately attempts secondary credential extraction from the **same request**. The only missing piece is teaching the secondary scheme classes to also read their credentials from headers.

`AuthenticationSession.getRequestHeader(name)` already exists and is used by `BasicWebAuthenticationScheme` — no changes to shared infrastructure are needed.

---

## Changes

### `TotpAuthenticationScheme`

**New configuration constant:**
```java
public static final String CODE_HEADER = "codeHeader";
```

**New field:**
```java
private String codeHeader;
```

**`configure()` addition:**
```java
codeHeader = config.getProperty(CODE_HEADER, "X-Totp-Code");
```

**`getCredentials()` — updated credential extraction:**
```java
String code = session.getRequestParam(codeParam);
if (StringUtils.isBlank(code)) {
    code = session.getRequestHeader(codeHeader);
}
if (StringUtils.isNotBlank(code)) {
    // ... existing credential construction
}
```

Form param takes precedence over header. Header is a fallback only.

**Runtime property:**
```
authentication.scheme.{schemeId}.config.codeHeader=X-Totp-Code   # default
```

---

### `SecretQuestionAuthenticationScheme`

**New configuration constants:**
```java
public static final String QUESTION_HEADER = "questionHeader";
public static final String ANSWER_HEADER   = "answerHeader";
```

**New fields:**
```java
protected String questionHeader;
protected String answerHeader;
```

**`configure()` addition:**
```java
questionHeader = config.getProperty(QUESTION_HEADER, "X-Secret-Question");
answerHeader   = config.getProperty(ANSWER_HEADER,   "X-Secret-Answer");
```

**`getCredentials()` — updated credential extraction:**
```java
String question = session.getRequestParam(questionParam);
String answer   = session.getRequestParam(answerParam);
if (StringUtils.isBlank(question)) {
    question = session.getRequestHeader(questionHeader);
}
if (StringUtils.isBlank(answer)) {
    answer = session.getRequestHeader(answerHeader);
}
if (StringUtils.isNotBlank(question) && StringUtils.isNotBlank(answer)) {
    // ... existing credential construction
}
```

Form params take precedence over headers. Headers are fallback only.

**Runtime properties:**
```
authentication.scheme.{schemeId}.config.questionHeader=X-Secret-Question  # default
authentication.scheme.{schemeId}.config.answerHeader=X-Secret-Answer       # default
```

---

## Wire Format

### TOTP 2FA — single-request REST authentication
```
GET /ws/rest/v1/session HTTP/1.1
Authorization: Basic base64(username:password)
X-Totp-Code: 123456
```

### SecretQuestion 2FA — single-request REST authentication
```
GET /ws/rest/v1/session HTTP/1.1
Authorization: Basic base64(username:password)
X-Secret-Question: What is your mother's maiden name?
X-Secret-Answer: Smith
```

---

## Unchanged Behavior

- Form-based web authentication is unaffected. Params always take precedence over headers.
- `EmailAuthenticationScheme` is not changed (session-stateful by design).
- `BasicWebAuthenticationScheme`, `BasicWithLocationAuthenticationScheme`, `TwoFactorAuthenticationScheme`, `AuthenticationFilter`, and `AuthenticationSession` require no changes.
- All existing tests continue to pass without modification.

---

## Tests

### `TotpAuthenticationSchemeTest` (new file — no test file exists today)

| Test | Description |
|---|---|
| `shouldGetCredentialsFromRequestParam` | Code via form param; verifies existing behavior is preserved |
| `shouldGetCredentialsFromHeader` | Code via `X-Totp-Code` header, param absent |
| `shouldPreferParamOverHeader` | Both present; form param wins |
| `shouldReturnNullIfNeitherParamNorHeaderPresent` | Neither present; returns null |
| `shouldUseConfiguredHeaderName` | Scheme configured with custom `codeHeader`; custom header name is read |

### `SecretQuestionAuthenticationSchemeTest` (additions to existing file)

| Test | Description |
|---|---|
| `shouldGetCredentialsFromHeaders` | Both question and answer via headers, params absent |
| `shouldPreferParamsOverHeaders` | Both params and headers present; params win |
| `shouldReturnNullIfQuestionPresentButAnswerAbsentViaHeaders` | Partial headers still return null |
| `shouldReturnNullIfAnswerPresentButQuestionAbsentViaHeaders` | Other partial case still returns null |

All tests use the existing `MockAuthenticationSession` + `MockHttpServletRequest` infrastructure.

`TotpAuthenticationSchemeTest` requires a new `MockTotpAuthenticationScheme` (following the same pattern as `MockSecretQuestionAuthenticationScheme`) that overrides `verifyCode(secret, code)` with a simple deterministic check to avoid real TOTP crypto and time-dependency in tests.

---

## Files Modified

| File | Change |
|---|---|
| `omod/.../web/TotpAuthenticationScheme.java` | Add `CODE_HEADER` constant, `codeHeader` field, configure, header fallback in `getCredentials()` |
| `omod/.../web/SecretQuestionAuthenticationScheme.java` | Add `QUESTION_HEADER`, `ANSWER_HEADER` constants, fields, configure, header fallbacks in `getCredentials()` |
| `omod/.../web/mocks/MockTotpAuthenticationScheme.java` | New mock: overrides `verifyCode()` for deterministic test validation |
| `omod/.../web/TotpAuthenticationSchemeTest.java` | New test file |
| `omod/.../web/SecretQuestionAuthenticationSchemeTest.java` | Add four new test cases |
