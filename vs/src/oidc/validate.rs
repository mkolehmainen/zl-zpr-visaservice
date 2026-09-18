//! Offline validation of an OIDC `id_token` against a cached JWKS.
//!
//! Security posture (spec-OIDC.md *Security requirements*, all non-negotiable):
//! `RS256` only — `alg: none`, HS*, ES* and PS* are rejected before any
//! cryptography runs; `iss`, `aud`, `exp`, `nonce` and `kid` are always
//! checked; the Google Workspace domain is matched on the `hd` claim and never
//! on the email domain; `email` is kept only when `email_verified == true`;
//! token contents are never logged (errors carry claim names, not values).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken as jwt;

/// Everything the validator needs from policy for one provider. Built from
/// `zpr::policy_types::OidcConfig` in C4; kept separate so this module has no
/// policy dependency.
pub struct IdpParams<'a> {
    /// Expected `iss` claim, e.g. `https://accounts.google.com`.
    pub issuer: &'a str,
    /// Expected `aud` claim: our OAuth client id. From policy, never the blob.
    pub client_id: &'a str,
    /// Accepted `hd` (hosted domain) values. `["*"]` = any account.
    pub allowed_domains: &'a [String],
    /// Maximum acceptable age of the authentication event (`auth_time`).
    /// `None` = no freshness requirement.
    pub max_auth_age: Option<Duration>,
    /// Whether this provider issues refresh tokens (`allow_offline_access`).
    /// A refreshable session is renewable, so the fixed session ceiling must
    /// anchor on a provider-asserted `auth_time`: the `auth_time -> iat`
    /// fallback closes for these providers (zipline#42).
    pub allow_offline_access: bool,
    /// Leeway for clock comparisons; use `config::MAX_CLOCK_SKEW_SECS`.
    pub clock_skew: Duration,
}

impl IdpParams<'_> {
    /// The default clock-skew allowance, shared with the rest of the visa
    /// service (`config::MAX_CLOCK_SKEW_SECS`).
    pub fn default_clock_skew() -> Duration {
        Duration::from_secs(crate::config::MAX_CLOCK_SKEW_SECS)
    }
}

/// Claims we keep after validation. Everything else in the token is dropped.
#[derive(Debug)]
pub struct ValidatedToken {
    /// The provider's stable subject identifier — the only identity claim.
    pub sub: String,
    /// Present only when the token carried `email_verified == true`.
    pub email: Option<String>,
    /// Google Workspace hosted domain, when present.
    pub hd: Option<String>,
    /// The `auth_time` claim; `iat` when absent and the provider has no
    /// offline access (a renewable session requires a real `auth_time`).
    /// Anchors the fixed session ceiling of the dual-clock credential
    /// lifetime (zipline#42).
    pub auth_time: SystemTime,
    /// The `iat` claim: when this token was minted. Anchors the renewal
    /// window of the dual-clock credential lifetime (zipline#42).
    pub iat: SystemTime,
    /// The full validated claim set, for `returns_attributes` mapping (C4).
    pub raw_claims: serde_json::Map<String, serde_json::Value>,
}

/// How the token's `nonce` claim is checked. An enum rather than a boolean so
/// the connect arm cannot be constructed with checking off by accident
/// (zipline#43 constraint: the two paths must not share a validation function
/// that takes a "skip nonce" flag).
pub enum NonceExpectation<'a> {
    /// Connect path: the token must carry exactly this nonce. Missing and
    /// mismatched are the same failure; the expected value is never echoed.
    Required(&'a str),
    /// Reauth path (zipline#43): a refresh-grant `id_token` SHOULD NOT
    /// carry a `nonce` claim, and if one is present it MUST equal the
    /// *original* login nonce (OIDC Core §12.2) — absent or original,
    /// never fresh — so it can never match a fresh challenge. The caller
    /// binds the token to the live session
    /// (same `sub`, increasing `iat`, unchanged `auth_time`) instead; only
    /// the nonce equality is skipped — every other check runs unchanged.
    SessionBound,
}

/// Validation failures, partitioned by the `ErrorCode` they map to on the
/// connect path (Contract 2 error table).
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    /// -> `ErrorCode::invalidSignature`
    #[error("token signature or header invalid: {0}")]
    Signature(String),
    /// -> `ErrorCode::authError` (`hd`, `max_auth_age`)
    #[error("token rejected: {0}")]
    Rejected(String),
    /// -> `invalidSignature` (after one JWKS refresh attempt in C3)
    #[error("unknown key id {0}")]
    UnknownKid(String),
    /// -> `temporarilyUnavailable`
    #[error("no signing keys available")]
    NoKeys,
}

/// Validate `id_token` against `keys` (a JWKS) and `params`, checking the
/// `nonce` claim per `nonce` (required equality on the connect path; skipped —
/// and only it — under [NonceExpectation::SessionBound] on the reauth path).
/// Allowlist: RS256 only. Rejects `alg: none`, HS*, ES*,
/// PS*. `now` governs the `auth_time` freshness check and the future-`iat`
/// rejection; `exp` is checked by the JWT library against the real clock
/// with `params.clock_skew` leeway.
pub fn validate_id_token(
    id_token: &str,
    keys: &jwt::jwk::JwkSet,
    params: &IdpParams,
    nonce: NonceExpectation<'_>,
    now: SystemTime,
) -> Result<ValidatedToken, OidcError> {
    // Header first: the algorithm allowlist must be enforced before any key
    // material is even selected (defeats alg-confusion and `alg: none`).
    // A header naming an algorithm outside the library's enum (e.g. "none")
    // fails to parse here, which is the same rejection.
    let header =
        jwt::decode_header(id_token).map_err(|e| OidcError::Signature(format!("header: {e}")))?;
    if header.alg != jwt::Algorithm::RS256 {
        return Err(OidcError::Signature(format!(
            "algorithm {:?} not in allowlist (RS256 only)",
            header.alg
        )));
    }

    if keys.keys.is_empty() {
        return Err(OidcError::NoKeys);
    }

    // Key selection strictly by `kid`; no trial verification against every key.
    let kid = header
        .kid
        .ok_or_else(|| OidcError::Signature("missing kid".to_string()))?;
    let jwk = keys.find(&kid).ok_or(OidcError::UnknownKid(kid))?;
    let key = jwt::DecodingKey::from_jwk(jwk)
        .map_err(|e| OidcError::Signature(format!("bad JWK: {e}")))?;

    // Signature, `iss`, `aud` and `exp` are the library's job.
    let mut validation = jwt::Validation::new(jwt::Algorithm::RS256);
    validation.set_audience(&[params.client_id]);
    validation.set_issuer(&[params.issuer]);
    validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
    validation.leeway = params.clock_skew.as_secs();
    validation.validate_exp = true;

    let data =
        jwt::decode::<serde_json::Map<String, serde_json::Value>>(id_token, &key, &validation)
            .map_err(|e| OidcError::Signature(e.to_string()))?;
    let mut claims = data.claims;

    // `nonce` binds the token to this connection attempt. Missing and
    // mismatched are the same failure; the expected value is never echoed.
    // The reauth path (zipline#43) binds to the live session instead, so
    // `SessionBound` skips only this equality — nothing else.
    match nonce {
        NonceExpectation::Required(expected) => {
            match claims.get("nonce").and_then(|v| v.as_str()) {
                Some(n) if n == expected => (),
                _ => {
                    return Err(OidcError::Signature(
                        "nonce missing or mismatched".to_string(),
                    ));
                }
            }
        }
        NonceExpectation::SessionBound => (),
    }

    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OidcError::Signature("sub claim missing or not a string".to_string()))?
        .to_string();

    let hd = claims
        .get("hd")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Domain rule: `["*"]` skips the check entirely; otherwise `hd` must be
    // present AND in the list. The email domain is never consulted — it is
    // user-controlled at some providers, `hd` is asserted by Google.
    let any_domain = params.allowed_domains == ["*".to_string()];
    if !any_domain {
        match &hd {
            None => {
                return Err(OidcError::Rejected(
                    "hd claim absent (consumer account?)".to_string(),
                ));
            }
            Some(d) if !params.allowed_domains.contains(d) => {
                // Claim names only, never values: the token's `hd` is
                // attacker-influenced bytes and must not reach logs.
                return Err(OidcError::Rejected(
                    "hd claim not in allowed_domains".to_string(),
                ));
            }
            Some(_) => (),
        }
    }

    // `email` is only trustworthy when the provider says it verified it. An
    // unverified email is also stripped from `raw_claims`, which feeds the
    // `returns_attributes` mapping (C4) — otherwise the unverified value
    // would still be ingested through that path.
    let email_verified = claims
        .get("email_verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let email = if email_verified {
        claims
            .get("email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        claims.remove("email");
        None
    };

    // Token mint moment: `iat` is always required (the JWT profile mandates
    // it, and it anchors the renewal window of the dual-clock lifetime).
    let iat_secs = claims
        .get("iat")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| OidcError::Signature("iat claim missing or not a number".to_string()))?;
    // Authentication moment: `auth_time` when present. The `iat` fallback is
    // only sound for providers WITHOUT offline access: their session cannot
    // renew, so the first token's mint moment approximates the login. A
    // provider issuing refresh tokens renews `iat` on every refresh, which
    // would let the session ceiling creep forever — those must assert a real
    // `auth_time` (zipline#42).
    let auth_time_secs = match claims.get("auth_time").and_then(|v| v.as_u64()) {
        Some(secs) => secs,
        None if !params.allow_offline_access => iat_secs,
        None => {
            return Err(OidcError::Rejected(
                "auth_time required for a renewable session".to_string(),
            ));
        }
    };
    // Checked: a huge value (e.g. u64::MAX) is unrepresentable as SystemTime
    // and would panic on `UNIX_EPOCH + Duration`. Such a token is nonsense —
    // reject it like any other bad `auth_time`.
    let auth_time = UNIX_EPOCH
        .checked_add(Duration::from_secs(auth_time_secs))
        .ok_or_else(|| {
            OidcError::Rejected("auth_time/iat out of representable range".to_string())
        })?;
    let iat = UNIX_EPOCH
        .checked_add(Duration::from_secs(iat_secs))
        .ok_or_else(|| {
            OidcError::Rejected("auth_time/iat out of representable range".to_string())
        })?;

    // A future `iat` is a provider clock error (PR #18 review): the JWT
    // library does not temporally validate `iat`, and the connect path
    // derives the credential expiry from it — accepting would extend the
    // credential by the entire clock error. The allowance is the same
    // `clock_skew` leeway `exp` and `max_auth_age` get. `duration_since`
    // keeps the comparison total: Ok(ahead) only when `iat` is ahead of
    // `now`, no arithmetic that can overflow.
    if iat
        .duration_since(now)
        .is_ok_and(|ahead| ahead > params.clock_skew)
    {
        return Err(OidcError::Rejected(
            "iat is in the future beyond clock-skew leeway".to_string(),
        ));
    }

    // Freshness: the authentication event must be recent enough when policy
    // demands it (`max_auth_age_seconds`), with clock-skew leeway.
    if let Some(max_age) = params.max_auth_age {
        let age = now.duration_since(auth_time).unwrap_or(Duration::ZERO); // auth_time in the future = age 0
        if age > max_age + params.clock_skew {
            return Err(OidcError::Rejected(format!(
                "authentication is {}s old, max_auth_age is {}s",
                age.as_secs(),
                max_age.as_secs()
            )));
        }
    }

    Ok(ValidatedToken {
        sub,
        email,
        hd,
        auth_time,
        iat,
        raw_claims: claims,
    })
}

#[cfg(test)]
pub(crate) mod mint {
    //! Test-only token minter for the fixture keypair.
    //!
    //! `vs/tests/data/oidc-test-rsa.pem` is a throwaway 2048-bit RSA key
    //! generated for these tests only. `oidc-test-jwks.json` is the JWKS
    //! rendering of the SAME key (kid "k1"), generated from the PEM with
    //! openssl; parsing the JSON avoids taking the `rsa` crate as a new
    //! dev-dependency just to derive n/e at test time.

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken as jwt;

    pub const TEST_KID: &str = "k1";

    /// The fixture private key (PEM).
    pub fn test_rsa_pem() -> &'static [u8] {
        include_bytes!("../../tests/data/oidc-test-rsa.pem")
    }

    /// The fixture public key (PEM) — used as the HMAC "secret" in the
    /// algorithm-confusion vector.
    pub fn test_rsa_pub_pem() -> &'static [u8] {
        include_bytes!("../../tests/data/oidc-test-rsa.pub.pem")
    }

    /// The JWKS containing the fixture key under kid "k1".
    pub fn test_jwks() -> jwt::jwk::JwkSet {
        serde_json::from_slice(include_bytes!("../../tests/data/oidc-test-jwks.json")).unwrap()
    }

    /// Mint a signed token over `claims` with the given `kid` and algorithm.
    pub fn token(
        claims: serde_json::Value,
        kid: &str,
        alg: jwt::Algorithm,
        key: &jwt::EncodingKey,
    ) -> String {
        let mut header = jwt::Header::new(alg);
        header.kid = Some(kid.to_string());
        jwt::encode(&header, &claims, key).unwrap()
    }

    /// Hand-assemble an unsigned `alg: none` token: the library (correctly)
    /// refuses to encode one, but an attacker does not need the library.
    pub fn token_alg_none(claims: &serde_json::Value, kid: &str) -> String {
        let header = serde_json::json!({"alg": "none", "typ": "JWT", "kid": kid});
        format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap()),
        )
    }
}

#[cfg(test)]
mod tests {
    //! One test per row of the spec's *JWT validation* table (docs/OIDC.md).

    use super::mint::{TEST_KID, test_jwks, test_rsa_pem, test_rsa_pub_pem, token, token_alg_none};
    use super::*;
    use jsonwebtoken as jwt;
    use serde_json::json;

    const ISSUER: &str = "https://accounts.google.com";
    const CLIENT_ID: &str = "test-client-id.apps.googleusercontent.com";
    const NONCE: &str = "expected-nonce-value";

    /// Unix seconds for "now" as the tests see it (the real clock: the JWT
    /// library validates `exp` against real time).
    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// A fully valid baseline claim set; tests override single fields.
    fn base_claims() -> serde_json::Value {
        json!({
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "10769150350006150715113082367",
            "exp": now_secs() + 3600,
            "iat": now_secs(),
            "nonce": NONCE,
            "hd": "example.com",
            "email": "jane@example.com",
            "email_verified": true,
        })
    }

    /// Params accepting the baseline claims.
    fn params(allowed: &[String]) -> IdpParams<'_> {
        IdpParams {
            issuer: ISSUER,
            client_id: CLIENT_ID,
            allowed_domains: allowed,
            max_auth_age: None,
            allow_offline_access: false,
            clock_skew: IdpParams::default_clock_skew(),
        }
    }

    /// Sign `claims` with the fixture key under the standard kid.
    fn sign(claims: serde_json::Value) -> String {
        let key = jwt::EncodingKey::from_rsa_pem(test_rsa_pem()).unwrap();
        token(claims, TEST_KID, jwt::Algorithm::RS256, &key)
    }

    /// Run the validator with default params over `claims`.
    fn validate(claims: serde_json::Value) -> Result<ValidatedToken, OidcError> {
        let allowed = vec!["example.com".to_string()];
        validate_id_token(
            &sign(claims),
            &test_jwks(),
            &params(&allowed),
            NonceExpectation::Required(NONCE),
            SystemTime::now(),
        )
    }

    // valid -> Ok with sub, hd, email
    #[test]
    fn valid_token_accepted() {
        let tok = validate(base_claims()).unwrap();
        assert_eq!(tok.sub, "10769150350006150715113082367");
        assert_eq!(tok.hd.as_deref(), Some("example.com"));
        assert_eq!(tok.email.as_deref(), Some("jane@example.com"));
        // raw claims retained for returns_attributes mapping
        assert!(tok.raw_claims.contains_key("iss"));
    }

    // alg: none -> Signature
    #[test]
    fn alg_none_rejected() {
        let allowed = vec!["example.com".to_string()];
        let t = token_alg_none(&base_claims(), TEST_KID);
        let err = validate_id_token(
            &t,
            &test_jwks(),
            &params(&allowed),
            NonceExpectation::Required(NONCE),
            SystemTime::now(),
        )
        .unwrap_err();
        assert!(matches!(err, OidcError::Signature(_)), "{err}");
    }

    // HS256 with the RSA public key bytes as HMAC secret -> Signature
    // (classic algorithm-confusion attack)
    #[test]
    fn hs256_algorithm_confusion_rejected() {
        let allowed = vec!["example.com".to_string()];
        let key = jwt::EncodingKey::from_secret(test_rsa_pub_pem());
        let t = token(base_claims(), TEST_KID, jwt::Algorithm::HS256, &key);
        let err = validate_id_token(
            &t,
            &test_jwks(),
            &params(&allowed),
            NonceExpectation::Required(NONCE),
            SystemTime::now(),
        )
        .unwrap_err();
        assert!(matches!(err, OidcError::Signature(_)), "{err}");
    }

    // wrong aud -> Signature
    #[test]
    fn wrong_audience_rejected() {
        let mut c = base_claims();
        c["aud"] = json!("attacker-client-id.apps.googleusercontent.com");
        let err = validate(c).unwrap_err();
        assert!(matches!(err, OidcError::Signature(_)), "{err}");
    }

    // wrong iss -> Signature
    #[test]
    fn wrong_issuer_rejected() {
        let mut c = base_claims();
        c["iss"] = json!("https://evil.example.net");
        let err = validate(c).unwrap_err();
        assert!(matches!(err, OidcError::Signature(_)), "{err}");
    }

    // exp in the past -> Signature
    #[test]
    fn expired_token_rejected() {
        let mut c = base_claims();
        // Older than the leeway window so the library rejects it.
        c["exp"] = json!(now_secs() - 3600);
        let err = validate(c).unwrap_err();
        assert!(matches!(err, OidcError::Signature(_)), "{err}");
    }

    // missing nonce -> Signature
    #[test]
    fn missing_nonce_rejected() {
        let mut c = base_claims();
        c.as_object_mut().unwrap().remove("nonce");
        let err = validate(c).unwrap_err();
        assert!(matches!(err, OidcError::Signature(_)), "{err}");
    }

    // mismatched nonce -> Signature
    #[test]
    fn mismatched_nonce_rejected() {
        let mut c = base_claims();
        c["nonce"] = json!("some-other-nonce");
        let err = validate(c).unwrap_err();
        assert!(matches!(err, OidcError::Signature(_)), "{err}");
    }

    // zipline#43 (R3): under SessionBound the nonce equality — and only it —
    // is skipped: a token whose nonce matches no fresh challenge (a refresh
    // grant SHOULD NOT carry a nonce, and one it does carry is the original
    // login nonce — never a fresh one; OIDC Core §12.2) validates,
    // and a token with no nonce at all validates too. Every other check
    // stays live, e.g. a wrong audience still fails.
    #[test]
    fn session_bound_ignores_nonce_mismatch() {
        let allowed = vec!["example.com".to_string()];

        let mut c = base_claims();
        c["nonce"] = json!("the-original-login-nonce");
        let tok = validate_id_token(
            &sign(c),
            &test_jwks(),
            &params(&allowed),
            NonceExpectation::SessionBound,
            SystemTime::now(),
        )
        .expect("SessionBound must not check the nonce");
        assert_eq!(tok.sub, "10769150350006150715113082367");

        let mut c2 = base_claims();
        c2.as_object_mut().unwrap().remove("nonce");
        validate_id_token(
            &sign(c2),
            &test_jwks(),
            &params(&allowed),
            NonceExpectation::SessionBound,
            SystemTime::now(),
        )
        .expect("SessionBound must accept a missing nonce");

        // Only the nonce check is relaxed: everything else still runs.
        let mut c3 = base_claims();
        c3["aud"] = json!("attacker-client-id.apps.googleusercontent.com");
        let err = validate_id_token(
            &sign(c3),
            &test_jwks(),
            &params(&allowed),
            NonceExpectation::SessionBound,
            SystemTime::now(),
        )
        .unwrap_err();
        assert!(matches!(err, OidcError::Signature(_)), "{err}");
    }

    // hd absent (consumer account) -> Rejected
    #[test]
    fn absent_hd_rejected() {
        let mut c = base_claims();
        c.as_object_mut().unwrap().remove("hd");
        let err = validate(c).unwrap_err();
        assert!(matches!(err, OidcError::Rejected(_)), "{err}");
    }

    // hd not in allowed_domains -> Rejected, and the error names the claim
    // without echoing the token-supplied value (claim names, never values)
    #[test]
    fn wrong_hd_rejected() {
        let mut c = base_claims();
        c["hd"] = json!("not-allowed.example.org");
        let err = validate(c).unwrap_err();
        assert!(matches!(err, OidcError::Rejected(_)), "{err}");
        assert!(
            !err.to_string().contains("not-allowed.example.org"),
            "error must not echo the token's hd value: {err}"
        );
    }

    // email_verified: false -> Ok with email == None
    #[test]
    fn unverified_email_dropped() {
        let mut c = base_claims();
        c["email_verified"] = json!(false);
        let tok = validate(c).unwrap();
        assert_eq!(tok.email, None);
        // the identity itself is still valid
        assert_eq!(tok.sub, "10769150350006150715113082367");
    }

    // email_verified: false -> email removed from raw_claims too, so the
    // returns_attributes mapping (C4) can never ingest an unverified email
    #[test]
    fn unverified_email_stripped_from_raw_claims() {
        let mut c = base_claims();
        c["email_verified"] = json!(false);
        let tok = validate(c).unwrap();
        assert!(
            !tok.raw_claims.contains_key("email"),
            "unverified email must not survive in raw_claims"
        );
        // missing email_verified counts as unverified, same rule
        let mut c2 = base_claims();
        c2.as_object_mut().unwrap().remove("email_verified");
        let tok2 = validate(c2).unwrap();
        assert!(!tok2.raw_claims.contains_key("email"));
        // and a verified email is retained
        let tok3 = validate(base_claims()).unwrap();
        assert!(tok3.raw_claims.contains_key("email"));
    }

    // unknown kid -> UnknownKid
    #[test]
    fn unknown_kid_rejected() {
        let allowed = vec!["example.com".to_string()];
        let key = jwt::EncodingKey::from_rsa_pem(test_rsa_pem()).unwrap();
        let t = token(base_claims(), "rotated-away", jwt::Algorithm::RS256, &key);
        let err = validate_id_token(
            &t,
            &test_jwks(),
            &params(&allowed),
            NonceExpectation::Required(NONCE),
            SystemTime::now(),
        )
        .unwrap_err();
        assert!(
            matches!(err, OidcError::UnknownKid(ref k) if k == "rotated-away"),
            "{err}"
        );
    }

    // auth_time older than max_auth_age -> Rejected
    #[test]
    fn stale_auth_time_rejected() {
        let mut c = base_claims();
        c["auth_time"] = json!(now_secs() - 86_400); // authenticated a day ago
        let allowed = vec!["example.com".to_string()];
        let mut p = params(&allowed);
        p.max_auth_age = Some(Duration::from_secs(3600));
        let err = validate_id_token(
            &sign(c),
            &test_jwks(),
            &p,
            NonceExpectation::Required(NONCE),
            SystemTime::now(),
        )
        .unwrap_err();
        assert!(matches!(err, OidcError::Rejected(_)), "{err}");
    }

    // allowed_domains == ["*"] with no hd -> Ok
    #[test]
    fn wildcard_domain_accepts_missing_hd() {
        let mut c = base_claims();
        c.as_object_mut().unwrap().remove("hd");
        let allowed = vec!["*".to_string()];
        let tok = validate_id_token(
            &sign(c),
            &test_jwks(),
            &params(&allowed),
            NonceExpectation::Required(NONCE),
            SystemTime::now(),
        )
        .unwrap();
        assert_eq!(tok.hd, None);
    }

    // no auth_time -> auth_time == iat (providers WITHOUT offline access only)
    #[test]
    fn auth_time_falls_back_to_iat() {
        let iat = now_secs();
        let mut c = base_claims();
        c["iat"] = json!(iat);
        // base_claims has no auth_time
        let tok = validate(c).unwrap();
        assert_eq!(tok.auth_time, UNIX_EPOCH + Duration::from_secs(iat));

        // and when auth_time IS present, it wins over iat
        let mut c2 = base_claims();
        c2["auth_time"] = json!(iat - 100);
        let tok2 = validate(c2).unwrap();
        assert_eq!(tok2.auth_time, UNIX_EPOCH + Duration::from_secs(iat - 100));
    }

    // T1(c) (zipline#42): a provider with offline access issues refresh
    // tokens, so its session is renewable and the fixed session ceiling must
    // anchor on a provider-asserted `auth_time` — the iat fallback closes.
    #[test]
    fn offline_access_without_auth_time_rejected() {
        let c = base_claims(); // no auth_time
        let allowed = vec!["example.com".to_string()];
        let mut p = params(&allowed);
        p.allow_offline_access = true;
        let err = validate_id_token(
            &sign(c),
            &test_jwks(),
            &p,
            NonceExpectation::Required(NONCE),
            SystemTime::now(),
        )
        .unwrap_err();
        assert!(
            matches!(err, OidcError::Rejected(ref msg)
                if msg == "auth_time required for a renewable session"),
            "expected the exact renewable-session rejection, got: {err}"
        );
    }

    // T1(c) counterpart: with offline access, a token that DOES carry
    // auth_time still validates.
    #[test]
    fn offline_access_with_auth_time_accepted() {
        let at = now_secs() - 100;
        let mut c = base_claims();
        c["auth_time"] = json!(at);
        let allowed = vec!["example.com".to_string()];
        let mut p = params(&allowed);
        p.allow_offline_access = true;
        let tok = validate_id_token(
            &sign(c),
            &test_jwks(),
            &p,
            NonceExpectation::Required(NONCE),
            SystemTime::now(),
        )
        .unwrap();
        assert_eq!(tok.auth_time, UNIX_EPOCH + Duration::from_secs(at));
    }

    // T1 (zipline#42): `iat` lands in ValidatedToken.iat, and `auth_time`,
    // when present, still wins for `.auth_time` while `.iat` stays the iat.
    #[test]
    fn iat_is_kept_alongside_auth_time() {
        let iat = now_secs();
        let mut c = base_claims();
        c["iat"] = json!(iat);
        c["auth_time"] = json!(iat - 3600);
        let tok = validate(c).unwrap();
        assert_eq!(tok.iat, UNIX_EPOCH + Duration::from_secs(iat));
        assert_eq!(tok.auth_time, UNIX_EPOCH + Duration::from_secs(iat - 3600));

        // without auth_time (and no offline access) both anchor on iat
        let mut c2 = base_claims();
        c2["iat"] = json!(iat);
        let tok2 = validate(c2).unwrap();
        assert_eq!(tok2.iat, UNIX_EPOCH + Duration::from_secs(iat));
        assert_eq!(tok2.auth_time, tok2.iat);
    }

    // auth_time near u64::MAX -> Rejected, never a panic on
    // UNIX_EPOCH + Duration (unrepresentable SystemTime)
    #[test]
    fn huge_auth_time_rejected_not_panic() {
        let mut c = base_claims();
        c["auth_time"] = json!(u64::MAX);
        let err = validate(c).unwrap_err();
        assert!(matches!(err, OidcError::Rejected(_)), "{err}");

        // same guard on the iat fallback path
        let mut c2 = base_claims();
        c2.as_object_mut().unwrap().remove("auth_time");
        c2["iat"] = json!(u64::MAX);
        // a u64::MAX iat also fails the library's iat sanity; either way it
        // must be an error, not a panic
        let _ = validate(c2).unwrap_err();
    }

    // zipline#42 review (PR #18): `jsonwebtoken` does not temporally validate
    // `iat`, so a correctly signed token minted "in the future" (provider
    // clock skew or misconfiguration) would otherwise have its entire clock
    // error stamped into the credential lifetime (the connect path derives
    // `iat + expiration_seconds`). Beyond the shared clock-skew leeway a
    // future `iat` is rejected; within it, accepted.
    #[test]
    fn future_iat_beyond_skew_rejected() {
        let now_s = now_secs();
        // Whole-second "now" so boundary comparisons are exact.
        let now = UNIX_EPOCH + Duration::from_secs(now_s);
        let skew = IdpParams::default_clock_skew().as_secs();
        let allowed = vec!["example.com".to_string()];

        // Just beyond the leeway: rejected, claim name only (never the value).
        let mut c = base_claims();
        c["iat"] = json!(now_s + skew + 61);
        let err = validate_id_token(
            &sign(c),
            &test_jwks(),
            &params(&allowed),
            NonceExpectation::Required(NONCE),
            now,
        )
        .unwrap_err();
        assert!(matches!(err, OidcError::Rejected(_)), "{err}");

        // Within the leeway: accepted — provider clocks legitimately drift,
        // and this is the same allowance `exp` and `max_auth_age` get.
        let mut c2 = base_claims();
        c2["iat"] = json!(now_s + skew - 60);
        let tok = validate_id_token(
            &sign(c2),
            &test_jwks(),
            &params(&allowed),
            NonceExpectation::Required(NONCE),
            now,
        )
        .unwrap();
        assert_eq!(tok.iat, UNIX_EPOCH + Duration::from_secs(now_s + skew - 60));
    }

    // zipline#42 review (PR #18) guard: fixing the skewed-ceiling finding must
    // not widen acceptance — an auth_time older than max_auth_age + clock_skew
    // is still rejected, right at the boundary.
    #[test]
    fn auth_time_just_beyond_skew_leeway_still_rejected() {
        let now_s = now_secs();
        // Whole-second "now" so boundary comparisons are exact.
        let now = UNIX_EPOCH + Duration::from_secs(now_s);
        let skew = IdpParams::default_clock_skew().as_secs();
        let allowed = vec!["example.com".to_string()];
        let mut p = params(&allowed);
        p.max_auth_age = Some(Duration::from_secs(7200));

        // One past the leeway window: rejected.
        let mut c = base_claims();
        c["auth_time"] = json!(now_s - 7200 - skew - 1);
        let err = validate_id_token(
            &sign(c),
            &test_jwks(),
            &p,
            NonceExpectation::Required(NONCE),
            now,
        )
        .unwrap_err();
        assert!(matches!(err, OidcError::Rejected(_)), "{err}");

        // Exactly at the leeway boundary: still accepted (skew allowance).
        let mut c2 = base_claims();
        c2["auth_time"] = json!(now_s - 7200 - skew);
        validate_id_token(
            &sign(c2),
            &test_jwks(),
            &p,
            NonceExpectation::Required(NONCE),
            now,
        )
        .expect("auth_time exactly max_auth_age + clock_skew old is accepted");
    }

    // empty key set -> NoKeys (not a table row; completes the error taxonomy)
    #[test]
    fn empty_jwks_is_no_keys() {
        let allowed = vec!["example.com".to_string()];
        let empty = jwt::jwk::JwkSet { keys: vec![] };
        let err = validate_id_token(
            &sign(base_claims()),
            &empty,
            &params(&allowed),
            NonceExpectation::Required(NONCE),
            SystemTime::now(),
        )
        .unwrap_err();
        assert!(matches!(err, OidcError::NoKeys), "{err}");
    }
}
