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
    /// The `auth_time` claim, else `iat`.
    pub auth_time: SystemTime,
    /// The full validated claim set, for `returns_attributes` mapping (C4).
    pub raw_claims: serde_json::Map<String, serde_json::Value>,
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

/// Validate `id_token` against `keys` (a JWKS) and `params`, requiring
/// `expected_nonce`. Allowlist: RS256 only. Rejects `alg: none`, HS*, ES*,
/// PS*. `now` governs the `auth_time` freshness check; `exp`/`iat` are
/// checked by the JWT library against the real clock with
/// `params.clock_skew` leeway.
pub fn validate_id_token(
    id_token: &str,
    keys: &jwt::jwk::JwkSet,
    params: &IdpParams,
    expected_nonce: &str,
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
    match claims.get("nonce").and_then(|v| v.as_str()) {
        Some(n) if n == expected_nonce => (),
        _ => {
            return Err(OidcError::Signature(
                "nonce missing or mismatched".to_string(),
            ));
        }
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

    // Authentication moment: `auth_time` when present, else `iat`.
    let auth_time_secs = claims
        .get("auth_time")
        .and_then(|v| v.as_u64())
        .or_else(|| claims.get("iat").and_then(|v| v.as_u64()))
        .ok_or_else(|| OidcError::Signature("neither auth_time nor iat present".to_string()))?;
    // Checked: a huge value (e.g. u64::MAX) is unrepresentable as SystemTime
    // and would panic on `UNIX_EPOCH + Duration`. Such a token is nonsense —
    // reject it like any other bad `auth_time`.
    let auth_time = UNIX_EPOCH
        .checked_add(Duration::from_secs(auth_time_secs))
        .ok_or_else(|| {
            OidcError::Rejected("auth_time/iat out of representable range".to_string())
        })?;

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
        raw_claims: claims,
    })
}

#[cfg(test)]
mod mint {
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
            NONCE,
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
            NONCE,
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
            NONCE,
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
            NONCE,
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
        let err =
            validate_id_token(&sign(c), &test_jwks(), &p, NONCE, SystemTime::now()).unwrap_err();
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
            NONCE,
            SystemTime::now(),
        )
        .unwrap();
        assert_eq!(tok.hd, None);
    }

    // no auth_time -> auth_time == iat
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

    // empty key set -> NoKeys (not a table row; completes the error taxonomy)
    #[test]
    fn empty_jwks_is_no_keys() {
        let allowed = vec!["example.com".to_string()];
        let empty = jwt::jwk::JwkSet { keys: vec![] };
        let err = validate_id_token(
            &sign(base_claims()),
            &empty,
            &params(&allowed),
            NONCE,
            SystemTime::now(),
        )
        .unwrap_err();
        assert!(matches!(err, OidcError::NoKeys), "{err}");
    }
}
