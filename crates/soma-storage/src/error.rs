use thiserror::Error;

/// All errors that `soma-storage` can produce.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The requested row does not exist (or is outside the caller's tenant).
    #[error("not found")]
    NotFound,

    /// A uniqueness or check constraint was violated.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Input value failed type or range validation.
    #[error("validation: {0}")]
    Validation(String),

    /// EAV property key is not in the `02_dim_attr_defs` whitelist.
    #[error("attribute key not in whitelist")]
    WhitelistViolation,

    /// Attempted cross-tenant access.
    #[error("cross-tenant access denied")]
    CrossTenant,

    /// Crypto layer error.
    #[error("crypto error: {0}")]
    Crypto(#[from] soma_crypto::Error),

    /// Raw database error (un-mapped).
    #[error("database error")]
    Db(#[from] sqlx::Error),

    /// Migration error.
    #[error("migration error: {0}")]
    Migrate(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Map an `sqlx::Error` to a domain `Error`, translating SQLSTATE codes.
pub(crate) fn map_sqlx(e: sqlx::Error) -> Error {
    if let sqlx::Error::Database(ref dbe) = e {
        match dbe.code().as_deref() {
            Some("23505") => {
                // unique_violation
                return Error::Conflict(dbe.message().to_owned());
            }
            Some("23503") => {
                // foreign_key_violation — whitelist check?
                let constraint = dbe.constraint().unwrap_or("");
                if constraint.contains("whitelist")
                    || dbe.message().to_ascii_lowercase().contains("whitelist")
                {
                    return Error::WhitelistViolation;
                }
                return Error::Db(e);
            }
            Some("23514") => {
                // check_violation — return a generic validation error; never leak
                // the internal constraint name to the client.
                return Error::Validation("invalid input: check constraint violated".to_owned());
            }
            _ => {}
        }
    }
    Error::Db(e)
}
