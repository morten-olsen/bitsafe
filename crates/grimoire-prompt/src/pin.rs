/// PIN: 3 attempts, no backoff. After 3 failures, require master password.
pub const PIN_MAX_ATTEMPTS: u32 = 3;

/// Master password: exponential backoff on failed attempts.
///
/// Attempt 1: 0s (immediate)
/// Attempt 2: 1s
/// Attempt 3: 2s
/// Attempt 4: 4s
/// Attempt N: min(2^(N-2), 30) seconds
pub fn master_password_backoff_seconds(attempt: u32) -> u64 {
    if attempt <= 1 {
        return 0;
    }
    let exp = (attempt - 2).min(30);
    (1u64 << exp).min(30)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_password_backoff_schedule() {
        assert_eq!(master_password_backoff_seconds(1), 0);
        assert_eq!(master_password_backoff_seconds(2), 1);
        assert_eq!(master_password_backoff_seconds(3), 2);
        assert_eq!(master_password_backoff_seconds(4), 4);
        assert_eq!(master_password_backoff_seconds(5), 8);
        assert_eq!(master_password_backoff_seconds(6), 16);
        assert_eq!(master_password_backoff_seconds(7), 30); // capped
        assert_eq!(master_password_backoff_seconds(100), 30); // still capped
    }
}
