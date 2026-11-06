//! Read-only protocol for the administrator adapter; never performs deployment.
use std::ffi::OsString;

pub fn evaluate(args: &[OsString]) -> Result<bool, &'static str> {
    const ERROR: &str = "invalid cutover-policy request";
    let words: Vec<_> = args
        .iter()
        .map(|s| s.to_str().ok_or(ERROR))
        .collect::<Result<_, _>>()?;
    let boolean = |s: &str| match s {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(ERROR),
    };
    let number = |s: &str| {
        if s.is_empty()
            || s.len() > 20
            || !s.bytes().all(|b| b.is_ascii_digit())
            || (s.len() > 1 && s.starts_with('0'))
        {
            return Err(ERROR);
        }
        s.parse::<u64>().map_err(|_| ERROR)
    };
    use pathward::cutover as policy;
    match words.as_slice() {
        ["window", boot, started, now] => Ok(policy::window_allowed(
            boolean(boot)?,
            number(started)?,
            number(now)?,
        )),
        ["stop-old", pending, armed, preflight, unchanged] => Ok(policy::stop_old_allowed(
            boolean(pending)?,
            boolean(armed)?,
            boolean(preflight)?,
            boolean(unchanged)?,
        )),
        ["commit", awaiting, verified, window, armed] => Ok(policy::commit_allowed(
            boolean(awaiting)?,
            boolean(verified)?,
            boolean(window)?,
            boolean(armed)?,
        )),
        ["disarm", committed, persisted, current] => Ok(policy::disarm_allowed(
            boolean(committed)?,
            number(persisted)?,
            number(current)?,
        )),
        ["watchdog", committed, prepared, restored] => Ok(policy::watchdog_required(
            boolean(committed)?,
            boolean(prepared)?,
            boolean(restored)?,
        )),
        _ => Err(ERROR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn query(words: &[&str]) -> Result<bool, &'static str> {
        evaluate(&words.iter().map(OsString::from).collect::<Vec<_>>())
    }
    #[test]
    fn protocol_denies_missing_checks_and_rejects_ambiguous_inputs() {
        assert_eq!(query(&["commit", "1", "1", "1", "1"]), Ok(true));
        for i in 1..5 {
            let mut args = ["commit", "1", "1", "1", "1"];
            args[i] = "0";
            assert_eq!(query(&args), Ok(false));
        }
        assert_eq!(query(&["window", "1", "1", "900000000001"]), Ok(false));
        assert_eq!(query(&["disarm", "1", "7", "8"]), Ok(false));
        assert_eq!(query(&["watchdog", "1", "0", "0"]), Ok(false));
        for invalid in ["-1", "+1", "01", "1\n", "18446744073709551616", ""] {
            assert!(query(&["window", "1", "0", invalid]).is_err());
        }
        assert!(query(&["commit", "true", "1", "1", "1"]).is_err());
        assert!(query(&["commit", "1", "1", "1", "1", "extra"]).is_err());
        assert!(query(&["unknown"]).is_err());
    }
}
