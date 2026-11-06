//! Small read-only recovery decision executable; no server dependencies.
use pathward::recovery::{self, Selection};
use std::{env, process::ExitCode};

fn boolean(s: &str) -> Result<bool, ()> {
    match s {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(()),
    }
}
fn selection(s: &str) -> Result<Selection, ()> {
    match s {
        "HOLD" => Ok(Selection::Hold),
        "OLD" => Ok(Selection::Old),
        "NEW" => Ok(Selection::New),
        _ => Err(()),
    }
}
fn epoch(s: &str) -> Result<u64, ()> {
    if s.is_empty()
        || s.len() > 20
        || !s.bytes().all(|b| b.is_ascii_digit())
        || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(());
    }
    s.parse().map_err(|_| ())
}
fn evaluate(words: &[String]) -> Result<String, ()> {
    let text: Vec<_> = words.iter().map(String::as_str).collect();
    let allowed = match text.as_slice() {
        [
            "upgrade",
            base,
            next,
            at_base,
            at_target,
            ready,
            compatible,
            stable,
        ] => {
            return Ok(format!(
                "{:?}",
                recovery::upgrade_action(
                    epoch(base)?,
                    epoch(next)?,
                    boolean(at_base)?,
                    boolean(at_target)?,
                    boolean(ready)?,
                    boolean(compatible)?,
                    boolean(stable)?
                )
            )
            .to_ascii_uppercase());
        }
        ["fallback", selected, boot, plan, failed, old] => recovery::fallback_allowed(
            boolean(selected)?,
            boolean(boot)?,
            boolean(plan)?,
            boolean(failed)?,
            boolean(old)?,
        ),
        ["select", p, r, c, t, n, o] => {
            return Ok(format!(
                "{:?}",
                recovery::select(
                    boolean(p)?,
                    boolean(r)?,
                    boolean(c)?,
                    boolean(t)?,
                    boolean(n)?,
                    boolean(o)?
                )
            )
            .to_ascii_uppercase());
        }
        ["start", chosen, requested, boot, plan] => recovery::start_allowed(
            selection(chosen)?,
            selection(requested)?,
            boolean(boot)?,
            boolean(plan)?,
        ),
        ["stop-old", plan, guard, old] => {
            recovery::stop_old_allowed(boolean(plan)?, boolean(guard)?, boolean(old)?)
        }
        ["trial", boot, plan, armed, elapsed] => {
            if elapsed.is_empty()
                || elapsed.len() > 20
                || !elapsed.bytes().all(|b| b.is_ascii_digit())
                || (elapsed.len() > 1 && elapsed.starts_with('0'))
            {
                return Err(());
            }
            recovery::trial_allowed(
                boolean(boot)?,
                boolean(plan)?,
                boolean(armed)?,
                elapsed.parse().map_err(|_| ())?,
            )
        }
        _ => return Err(()),
    };
    Ok(if allowed { "ALLOW" } else { "DENY" }.into())
}
fn main() -> ExitCode {
    match evaluate(&env::args().skip(1).collect::<Vec<_>>()) {
        Ok(answer) => {
            println!("{answer}");
            ExitCode::SUCCESS
        }
        Err(()) => {
            eprintln!("invalid recovery policy request");
            ExitCode::FAILURE
        }
    }
}
