//! Small bridge used by the isolated rehearsal controller, not a deployment CLI.
#![forbid(unsafe_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 6 {
        return Err("expected CURRENT INSPECTED READY PARITY ROLLBACK ISOLATED".into());
    }
    for digest in &args[..2] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid digest".into());
        }
    }
    if !pathward::release::migration_allowed(
        args[0].as_bytes(),
        args[1].as_bytes(),
        args[2].parse()?,
        args[3].parse()?,
        args[4].parse()?,
        args[5].parse()?,
    ) {
        return Err("handoff refused".into());
    }
    Ok(())
}
