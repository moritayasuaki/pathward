use pathward_admin::{
    Result, codec,
    engine::{Engine, Environment},
    require, storage,
    system::Real,
};
use std::path::{Path, PathBuf};

fn main() {
    if let Err(e) = run() {
        eprintln!("PathWard administrator: {e}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    require(
        a.len() >= 3 && a[0] == "--root",
        "usage: pathward-admin --root /absolute/private/store prepare INPUT SHA256 | apply REQUEST | boot | recover | fallback | gate UNIT | status",
    )?;
    require(
        cfg!(target_os = "linux") && rustix::process::geteuid().is_root(),
        "Linux administrator required",
    )?;
    let root = PathBuf::from(&a[1]);
    storage::trusted(&root)?;
    let mut e = Engine {
        root,
        env: Environment::production(),
        sys: Real,
    };
    if a[2] == "gate" {
        require(a.len() == 4, "gate arguments")?;
        require(e.gate(&a[3])?, "start denied")?;
        return Ok(());
    }
    if a[2] == "status" {
        require(a.len() == 3, "status arguments")?;
        println!("{}", serde_json::to_string(&e.status()?)?);
        return Ok(());
    }
    if a[2] == "boot" && e.boot_fast_path().unwrap_or(false) {
        return Ok(());
    }
    let _lock = match e.lock() {
        Ok(lock) => lock,
        Err(error)
            if a[2] == "fallback"
                && matches!(
                    error.downcast_ref::<std::fs::TryLockError>(),
                    Some(std::fs::TryLockError::WouldBlock)
                ) =>
        {
            // OnFailure may race a live administrator. Retry only contention;
            // invalid records/held recovery must still stop without a loop.
            eprintln!("PathWard fallback waits for the active administrator");
            std::process::exit(75);
        }
        Err(error) => return Err(error),
    };
    match a[2].as_str() {
        "prepare" => {
            require(a.len() == 5, "prepare INPUT SHA256")?;
            let bytes = storage::bytes(Path::new(&a[3]), true)?;
            require(codec::hash(&bytes) == a[4], "reviewed input hash mismatch")?;
            let id = e.prepare(
                &codec::parse(&bytes)?,
                &std::env::current_exe()?,
                &mut |_| Ok(()),
            )?;
            println!("PREPARED_NATIVE_REQUEST {id}");
        }
        "apply" => {
            require(a.len() == 4, "apply REQUEST")?;
            e.apply(&a[3], &mut |_| Ok(()))?;
            println!(
                "APPLIED_NATIVE_CONTRACT {}",
                serde_json::to_string(&e.status()?)?
            );
        }
        "boot" | "recover" | "fallback" => {
            require(a.len() == 3, "recovery arguments")?;
            e.recover(a[2] == "boot", a[2] == "fallback", &mut |_| Ok(()))?;
        }
        "watchdog" => {
            require(a.len() == 3, "watchdog arguments")?;
            e.watchdog(&mut |_| Ok(()))?;
        }
        _ => return Err("unknown operation".into()),
    }
    Ok(())
}
