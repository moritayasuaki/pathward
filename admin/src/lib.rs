pub mod codec;
pub mod confined;
pub mod contract;
pub mod engine;
pub mod publication;
pub mod storage;
pub mod system;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}
