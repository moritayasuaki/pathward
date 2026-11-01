//! A small typed cache policy; never accept arbitrary response header bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CachePolicy {
    #[default]
    NoStore,
    Revalidate,
    Public {
        seconds: u64,
        immutable: bool,
    },
}
impl CachePolicy {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "no-store" => return Some(Self::NoStore),
            "no-cache" => return Some(Self::Revalidate),
            _ => (),
        }
        let value = value.strip_prefix("public,max-age=")?;
        let (digits, immutable) = value
            .strip_suffix(",immutable")
            .map_or((value, false), |s| (s, true));
        if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let seconds = digits.parse().ok()?;
        if !pathward::content::shared_cache_allowed(200, true, false, seconds)
            || (immutable && seconds == 0)
        {
            return None;
        }
        Some(Self::Public { seconds, immutable })
    }
    pub fn value(self) -> String {
        match self {
            Self::NoStore => "no-store".into(),
            Self::Revalidate => "no-cache".into(),
            Self::Public { seconds, immutable } => format!(
                "public,max-age={seconds}{}",
                if immutable { ",immutable" } else { "" }
            ),
        }
    }
}

#[derive(Clone, Copy)]
pub struct CacheRule<'a> {
    pub scope: &'a str,
    pub prefix: bool,
    pub policy: CachePolicy,
}
