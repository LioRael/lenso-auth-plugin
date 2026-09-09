use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const ATTEMPT_TTL: i64 = 300;
const MAX_ATTEMPTS: usize = 128;

#[derive(Default)]
pub(crate) struct Attempts {
    entries: BTreeMap<String, Attempt>,
}
struct Attempt {
    poll_hash: [u8; 32],
    expires: i64,
    consent: Option<([u8; 32], [u8; 32])>,
    state: State,
}
enum State {
    Pending,
    Issuing,
    Ready(Zeroizing<String>),
    Failed,
}
impl std::fmt::Debug for Attempts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attempts")
            .field("count", &self.entries.len())
            .finish()
    }
}
#[derive(Debug, PartialEq)]
pub(crate) enum Failure {
    Unknown,
    Capacity,
    Rejected,
}
pub(crate) enum Poll {
    Pending,
    Ready(String),
    Failed,
}
pub(crate) fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}
impl Attempts {
    fn prune(&mut self, now: i64) {
        self.entries.retain(|_, attempt| attempt.expires > now);
    }
    pub(crate) fn insert(&mut self, id: String, secret: &str, now: i64) -> Result<(), Failure> {
        self.prune(now);
        if self.entries.len() >= MAX_ATTEMPTS {
            return Err(Failure::Capacity);
        }
        self.entries.insert(
            id,
            Attempt {
                poll_hash: digest(secret),
                expires: now + ATTEMPT_TTL,
                consent: None,
                state: State::Pending,
            },
        );
        Ok(())
    }
    pub(crate) fn consent(
        &mut self,
        id: &str,
        nonce: &str,
        credential: &str,
        now: i64,
    ) -> Result<(), Failure> {
        self.prune(now);
        let attempt = self.entries.get_mut(id).ok_or(Failure::Unknown)?;
        if !matches!(attempt.state, State::Pending) {
            return Err(Failure::Rejected);
        }
        attempt.consent = Some((digest(nonce), digest(credential)));
        Ok(())
    }
    pub(crate) fn claim(
        &mut self,
        id: &str,
        nonce: &str,
        credential: &str,
        now: i64,
    ) -> Result<(), Failure> {
        self.prune(now);
        let attempt = self.entries.get_mut(id).ok_or(Failure::Unknown)?;
        if !matches!(attempt.state, State::Pending)
            || attempt.consent != Some((digest(nonce), digest(credential)))
        {
            return Err(Failure::Rejected);
        }
        attempt.consent = None;
        attempt.state = State::Issuing;
        Ok(())
    }
    pub(crate) fn finish(&mut self, id: &str, result: Option<String>, now: i64) {
        self.prune(now);
        if let Some(attempt) = self.entries.get_mut(id)
            && matches!(attempt.state, State::Issuing)
        {
            attempt.state =
                result.map_or(State::Failed, |value| State::Ready(Zeroizing::new(value)));
        }
    }
    pub(crate) fn poll(&mut self, id: &str, secret: &str, now: i64) -> Result<Poll, Failure> {
        self.prune(now);
        let attempt = self.entries.get(id).ok_or(Failure::Unknown)?;
        if attempt.poll_hash != digest(secret) {
            return Err(Failure::Unknown);
        }
        Ok(match &attempt.state {
            State::Pending | State::Issuing => Poll::Pending,
            State::Failed => Poll::Failed,
            State::Ready(value) => Poll::Ready(value.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn consent_is_bound_to_session_and_claimed_once() {
        let mut attempts = Attempts::default();
        attempts.insert("a".into(), "poll", 0).unwrap();
        attempts.consent("a", "nonce", "parent", 1).unwrap();
        assert_eq!(
            attempts.claim("a", "nonce", "other", 2),
            Err(Failure::Rejected)
        );
        attempts.claim("a", "nonce", "parent", 2).unwrap();
        assert_eq!(
            attempts.claim("a", "nonce", "parent", 2),
            Err(Failure::Rejected)
        );
        attempts.finish("a", Some("credential".into()), 3);
        assert!(matches!(
            attempts.poll("a", "wrong", 4),
            Err(Failure::Unknown)
        ));
        assert!(matches!(attempts.poll("a", "poll", 4), Ok(Poll::Ready(_))));
        assert!(matches!(
            attempts.poll("a", "poll", 300),
            Err(Failure::Unknown)
        ));
        assert!(!format!("{attempts:?}").contains("credential"));
    }
}
