use std::net::SocketAddr;
use std::str;

use crate::error::{FSpeedError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenConnectionRequest {
    pub secret: String,
    pub target: SocketAddr,
}

pub fn parse_open_connection_payload(payload: &[u8]) -> Result<OpenConnectionRequest> {
    let payload_str = str::from_utf8(payload).map_err(|_| FSpeedError::InvalidPayloadFormat)?;

    let mut secret = None;
    let mut target = None;

    for line in payload_str.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(FSpeedError::InvalidPayloadFormat);
        }

        let key = parts[0].trim();
        let value = parts[1].trim();

        match key {
            "secret" => {
                if secret.is_some() {
                    return Err(FSpeedError::DuplicateKey("secret".to_string()));
                }
                secret = Some(value.to_string());
            }
            "target" => {
                if target.is_some() {
                    return Err(FSpeedError::DuplicateKey("target".to_string()));
                }
                let addr: SocketAddr = value
                    .parse()
                    .map_err(|_| FSpeedError::InvalidTargetAddr(value.to_string()))?;
                target = Some(addr);
            }
            _ => {
                return Err(FSpeedError::UnknownKey(key.to_string()));
            }
        }
    }

    let secret = secret.ok_or(FSpeedError::MissingSecret)?;
    let target = target.ok_or(FSpeedError::MissingTarget)?;

    Ok(OpenConnectionRequest { secret, target })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_payload() {
        let payload = b"secret=test123\ntarget=127.0.0.1:22";
        let req = parse_open_connection_payload(payload).unwrap();
        assert_eq!(req.secret, "test123");
        assert_eq!(req.target, "127.0.0.1:22".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_parse_valid_payload_reverse_order() {
        let payload = b"target=192.168.1.1:8080\r\nsecret=my_secret\r\n";
        let req = parse_open_connection_payload(payload).unwrap();
        assert_eq!(req.secret, "my_secret");
        assert_eq!(
            req.target,
            "192.168.1.1:8080".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn test_parse_missing_secret() {
        let payload = b"target=127.0.0.1:22";
        let err = parse_open_connection_payload(payload).unwrap_err();
        assert!(matches!(err, FSpeedError::MissingSecret));
    }

    #[test]
    fn test_parse_missing_target() {
        let payload = b"secret=test123";
        let err = parse_open_connection_payload(payload).unwrap_err();
        assert!(matches!(err, FSpeedError::MissingTarget));
    }

    #[test]
    fn test_parse_invalid_target() {
        let payload = b"secret=test123\ntarget=not_an_ip:22";
        let err = parse_open_connection_payload(payload).unwrap_err();
        assert!(matches!(err, FSpeedError::InvalidTargetAddr(_)));
    }

    #[test]
    fn test_parse_duplicate_key() {
        let payload = b"secret=test123\ntarget=127.0.0.1:22\nsecret=other";
        let err = parse_open_connection_payload(payload).unwrap_err();
        assert!(matches!(err, FSpeedError::DuplicateKey(_)));
    }

    #[test]
    fn test_parse_unknown_key() {
        let payload = b"secret=test123\ntarget=127.0.0.1:22\nfoo=bar";
        let err = parse_open_connection_payload(payload).unwrap_err();
        assert!(matches!(err, FSpeedError::UnknownKey(_)));
    }

    #[test]
    fn test_parse_invalid_format_no_equals() {
        let payload = b"secret test123\ntarget=127.0.0.1:22";
        let err = parse_open_connection_payload(payload).unwrap_err();
        assert!(matches!(err, FSpeedError::InvalidPayloadFormat));
    }
}
