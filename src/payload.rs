use std::str;

use crate::error::{FSpeedError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenConnectionRequest {
    pub target: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorResponse {
    pub status: String,
    pub reason: String,
}

pub fn parse_error_payload(payload: &[u8]) -> Result<ErrorResponse> {
    let payload_str = str::from_utf8(payload).map_err(|_| FSpeedError::InvalidPayloadFormat)?;

    let mut status = None;
    let mut reason = None;

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
            "status" => {
                if status.is_some() {
                    return Err(FSpeedError::DuplicateKey("status".to_string()));
                }
                status = Some(value.to_string());
            }
            "reason" => {
                if reason.is_some() {
                    return Err(FSpeedError::DuplicateKey("reason".to_string()));
                }
                reason = Some(value.to_string());
            }
            _ => {
                // Ignore unknown keys for forward compatibility on errors
            }
        }
    }

    let status = status.unwrap_or_else(|| "error".to_string());
    let reason = reason.unwrap_or_else(|| "unknown".to_string());

    Ok(ErrorResponse { status, reason })
}

pub fn build_error_payload(reason: &str) -> String {
    format!("status=error\nreason={}", reason)
}

pub fn build_ack_payload() -> String {
    "status=ok\n".to_string()
}

pub fn parse_open_connection_payload(payload: &[u8]) -> Result<OpenConnectionRequest> {
    let payload_str = str::from_utf8(payload).map_err(|_| FSpeedError::InvalidPayloadFormat)?;

    let mut target = None;
    let mut timestamp_ms = None;

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
            "target" => {
                if target.is_some() {
                    return Err(FSpeedError::DuplicateKey("target".to_string()));
                }
                target = Some(value.to_string());
            }
            "timestamp_ms" => {
                if timestamp_ms.is_some() {
                    return Err(FSpeedError::DuplicateKey("timestamp_ms".to_string()));
                }
                let ts: u64 = value.parse().map_err(|_| FSpeedError::InvalidTimestamp)?;
                timestamp_ms = Some(ts);
            }
            "secret" | "auth" | "nonce" => {
                return Err(FSpeedError::UnknownKey(key.to_string()));
            }
            _ => {
                return Err(FSpeedError::UnknownKey(key.to_string()));
            }
        }
    }

    let target = target.ok_or(FSpeedError::MissingTarget)?;
    let timestamp_ms = timestamp_ms.ok_or(FSpeedError::InvalidTimestamp)?;

    Ok(OpenConnectionRequest {
        target,
        timestamp_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_payload() {
        let payload = b"target=127.0.0.1:22\ntimestamp_ms=1234567890";
        let req = parse_open_connection_payload(payload).unwrap();
        assert_eq!(req.target, "127.0.0.1:22");
        assert_eq!(req.timestamp_ms, 1234567890);
    }

    #[test]
    fn test_parse_valid_payload_reverse_order() {
        let payload = b"timestamp_ms=1234567890\r\ntarget=example.com:8080\r\n";
        let req = parse_open_connection_payload(payload).unwrap();
        assert_eq!(req.target, "example.com:8080");
        assert_eq!(req.timestamp_ms, 1234567890);
    }

    #[test]
    fn test_parse_missing_target() {
        let payload = b"timestamp_ms=1234567890";
        let err = parse_open_connection_payload(payload).unwrap_err();
        assert!(matches!(err, FSpeedError::MissingTarget));
    }

    #[test]
    fn test_parse_missing_timestamp() {
        let payload = b"target=127.0.0.1:22";
        let err = parse_open_connection_payload(payload).unwrap_err();
        assert!(matches!(err, FSpeedError::InvalidTimestamp));
    }

    #[test]
    fn test_parse_invalid_timestamp() {
        let payload = b"target=127.0.0.1:22\ntimestamp_ms=not_a_number";
        let err = parse_open_connection_payload(payload).unwrap_err();
        assert!(matches!(err, FSpeedError::InvalidTimestamp));
    }

    #[test]
    fn test_parse_duplicate_key() {
        let payload = b"target=127.0.0.1:22\ntimestamp_ms=12345\ntarget=192.168.1.1:80";
        let err = parse_open_connection_payload(payload).unwrap_err();
        assert!(matches!(err, FSpeedError::DuplicateKey(_)));
    }

    #[test]
    fn test_parse_unknown_key() {
        let payload = b"target=127.0.0.1:22\ntimestamp_ms=1234567890\nfoo=bar";
        let err = parse_open_connection_payload(payload).unwrap_err();
        assert!(matches!(err, FSpeedError::UnknownKey(_)));
    }

    #[test]
    fn test_parse_secret_key_fails() {
        let payload = b"target=127.0.0.1:22\ntimestamp_ms=1234567890\nsecret=test123";
        let err = parse_open_connection_payload(payload).unwrap_err();
        assert!(matches!(err, FSpeedError::UnknownKey(_)));
    }

    #[test]
    fn test_parse_invalid_format_no_equals() {
        let payload = b"target 127.0.0.1:22\ntimestamp_ms=1234567890";
        let err = parse_open_connection_payload(payload).unwrap_err();
        assert!(matches!(err, FSpeedError::InvalidPayloadFormat));
    }

    #[test]
    fn test_build_and_parse_error_payload() {
        let error_str = build_error_payload("Target not allowed");
        let parsed = parse_error_payload(error_str.as_bytes()).unwrap();
        assert_eq!(parsed.status, "error");
        assert_eq!(parsed.reason, "Target not allowed");
    }

    #[test]
    fn test_parse_error_payload_ignore_unknown() {
        let payload = b"status=error\nreason=Decryption failed\nextra_info=123";
        let parsed = parse_error_payload(payload).unwrap();
        assert_eq!(parsed.status, "error");
        assert_eq!(parsed.reason, "Decryption failed");
    }

    #[test]
    fn test_build_ack_payload() {
        let ack_str = build_ack_payload();
        assert_eq!(ack_str, "status=ok\n");
    }
}
