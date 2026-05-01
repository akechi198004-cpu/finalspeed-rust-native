use std::io::Error as IoError;
use std::io::ErrorKind;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const MAX_FRAME_SIZE: u32 = 2 * 1024 * 1024; // 2MB

/// Writes a length-prefixed frame to the writer.
/// The frame format is:
/// [length: 4 bytes big-endian][encoded_packet bytes]
pub async fn write_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> std::io::Result<()> {
    let len = data.len() as u32;
    if len == 0 {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "Frame length cannot be 0",
        ));
    }
    if len > MAX_FRAME_SIZE {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "Frame length exceeds MAX_FRAME_SIZE",
        ));
    }

    // Write length
    writer.write_u32(len).await?;
    // Write data
    writer.write_all(data).await?;
    writer.flush().await?;

    Ok(())
}

/// Reads a length-prefixed frame from the reader.
pub async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    // Read length
    let len = match reader.read_u32().await {
        Ok(l) => l,
        Err(e) => {
            if e.kind() == ErrorKind::UnexpectedEof {
                return Err(e); // Propagate EOF cleanly
            }
            return Err(e);
        }
    };

    if len == 0 {
        return Err(IoError::new(ErrorKind::InvalidData, "Frame length is 0"));
    }
    if len > MAX_FRAME_SIZE {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "Frame length exceeds MAX_FRAME_SIZE",
        ));
    }

    // Read data
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_write_read_normal_frame() {
        let mut buf = Vec::new();
        let data = b"hello world";

        write_frame(&mut buf, data).await.unwrap();
        assert_eq!(buf.len(), 4 + data.len());

        let mut cursor = Cursor::new(buf);
        let read_data = read_frame(&mut cursor).await.unwrap();
        assert_eq!(read_data, data);
    }

    #[tokio::test]
    async fn test_write_zero_length() {
        let mut buf = Vec::new();
        let err = write_frame(&mut buf, b"").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn test_read_zero_length() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes()); // length 0

        let mut cursor = Cursor::new(buf);
        let err = read_frame(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_write_exceeds_max_size() {
        let mut buf = Vec::new();
        // create a large slice without allocating gigabytes of memory
        // Since we check the slice length, we just mock a slice or construct one just for size check,
        // Actually, we can't easily construct a > 2MB slice without allocating.
        // We'll allocate 2MB + 1 byte for this test.
        let data = vec![0u8; (MAX_FRAME_SIZE + 1) as usize];
        let err = write_frame(&mut buf, &data).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn test_read_exceeds_max_size() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME_SIZE + 1).to_be_bytes());

        let mut cursor = Cursor::new(buf);
        let err = read_frame(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_read_truncated_length() {
        let buf = vec![0u8, 0, 1]; // Only 3 bytes
        let mut cursor = Cursor::new(buf);
        let err = read_frame(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn test_read_truncated_body() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_be_bytes()); // Length 10
        buf.extend_from_slice(b"12345"); // Only 5 bytes

        let mut cursor = Cursor::new(buf);
        let err = read_frame(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn test_multiple_frames() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"frame1").await.unwrap();
        write_frame(&mut buf, b"frame22").await.unwrap();
        write_frame(&mut buf, b"frame333").await.unwrap();

        let mut cursor = Cursor::new(buf);
        let f1 = read_frame(&mut cursor).await.unwrap();
        assert_eq!(f1, b"frame1");

        let f2 = read_frame(&mut cursor).await.unwrap();
        assert_eq!(f2, b"frame22");

        let f3 = read_frame(&mut cursor).await.unwrap();
        assert_eq!(f3, b"frame333");

        let err = read_frame(&mut cursor).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }
}
