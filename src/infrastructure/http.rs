//! A bounded HTTP envelope for encrypted telegraff frames behind nginx.
use super::wire::{HEADER, MAX_FRAME, TAG};
use anyhow::{Result, ensure};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
const MAX_HEADERS: usize = 8192;
fn content_length(bytes: &[u8]) -> Result<usize> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    ensure!(
        request.parse(bytes)?.is_complete(),
        "Incomplete HTTP headers"
    );
    ensure!(
        request.method == Some("POST")
            && request.path == Some("/telegraff")
            && matches!(request.version, Some(0 | 1)),
        "Expected POST /telegraff"
    );
    let mut length = None;
    for header in request.headers {
        ensure!(
            !header.name.eq_ignore_ascii_case("transfer-encoding"),
            "Chunked HTTP requests are not supported"
        );
        ensure!(
            !header.name.eq_ignore_ascii_case("expect"),
            "HTTP Expect is not supported"
        );
        if header.name.eq_ignore_ascii_case("content-length") {
            ensure!(length.is_none(), "Duplicate HTTP Content-Length");
            let text = std::str::from_utf8(header.value)?.trim();
            ensure!(
                !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()),
                "Invalid HTTP Content-Length"
            );
            length = Some(text.parse::<usize>()?);
        }
    }
    let length = length.ok_or_else(|| anyhow::anyhow!("HTTP Content-Length required"))?;
    ensure!(
        (HEADER + TAG..=MAX_FRAME).contains(&length),
        "Invalid HTTP frame size"
    );
    Ok(length)
}
pub(super) async fn read_request(stream: &mut TcpStream) -> Result<(Vec<u8>, bool)> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).await?;
    if &prefix != b"POST" {
        let length = u32::from_be_bytes(prefix) as usize;
        ensure!(
            (HEADER + TAG..=MAX_FRAME).contains(&length),
            "Invalid frame size"
        );
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await?;
        return Ok((bytes, false));
    }
    let mut headers = prefix.to_vec();
    while !headers.ends_with(b"\r\n\r\n") {
        ensure!(headers.len() < MAX_HEADERS, "HTTP headers too large");
        headers.push(stream.read_u8().await?);
    }
    let length = content_length(&headers)?;
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok((bytes, true))
}
pub(super) async fn write_response(stream: &mut TcpStream, bytes: &[u8], http: bool) -> Result<()> {
    if !http {
        return super::receiver::write_frame(stream, bytes).await;
    }
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        bytes.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(bytes).await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ambiguous_or_unbounded_requests() {
        let size = HEADER + TAG;
        assert_eq!(
            content_length(
                format!("POST /telegraff HTTP/1.1\r\nContent-Length: {size}\r\n\r\n").as_bytes()
            )
            .unwrap(),
            size
        );
        for headers in [
            format!("Content-Length: {size}\r\nContent-Length: {size}"),
            format!("Content-Length: {size}\r\nTransfer-Encoding: chunked"),
            "Content-Length: 99999999".into(),
            "Content-Length: +100".into(),
            "".into(),
        ] {
            assert!(
                content_length(format!("POST /telegraff HTTP/1.1\r\n{headers}\r\n\r\n").as_bytes())
                    .is_err()
            );
        }
        assert!(
            content_length(
                format!("POST /other HTTP/1.1\r\nContent-Length: {size}\r\n\r\n").as_bytes()
            )
            .is_err()
        );
    }
}
