use std::path::Path;

pub async fn read_to_end(path: impl AsRef<Path>) -> std::io::Result<Vec<u8>> {
  tokio::fs::read(path).await
}
