use std::path::Path;

use monoio::{buf::SliceMut, fs::File};

pub async fn read_to_end(path: impl AsRef<Path>) -> std::io::Result<Vec<u8>> {
  let file = File::open(path.as_ref()).await?;
  let mut output = Vec::new();
  loop {
    let old_len = output.len();
    let new_len = old_len + 4096;
    output.resize(new_len, 0u8);
    let (res, buf) = file
      .read_at(SliceMut::new(output, old_len, new_len), old_len as u64)
      .await;
    output = buf.into_inner();
    let n = res?;
    output.resize(old_len + n, 0);
    if n == 0 {
      return Ok(output);
    }
  }
}
