use tokio::io::AsyncWriteExt;

#[macro_export]
macro_rules! aeprintln {
  ($($arg:tt)*) => {
    $crate::async_print::print_stderr(format!("{}\n", format_args!($($arg)*))).await
  };
}

pub async fn print_stderr(msg: String) {
  let _ = tokio::io::stderr().write_all(msg.as_bytes()).await;
}
