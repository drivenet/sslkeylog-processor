#[cfg(unix)]
pub(crate) fn print_error<T: std::fmt::Debug>(err: &T) {
    const SD_ERR: &str = "<3>";
    lazy_static! {
        static ref PREFIX: &'static str = match std::env::var("INVOCATION_ID") {
            Ok(_) => SD_ERR,
            Err(_) => "",
        };
    }
    let prefix: &str = &PREFIX;
    eprintln!("{}Error: {:?}", prefix, err);
}

#[cfg(not(unix))]
pub(crate) fn print_error<T: std::fmt::Debug>(err: &T) {
    eprintln!("Error: {:?}", err);
}
