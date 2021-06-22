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
    if prefix.is_empty() {
        eprintln!("Error: {:?}", err);
    } else {
        let mut message = String::new();
        for line in format!("Error: {:?}", err).lines() {
            if !message.is_empty() {
                message.push('\n');
            }

            message.push_str(prefix);
            message.push_str(line);
        }

        eprintln!("{}", message);
    }
}

#[cfg(not(unix))]
pub(crate) fn print_error<T: std::fmt::Debug>(err: &T) {
    eprintln!("Error: {:?}", err);
}

#[cfg(unix)]
pub(crate) fn print_warning<T: std::fmt::Debug>(err: &T) {
    const SD_ERR: &str = "<4>";
    lazy_static! {
        static ref PREFIX: &'static str = match std::env::var("INVOCATION_ID") {
            Ok(_) => SD_ERR,
            Err(_) => "",
        };
    }
    let prefix: &str = &PREFIX;
    if prefix.is_empty() {
        eprintln!("Warning: {:?}", err);
    } else {
        let mut message = String::new();
        for line in format!("Warning: {:?}", err).lines() {
            if !message.is_empty() {
                message.push('\n');
            }

            message.push_str(prefix);
            message.push_str(line);
        }

        eprintln!("{}", message);
    }
}

#[cfg(not(unix))]
pub(crate) fn print_warning<T: std::fmt::Debug>(err: &T) {
    println!("Warning: {:?}", err);
}
