use super::guarded::GuardedString;
use super::strings;
use std::io::{self, BufRead, Write};

pub fn read_password(prompt: &str) -> GuardedString {
    eprint!("{prompt}");
    io::stderr().flush().ok();
    let pw = read_line_no_echo();
    eprintln!();
    pw
}

pub fn read_password_confirmed(prompt: &str) -> GuardedString {
    loop {
        let pw1 = read_password(prompt);
        if pw1.is_empty() {
            return pw1;
        }
        let pw2 = read_password(strings::CONFIRM_PASSWORD);
        if pw1 == pw2 {
            return pw1;
        }
        eprintln!("{}", strings::PASSWORDS_MISMATCH);
    }
}

pub fn prompt_yes_no() -> bool {
    io::stdout().flush().ok();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        let answer = input.trim().to_lowercase();
        answer == "y" || answer == "yes"
    } else {
        false
    }
}

pub fn prompt_accept(filename: &str, file_size_display: &str) -> bool {
    println!("  │  Incoming file: {} ({})", filename, file_size_display);
    print!("  │  Accept? (y/n): ");
    io::stdout().flush().ok();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        let answer = input.trim().to_lowercase();
        answer == "y" || answer == "yes"
    } else {
        false
    }
}

#[cfg(windows)]
fn read_line_no_echo() -> GuardedString {
    #[allow(non_snake_case)]
    unsafe extern "system" {
        fn GetStdHandle(nStdHandle: u32) -> *mut core::ffi::c_void;
        fn GetConsoleMode(hConsoleHandle: *mut core::ffi::c_void, lpMode: *mut u32) -> i32;
        fn SetConsoleMode(hConsoleHandle: *mut core::ffi::c_void, dwMode: u32) -> i32;
    }

    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    let (handle, original_mode) = unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode: u32 = 0;
        GetConsoleMode(h, &mut mode);
        let orig = mode;
        SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT);
        (h, orig)
    };

    let mut guarded = GuardedString::new();
    let _ = io::stdin().lock().read_line(&mut guarded.inner);
    let trimmed_len = guarded.inner.trim_end().len();
    guarded.inner.truncate(trimmed_len);

    unsafe {
        SetConsoleMode(handle, original_mode);
    }

    guarded
}

#[cfg(unix)]
fn read_line_no_echo() -> GuardedString {
    let _ = std::process::Command::new("stty").arg("-echo").status();

    let mut guarded = GuardedString::new();
    let _ = io::stdin().lock().read_line(&mut guarded.inner);
    let trimmed_len = guarded.inner.trim_end().len();
    guarded.inner.truncate(trimmed_len);

    let _ = std::process::Command::new("stty").arg("echo").status();

    guarded
}

#[cfg(not(any(windows, unix)))]
fn read_line_no_echo() -> GuardedString {
    let mut guarded = GuardedString::new();
    let _ = io::stdin().lock().read_line(&mut guarded.inner);
    let trimmed_len = guarded.inner.trim_end().len();
    guarded.inner.truncate(trimmed_len);
    guarded
}
