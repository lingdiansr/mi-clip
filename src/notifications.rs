//! Desktop notifications, off the UI and transport threads.
//!
//! Both platforms use fixed strings: no filenames, clipboard text or peer names.
pub fn deliver(saved: bool) {
    let body = if saved {
        "文件已接收并保存。"
    } else {
        "收到手机的文件分享请求，请查看接收状态。"
    };
    #[cfg(target_os = "macos")]
    std::thread::spawn(move || {
        let script = format!(
            "display notification \"{body}\" with title \"Mi Clip\""
        );
        let result = std::process::Command::new("/usr/bin/osascript")
            .args(["-e", &script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if !result.is_ok_and(|status| status.success())
            && std::env::var_os("MICLIP_DIAGNOSTICS").is_some()
        {
            eprintln!("System notification unavailable; status feedback remains active.");
        }
    });
    // A missing notification service only affects the banner, never the transfer.
    #[cfg(target_os = "linux")]
    std::thread::spawn(move || {
        let result = notify_rust::Notification::new()
            .appname("Mi Clip")
            .summary("Mi Clip")
            .body(body)
            .show();
        if result.is_err() && std::env::var_os("MICLIP_DIAGNOSTICS").is_some() {
            eprintln!("System notification unavailable; status feedback remains active.");
        }
    });
}
