//! Use macOS's built-in notification command, off the UI and transport threads.
//! Scripts are fixed strings; no filenames, clipboard text or peer names enter them.
pub fn deliver(saved: bool) {
    std::thread::spawn(move || {
        let script = if saved {
            "display notification \"文件已接收并保存。\" with title \"Mi Clip\""
        } else {
            "display notification \"收到手机的文件分享请求，请查看菜单栏接收状态。\" with title \"Mi Clip\""
        };
        let result = std::process::Command::new("/usr/bin/osascript")
            .args(["-e", script])
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
}
