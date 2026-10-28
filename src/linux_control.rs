//! Session D-Bus single-instance entry point and share requests.
//!
//! The first process owns `com.cyeam.miclip` and serves a tiny control
//! interface; later launches forward one bounded request and exit. No Unix
//! socket protocol, no X11 property, no PID file.
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use zbus::blocking::Connection;

pub const BUS_NAME: &str = "com.cyeam.miclip";
const OBJECT_PATH: &str = "/com/cyeam/miclip";
pub const MAX_SHARE_URIS: usize = 128;
pub const MAX_SHARE_BYTES: usize = 64 * 1024;

/// A request forwarded from another launch of the same user.
#[derive(Debug)]
pub enum Request {
    Show,
    Share(Vec<PathBuf>),
}

struct ControlInterface {
    events: async_channel::Sender<Request>,
}

#[zbus::interface(name = "com.cyeam.miclip.Control")]
impl ControlInterface {
    /// Reflects the running window; idempotent.
    fn show(&self) -> zbus::fdo::Result<()> {
        self.events.try_send(Request::Show).map_err(busy)
    }

    /// Accepts local file URIs for the share picker.
    fn share(&self, uris: Vec<String>) -> zbus::fdo::Result<()> {
        let paths = validate_uris(&uris)
            .map_err(|error| zbus::fdo::Error::InvalidArgs(format!("{error:#}")))?;
        self.events.try_send(Request::Share(paths)).map_err(busy)
    }
}

fn busy<T>(error: async_channel::TrySendError<T>) -> zbus::fdo::Error {
    match error {
        async_channel::TrySendError::Full(_) => zbus::fdo::Error::Failed("Busy".into()),
        async_channel::TrySendError::Closed(_) => zbus::fdo::Error::Failed("Not running".into()),
    }
}

/// Owns the session bus name. Dropping it releases the name and the connection.
pub struct Control {
    connection: Connection,
    requests: Option<async_channel::Receiver<Request>>,
}

impl Control {
    pub fn take_requests(&mut self) -> Option<async_channel::Receiver<Request>> {
        self.requests.take()
    }

    /// Explicitly gives up the name before a replacement process starts.
    pub fn release(self) {
        drop(self);
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        let _ = self.connection.release_name(BUS_NAME);
    }
}

/// Attempts to become the single running instance.
///
/// Returns `Some(control)` for the first process, or forwards the request to the
/// running instance and returns `None`. An explicit configuration switch is
/// refused instead of silently replacing the running session.
pub fn session(
    show: bool,
    share: &[PathBuf],
    explicit_config: bool,
) -> anyhow::Result<Option<Control>> {
    let uris = encode_paths(share)?;
    let (sender, receiver) = async_channel::bounded(32);
    let connection =
        Connection::session().map_err(|error| anyhow::anyhow!("无法连接会话 D-Bus：{error}"))?;
    let flags = zbus::fdo::RequestNameFlags::DoNotQueue.into();
    match connection.request_name_with_flags(BUS_NAME, flags) {
        Ok(
            zbus::fdo::RequestNameReply::PrimaryOwner | zbus::fdo::RequestNameReply::AlreadyOwner,
        ) => {
            // Register before the window exists; callers retry until it appears.
            connection
                .object_server()
                .at(
                    OBJECT_PATH,
                    ControlInterface {
                        events: sender.clone(),
                    },
                )
                .map_err(|error| anyhow::anyhow!("无法注册控制接口：{error}"))?;
            Ok(Some(Control {
                connection,
                requests: Some(receiver),
            }))
        }
        Err(zbus::Error::NameTaken) => {
            if explicit_config {
                anyhow::bail!("已有实例运行，请先退出后切换配置");
            }
            forward(show, &uris)?;
            Ok(None)
        }
        Ok(reply) => anyhow::bail!("意外的 D-Bus 名称应答：{reply:?}"),
        Err(error) => Err(anyhow::anyhow!("无法注册单实例名称：{error}")),
    }
}

/// Sends the request, retrying while the owner has not registered its interface.
fn forward(show: bool, uris: &[String]) -> anyhow::Result<()> {
    let connection =
        Connection::session().map_err(|error| anyhow::anyhow!("无法连接会话 D-Bus：{error}"))?;
    let proxy = ControlProxyBlocking::builder(&connection)
        .destination(BUS_NAME)?
        .path(OBJECT_PATH)?
        .build()?;
    if !uris.is_empty() {
        return call(|| proxy.share(uris));
    }
    if show {
        return call(|| proxy.show());
    }
    Ok(())
}

fn call(mut request: impl FnMut() -> zbus::Result<()>) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match request() {
            Ok(()) => return Ok(()),
            Err(zbus::Error::MethodError(name, detail, _)) => {
                let name = name.as_str();
                let retry = Instant::now() < deadline
                    && matches!(
                        name,
                        "org.freedesktop.DBus.Error.ServiceUnknown"
                            | "org.freedesktop.DBus.Error.UnknownObject"
                            | "org.freedesktop.DBus.Error.UnknownInterface"
                            | "org.freedesktop.DBus.Error.UnknownMethod"
                            | "org.freedesktop.DBus.Error.NoReply"
                    );
                if !retry {
                    let reason = detail.unwrap_or_default();
                    anyhow::bail!("控制请求失败：{}", format!("{name} {reason}").trim());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(anyhow::anyhow!("控制请求失败：{error}")),
        }
    }
}

/// Converts caller paths to absolute local file URIs without resolving symlinks.
pub fn encode_paths(paths: &[PathBuf]) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(!paths.is_empty(), "没有可分享的文件");
    anyhow::ensure!(paths.len() <= MAX_SHARE_URIS, "分享文件数量超出限制");
    let mut uris = Vec::new();
    let mut total = 0;
    for path in paths {
        let absolute = std::path::absolute(path)?;
        let url = url::Url::from_file_path(&absolute)
            .map_err(|_| anyhow::anyhow!("无法转换为本地文件 URI：{}", absolute.display()))?;
        total += url.as_str().len();
        anyhow::ensure!(total <= MAX_SHARE_BYTES, "分享请求超出大小限制");
        uris.push(url.into());
    }
    Ok(uris)
}

/// Validates forwarded URIs: local files only, bounded in count and size.
pub fn validate_uris(uris: &[String]) -> anyhow::Result<Vec<PathBuf>> {
    anyhow::ensure!(!uris.is_empty(), "没有可分享的文件");
    anyhow::ensure!(uris.len() <= MAX_SHARE_URIS, "分享文件数量超出限制");
    anyhow::ensure!(
        uris.iter().map(String::len).sum::<usize>() <= MAX_SHARE_BYTES,
        "分享请求超出大小限制"
    );
    let mut paths = Vec::new();
    for uri in uris {
        let url = url::Url::parse(uri).map_err(|_| anyhow::anyhow!("分享请求包含无效 URI"))?;
        anyhow::ensure!(url.scheme() == "file", "只支持本地文件");
        anyhow::ensure!(
            url.host_str()
                .is_none_or(|host| host.is_empty() || host == "localhost"),
            "不支持远程主机"
        );
        let path = url
            .to_file_path()
            .map_err(|_| anyhow::anyhow!("分享 URI 没有可用路径"))?;
        anyhow::ensure!(
            !path.as_os_str().as_encoded_bytes().contains(&0),
            "分享路径包含 NUL 字节"
        );
        paths.push(path);
    }
    Ok(paths)
}

#[zbus::proxy(
    interface = "com.cyeam.miclip.Control",
    default_service = "com.cyeam.miclip",
    default_path = "/com/cyeam/miclip"
)]
trait Control {
    fn show(&self) -> zbus::Result<()>;
    fn share(&self, uris: &[String]) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_local_file_uris_are_accepted() {
        assert!(validate_uris(&[]).is_err());
        assert!(validate_uris(&["https://example.invalid/a".into()]).is_err());
        assert!(validate_uris(&["file://remote.invalid/tmp/a".into()]).is_err());
        assert!(validate_uris(&["file:///tmp/a%00b".into()]).is_err());
        assert_eq!(
            validate_uris(&["file:///tmp/a%20b".into()]).unwrap(),
            vec![PathBuf::from("/tmp/a b")]
        );
        let too_many: Vec<String> = (0..=MAX_SHARE_URIS)
            .map(|index| format!("file:///tmp/{index}"))
            .collect();
        assert!(validate_uris(&too_many).is_err());
        let oversized = format!("file:///tmp/{}", "x".repeat(MAX_SHARE_BYTES));
        assert!(validate_uris(&[oversized]).is_err());
    }

    #[test]
    fn paths_become_absolute_uris_without_canonicalizing() {
        let relative = PathBuf::from("relative name %.txt");
        let uris = encode_paths(&[relative.clone()]).unwrap();
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("file:///"));
        let absolute = std::path::absolute(&relative).unwrap();
        assert_eq!(validate_uris(&uris).unwrap(), vec![absolute]);
        assert!(encode_paths(&[]).is_err());
    }
}
