//! In-memory discovery for the local device list. Never persist or log peer metadata.
use crate::tray::TrayEvent;
use async_channel::Sender;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub(crate) struct Device {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub device_type: u8,
    pub addresses: Vec<SocketAddr>,
}
impl Device {
    pub fn kind(&self) -> &'static str {
        match self.device_type {
            1 => "手机",
            2 => "电脑",
            _ => "设备",
        }
    }
}
#[derive(Clone, Default)]
pub(crate) struct Devices {
    pub entries: Vec<Device>,
    pub scanning: bool,
    pub failed: bool,
    pub target: Option<SocketAddr>,
}
impl Devices {
    pub fn rows(&self, status: &str) -> Vec<(String, String)> {
        let target_state = match status {
            "已连接" => "已连接 · 认证通过",
            "连接中" => "连接中",
            "认证中" => "认证中",
            _ => "未连接 · 自动重试",
        };
        let mut matched = false;
        let mut rows = Vec::new();
        for device in &self.entries {
            let active = self.target.is_some_and(|a| device.addresses.contains(&a));
            matched |= active;
            let state = if active {
                target_state
            } else if device.device_type == 1 {
                "已发现 · 未连接"
            } else {
                "已发现 · 暂不支持连接"
            };
            let address = device
                .addresses
                .first()
                .map(ToString::to_string)
                .unwrap_or_else(|| {
                    format!("{}:{}", device.host.trim_end_matches('.'), device.port)
                });
            rows.push((
                format!("{} · {}", device.name, device.kind()),
                format!("{state} · {address}"),
            ));
        }
        // A connected device can stop advertising. Keep its actual session visible,
        // and label a config fallback separately from a discovered phone.
        if !matched && let Some(target) = self.target {
            rows.insert(
                0,
                (
                    "手机 · 当前连接目标".into(),
                    format!("{target_state} · {target}"),
                ),
            );
        }
        rows
    }
}

pub fn start(events: Sender<TrayEvent>, stop: Arc<AtomicBool>) -> mpsc::SyncSender<()> {
    let (request, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut next_scan = Instant::now();
        while !stop.load(Ordering::Relaxed) {
            if Instant::now() < next_scan {
                match receiver.recv_timeout(Duration::from_millis(250)) {
                    Ok(()) => (),
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            while receiver.try_recv().is_ok() {}
            let _ = events.send_blocking(TrayEvent::Discovering);
            let result = mi_clip::discovery::discover(Duration::from_secs(5))
                .map(|endpoints| {
                    let mut devices = Vec::new();
                    for endpoint in endpoints {
                        // Interfaces may produce duplicate records for one device.
                        if devices.iter().any(|d: &Device| {
                            d.host == endpoint.host && d.port == endpoint.kcp_port
                        }) {
                            continue;
                        }
                        let addresses = (endpoint.host.as_str(), endpoint.kcp_port)
                            .to_socket_addrs()
                            .map(|a| a.collect())
                            .unwrap_or_default();
                        let name = endpoint.model.filter(|s| !s.is_empty()).unwrap_or_else(|| {
                            endpoint.host.trim_end_matches(".local.").to_owned()
                        });
                        devices.push(Device {
                            name,
                            host: endpoint.host,
                            port: endpoint.kcp_port,
                            device_type: endpoint.device_type,
                            addresses,
                        });
                    }
                    devices.sort_by_key(|d| d.device_type != 1);
                    devices
                })
                .map_err(|_| ());
            let _ = events.send_blocking(TrayEvent::Devices(result));
            next_scan = Instant::now() + Duration::from_secs(15);
        }
    });
    request
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_matching_endpoint_is_authenticated_and_session_survives_missing_advertisement() {
        let address: SocketAddr = "192.0.2.1:1234".parse().unwrap();
        let mut devices = Devices {
            target: Some(address),
            ..Default::default()
        };
        assert!(devices.rows("已连接")[0].1.contains("认证通过"));
        devices.entries.push(Device {
            name: "测试手机".into(),
            host: "phone.local.".into(),
            port: 1234,
            device_type: 1,
            addresses: vec![address],
        });
        devices.entries.push(Device {
            name: "另一手机".into(),
            host: "other.local.".into(),
            port: 1234,
            device_type: 1,
            addresses: vec!["192.0.2.2:1234".parse().unwrap()],
        });
        let rows = devices.rows("已连接");
        assert_eq!(rows.len(), 2);
        assert!(rows[0].1.contains("认证通过"));
        assert!(rows[1].1.contains("未连接"));
        assert!(devices.rows("等待重连")[0].1.contains("自动重试"));
    }
}
