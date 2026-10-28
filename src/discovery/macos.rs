//! macOS DNS-SD discovery; no vendor runtime or subprocess dependency.
use super::Endpoint;
use crate::advertisement::Advertisement;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    collections::HashSet,
    ffi::{CStr, c_char, c_void},
    net::ToSocketAddrs,
    time::{Duration, Instant},
};
type Service = *mut c_void;
type BrowseCallback = unsafe extern "C" fn(
    Service,
    u32,
    u32,
    i32,
    *const c_char,
    *const c_char,
    *const c_char,
    *mut c_void,
);
type ResolveCallback = unsafe extern "C" fn(
    Service,
    u32,
    u32,
    i32,
    *const c_char,
    *const c_char,
    u16,
    u16,
    *const u8,
    *mut c_void,
);
#[link(name = "System")]
unsafe extern "C" {
    fn DNSServiceBrowse(
        out: *mut Service,
        flags: u32,
        interface: u32,
        kind: *const c_char,
        domain: *const c_char,
        callback: BrowseCallback,
        context: *mut c_void,
    ) -> i32;
    fn DNSServiceResolve(
        out: *mut Service,
        flags: u32,
        interface: u32,
        name: *const c_char,
        kind: *const c_char,
        domain: *const c_char,
        callback: ResolveCallback,
        context: *mut c_void,
    ) -> i32;
    fn DNSServiceRefSockFD(service: Service) -> i32;
    fn DNSServiceProcessResult(service: Service) -> i32;
    fn DNSServiceRefDeallocate(service: Service);
    fn TXTRecordGetValuePtr(
        size: u16,
        txt: *const c_void,
        key: *const c_char,
        length: *mut u8,
    ) -> *const c_void;
}

#[derive(Default)]
struct State {
    services: Vec<Service>,
    seen: HashSet<(u32, Vec<u8>)>,
    endpoints: Vec<Endpoint>,
    failed: bool,
}
impl Drop for State {
    fn drop(&mut self) {
        for &service in &self.services {
            unsafe {
                DNSServiceRefDeallocate(service);
            }
        }
    }
}
unsafe extern "C" fn resolved(
    _: Service,
    _: u32,
    interface: u32,
    error: i32,
    _: *const c_char,
    host: *const c_char,
    _: u16,
    size: u16,
    txt: *const u8,
    context: *mut c_void,
) {
    if error != 0 || host.is_null() || txt.is_null() {
        return;
    }
    let state = unsafe { &mut *(context as *mut State) };
    let mut length = 0;
    let value = unsafe { TXTRecordGetValuePtr(size, txt.cast(), c"AppData".as_ptr(), &mut length) };
    if value.is_null() || length == 0 {
        return;
    }
    let encoded = unsafe { std::slice::from_raw_parts(value.cast::<u8>(), length as usize) };
    let Ok(bytes) = STANDARD.decode(encoded) else {
        return;
    };
    let Ok(ad) = Advertisement::parse(&bytes) else {
        return;
    };
    let Some(port) = ad.kcp_port.filter(|&p| p != 0) else {
        return;
    };
    let Ok(host) = (unsafe { CStr::from_ptr(host) }).to_str() else {
        return;
    };
    if host.len() > 255 || state.endpoints.len() >= 64 {
        return;
    }
    if !state
        .endpoints
        .iter()
        .any(|e| e.host == host && e.kcp_port == port && e.interface == interface)
    {
        state.endpoints.push(Endpoint {
            host: host.into(),
            interface,
            kcp_port: port,
            device_type: ad.device_type,
            model: ad
                .model
                .filter(|s| !s.chars().any(char::is_control))
                .map(str::to_owned),
            resolved: Vec::new(),
        });
    }
}
unsafe extern "C" fn browsed(
    _: Service,
    flags: u32,
    interface: u32,
    error: i32,
    name: *const c_char,
    kind: *const c_char,
    domain: *const c_char,
    context: *mut c_void,
) {
    if error != 0 || flags & 2 == 0 || name.is_null() || kind.is_null() || domain.is_null() {
        return;
    }
    let state = unsafe { &mut *(context as *mut State) };
    if state.services.len() >= 65
        || !state.seen.insert((
            interface,
            (unsafe { CStr::from_ptr(name) }).to_bytes().to_vec(),
        ))
    {
        return;
    }
    let mut service = std::ptr::null_mut();
    // DNS-SD delivers callbacks only through ProcessResult, after this borrow ends.
    if unsafe {
        DNSServiceResolve(
            &mut service,
            0,
            interface,
            name,
            kind,
            domain,
            resolved,
            context,
        )
    } == 0
    {
        state.services.push(service);
    }
}

pub(super) fn discover(timeout: Duration) -> anyhow::Result<Vec<Endpoint>> {
    let mut state = Box::<State>::default();
    let context = (&mut *state as *mut State).cast();
    let mut service = std::ptr::null_mut();
    let error = unsafe {
        DNSServiceBrowse(
            &mut service,
            0,
            0,
            c"_lyra-mdns._udp".as_ptr(),
            c"local.".as_ptr(),
            browsed,
            context,
        )
    };
    anyhow::ensure!(error == 0, "System DNS-SD browse failed ({error})");
    state.services.push(service);
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let refs = state.services.clone();
        let mut fds: Vec<libc::pollfd> = refs
            .iter()
            .map(|&service| libc::pollfd {
                fd: unsafe { DNSServiceRefSockFD(service) },
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        anyhow::ensure!(
            fds.iter().all(|p| p.fd >= 0),
            "Invalid system DNS-SD socket"
        );
        let result = unsafe {
            libc::poll(
                fds.as_mut_ptr(),
                fds.len() as libc::nfds_t,
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .min(200) as i32,
            )
        };
        if result < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            anyhow::bail!("DNS-SD socket polling failed");
        }
        for (fd, service) in fds.iter().zip(refs) {
            anyhow::ensure!(
                fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0,
                "DNS-SD socket closed"
            );
            if fd.revents & libc::POLLIN != 0 && unsafe { DNSServiceProcessResult(service) } != 0 {
                state.failed = true;
            }
        }
        anyhow::ensure!(!state.failed, "System DNS-SD response failed");
    }
    let mut endpoints = std::mem::take(&mut state.endpoints);
    // Resolve once, while the records are fresh. A failure leaves an empty list
    // and callers keep their previous behaviour of skipping that endpoint.
    for endpoint in &mut endpoints {
        endpoint.resolved = (endpoint.host.as_str(), endpoint.kcp_port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect())
            .unwrap_or_default();
    }
    Ok(endpoints)
}
