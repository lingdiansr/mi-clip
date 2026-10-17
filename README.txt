Mi Clip

轻量的 macOS 小米共享剪贴板客户端，Rust 实现，状态栏 UI 使用 gpui-rhai。
手机使用系统内置互联功能，无需安装新软件。运行时不加载小米官方库。

当前范围
- 双向 UTF-8 短文本，每次最多 3072 字节；不支持图片、富文本或长文本。
- 手机与 Mac 在同一局域网，并开启手机互联功能。
- 菜单栏常驻一个自行设计的单色图标，无主窗口和 Dock 图标。
- 点击打开小型状态面板；再次点击图标、点击外部或按 Esc 可收起；“退出”和 Cmd-Q 结束程序。
- 连接断开后自动重新发现并重试，剪贴板读取使用系统原生接口。
- 正常运行不保存剪贴板正文、传输报文或临时会话密钥。
- 自申请的账号会话和设备证书保存在本机私有目录，文件权限 0600。
- 同账号证书、临时公钥签名、服务端密钥确认及 AES-GCM 消息认证均验证后使用。

验证范围
已在 Intel Mac 与一台 HyperOS 3 小米手机上验证：退出官方 Mac 客户端后，
手机复制的测试文本可以写入 Mac 系统剪贴板；反向文本由手机粘贴确认一致。
其他系统版本和设备组合尚未验证。这是早期协议互操作版本。

构建
需要 macOS、Xcode Command Line Tools 和 Rust 1.95 或更高版本。
  ./tools/build-release.sh --bin mi-clip
  ./target/release/mi-clip

构建脚本移除个人源码目录和 Cargo 缓存路径。Rhai 脚本及图标嵌入单一二进制。
默认构建只输出状态栏程序，不需要安装 Node、Python 或官方互联客户端。

首次登录
从 Release 下载对应架构的文件后，重命名为 mi-clip，并执行 chmod +x mi-clip。
以下命令都由同一个 mi-clip 二进制提供。授权状态不要放进源码仓库。
  umask 077
  miclip_dir="$HOME/Library/Application Support/MiClip"
  mkdir -p "$miclip_dir"
  chmod 700 "$miclip_dir"
  ./mi-clip --auth prepare "$miclip_dir/qr-state.json" "$miclip_dir/qr.png"
  open "$miclip_dir/qr.png"

用手机扫码并确认登录后执行：
  ./mi-clip --auth poll "$miclip_dir/qr-state.json" "$miclip_dir/grant.json"
  ./mi-clip --auth redeem "$miclip_dir/grant.json" "$miclip_dir/session.json"
  ./mi-clip --auth account-cert "$miclip_dir/session.json" "$miclip_dir/account.pem"
  ./mi-clip --auth device-cert "$miclip_dir/session.json" "$miclip_dir/device"

二维码约 5 分钟过期；poll 遇到等待超时可在二维码有效期内重试。
redeem 的一次性授权不要重复兑换；账号失效时重新执行登录流程。
在上述私有目录创建 config.json，内容如下：
  {
    "session": "session.json",
    "identity": "device/device.json",
    "account_certificate": "account.pem"
  }
  chmod 600 "$miclip_dir/config.json"

之后直接运行 ./mi-clip。程序会自动读取这个配置并发现同一局域网的手机。
也可指定配置：./mi-clip --config /私有目录/config.json
路径相对于配置文件所在目录解析。请保持手机解锁、互联页面开启以完成首次发现。

验证命令
  cargo test --no-default-features --features research --lib
  ./target/release/mi-clip --check-ui
  ./target/release/mi-clip --smoke-test
  python3 tests/probe_test.py ./target/release/mi-clip

协议研究
研究 CLI 可单独构建，不依赖 GPUI：
  cargo build --release --no-default-features --features research --bin mi-clip-auth
  ./target/release/mi-clip-auth discover /私有目录/endpoints.json

--auth probe-handshake INPUT OUTPUT 是有界诊断模式，会显式保存私有报文和密钥。
它不是默认运行模式。请勿公开研究输出、登录二维码、会话、证书或密钥。
源码仓库仅包含实现、合成测试和原始图标，没有真实账号、设备标识或抓包。

设计取舍
UI 按需创建，正常驻留不运行 Rhai 面板或隐藏主窗口。
保留 gpui-rhai 时，UI 框架仍占主要二进制体积；协议核心可以独立构建。
网络传输为单手机场景的有界 KCP 实现，尚未覆盖所有网络拥塞和漫游场景。

签名自动更新
- 启动约 10 秒后检查一次，之后每小时检查；状态面板可手动检查。
- 从 GitHub Release 获取当前架构的签名清单，并在后台下载较新版本。
- 清单使用独立 P-256 发布密钥签名，二进制验证签名覆盖的 SHA-256、长度和架构。
- 检查通过后点击“更新至 …”，程序停止同步、原子替换并重新启动。
- 保留旧二进制，直到新程序的状态栏报告启动就绪；启动失败则恢复旧版。
- 不接受降级、不执行下载脚本、不引入 Sparkle 或其他更新框架。
- 更新源须允许匿名下载；没有 Release 或没有当前架构的清单时显示“更新尚未发布”。
- 本地开发构建不配置更新源时，不进行可用更新安装。

更新发布
推送与 Cargo.toml 版本一致的稳定 tag（例如 v0.2.0）后，GitHub Actions 会：
- 分别在 Intel 和 Apple Silicon 的 macOS runner 上测试并编译优化后的二进制。
- 校验 Rhai 脚本、合成设备协议和更新签名，生成二进制、签名清单及 SHA-256 文件。
- 等两个架构均成功后上传到 GitHub Release，完成上传后再公开新 Release。
- 发布完成后推送飞书消息，包含版本号、两个架构说明、下载链接和构建记录。
仓库 Actions Secret MI_CLIP_SIGNING_KEY 需保存现有 32 字节 P-256 发布私钥的 Base64。
仓库 Actions Secret FEISHU_WEBHOOK_URL 保存飞书机器人的 Webhook 地址，不写入源码。
工作流只上传 release-assets 中的发布文件，签名私钥与配置在临时目录中使用后删除。
只接受 v主版本.次版本.修订版本，且必须与 Cargo.toml 一致；不发布预览版或裸数字 tag。

构建脚本从 origin 的 GitHub 地址推导更新仓库，也可通过环境变量指定：
  MI_CLIP_UPDATE_REPOSITORY=owner/mi-clip ./tools/build-release.sh --bin mi-clip

私钥不属于客户端和仓库。src/update_key.rs 只包含本项目的公开验证密钥。
发布者应备份对应的 32 字节 P-256 私钥，并在所有后续版本沿用这把发布密钥。
在仓库外创建签名配置，例如：
  {
    "version": "0.1.0",
    "arch": "x86_64",
    "repository": "owner/mi-clip",
    "binary": "/构建目录/mi-clip",
    "private_key": "/私有目录/signing.key"
  }
  ./mi-clip --auth sign-update /私有目录/release.json /发布目录

把生成的 mi-clip-macos-x86_64 和 manifest-macos-x86_64.json 放到 v0.1.0 Release。
ARM 构建使用 arch=aarch64 和对应名称。只有 x86_64 已在本机验证。
发布版本号必须同时更新 Cargo.toml 并递增，签名清单和二进制的版本必须一致。
签名配置、私钥及发布输出应保存在源码目录之外。

更新验证
  cargo test --no-default-features --features research --lib
  MICLIP_TEST_APP=/构建目录/mi-clip cargo test --no-default-features --features research --lib updater::tests::real_gui_restart_reports_ready -- --ignored --test-threads=1
第二条在临时目录中验证替换和实际 GUI 重启，不替换当前安装的程序。
  python3 tests/update_signature_test.py /发布目录/manifest-macos-x86_64.json /发布目录/mi-clip-macos-x86_64
该测试仅用公开验证密钥和系统 OpenSSL，独立检查真实发布签名及二进制摘要。

本机 v0.1.0 验证结果
- Intel macOS 单文件 16,523,352 字节，源码与锁文件合计约 370 KB。
- 26 项 Rust 测试通过，包括真实 GUI 更新重启和失败回退。
- 状态栏启动、Rhai 状态刷新后的 Esc、底部退出按钮及外部关闭事件均通过验证。
- 外部鼠标监听仅在面板打开期间注册，面板关闭即释放。
- 真实发布签名由系统 OpenSSL 独立验证，篡改后的清单被拒绝。
- 手机与 Mac 双向文本同步在官方客户端退出后通过验证。
- 不依赖官方动态库；尚未执行卸载官方 App 的测试。
