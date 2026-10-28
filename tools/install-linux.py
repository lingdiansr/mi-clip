#!/usr/bin/env python3
"""Installs Mi Clip for the current user only.

Python is needed by this installer, not by the application. Nothing here asks
for privileges, starts at login, or edits PATH: it copies the binary and the
desktop entries into the user's private data directories and reports where.
"""
import os
import stat
import sys
from pathlib import Path


def fail(message):
    raise SystemExit(f"安装失败：{message}")


def desktop_quote(value):
    """Quotes one Exec argument per the Desktop Entry specification.

    Inside double quotes a backslash, double quote, backtick and dollar sign are
    escaped; a literal percent sign becomes a field-code escape.
    """
    escaped = (
        str(value).replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("`", "\\`")
        .replace("$", "\\$")
    )
    return '"' + escaped.replace("%", "%%") + '"'


def rewrite_exec(text, executable):
    """Replaces the program in every Exec line, keeping arguments and %F."""
    lines = []
    replaced = False
    for line in text.splitlines():
        if line.startswith("Exec="):
            command = line[len("Exec=") :]
            arguments = command.split(" ", 1)[1] if " " in command else ""
            new = f"Exec={desktop_quote(executable)}"
            if arguments:
                new = f"{new} {arguments}"
            lines.append(new)
            replaced = True
        else:
            lines.append(line)
    if not replaced:
        fail("desktop 文件缺少 Exec 行")
    return "\n".join(lines) + "\n"


def install_bytes(source, target, mode):
    """Atomically installs a regular file, never touching a symlink or device."""
    if target.is_symlink():
        fail(f"{target} 是符号链接，拒绝覆盖")
    if target.exists() and not target.is_file():
        fail(f"{target} 不是普通文件，拒绝覆盖")
    payload = source.read_bytes() if isinstance(source, Path) else source
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.new-{os.getpid()}")
    temporary.write_bytes(payload)
    os.chmod(temporary, mode)
    os.replace(temporary, target)


def main():
    package = Path(__file__).resolve().parent
    binary = package / "bin/mi-clip"
    if not binary.is_file():
        fail("包内缺少 bin/mi-clip")
    details = binary.stat()
    if not stat.S_ISREG(details.st_mode) or not details.st_mode & 0o111:
        fail("包内 bin/mi-clip 不是可执行普通文件")

    home = Path.home()
    data = home / ".local/share"
    binary_target = home / ".local/bin/mi-clip"
    launcher_target = data / "applications/com.cyeam.miclip.desktop"
    menu_target = data / "kio/servicemenus/mi-clip-share.desktop"
    icon_target = data / "icons/hicolor/scalable/apps/mi-clip.svg"

    print("将要安装（仅当前用户，无 sudo）：")
    print(f"  {binary_target} (0755)")
    print(f"  {launcher_target} (0644)")
    # KDE only loads a user service menu that carries the executable bit.
    print(f"  {menu_target} (0755)")
    print(f"  {icon_target} (0644)")

    install_bytes(binary, binary_target, 0o755)
    install_bytes(
        rewrite_exec(
            (package / "share/applications/com.cyeam.miclip.desktop").read_text(
                encoding="utf-8"
            ),
            binary_target,
        ),
        launcher_target,
        0o644,
    )
    install_bytes(
        rewrite_exec(
            (package / "share/kio/servicemenus/mi-clip-share.desktop").read_text(
                encoding="utf-8"
            ),
            binary_target,
        ),
        menu_target,
        0o755,
    )
    install_bytes(
        package / "share/icons/hicolor/scalable/apps/mi-clip.svg",
        icon_target,
        0o644,
    )
    print("安装完成。应用运行不依赖 Python；请在桌面会话中重新登录后使用。")
    if str(binary_target.parent) not in os.environ.get("PATH", "").split(os.pathsep):
        print(f"提示：{binary_target.parent} 不在 PATH 中；桌面入口会自动使用绝对路径。")


if __name__ == "__main__":
    sys.exit(main())
