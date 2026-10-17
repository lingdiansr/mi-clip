//! Native macOS text clipboard access; no helper processes or history database.
use objc2::rc::autoreleasepool;
use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString};
use objc2_foundation::NSString;

pub fn read() -> (isize, Option<String>) {
    autoreleasepool(|_| {
        let board = NSPasteboard::generalPasteboard();
        let count = board.changeCount();
        // SAFETY: AppKit's exported constant is a process-lifetime NSString.
        let text = board
            .stringForType(unsafe { NSPasteboardTypeString })
            .filter(|s| s.length() <= crate::message_center::MAX_INLINE_TEXT)
            .map(|s| s.to_string());
        (count, text)
    })
}

pub fn change_count() -> isize {
    autoreleasepool(|_| NSPasteboard::generalPasteboard().changeCount())
}

pub fn write(text: &str) -> anyhow::Result<isize> {
    autoreleasepool(|_| {
        let board = NSPasteboard::generalPasteboard();
        board.clearContents();
        anyhow::ensure!(
            board.setString_forType(&NSString::from_str(text), unsafe { NSPasteboardTypeString }),
            "macOS rejected text clipboard write"
        );
        Ok(board.changeCount())
    })
}
