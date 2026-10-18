//! Native macOS text clipboard access; no helper processes or history database.
use objc2::rc::autoreleasepool;
use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString};
use objc2_foundation::{NSArray, NSString, ns_string};

pub enum Content {
    Text(String),
    Files,
    Unsupported,
}

fn read_from(board: &NSPasteboard) -> (isize, Content) {
    let count = board.changeCount();
    // Finder offers both file URLs and a plain-text filename. Check file
    // representations first, including promised files and legacy applications.
    #[allow(deprecated)]
    let file_types = NSArray::from_slice(&[
        unsafe { objc2_app_kit::NSPasteboardTypeFileURL },
        unsafe { objc2_app_kit::NSFilenamesPboardType },
        unsafe { objc2_app_kit::NSFilesPromisePboardType },
        ns_string!("com.apple.pasteboard.promised-file-url"),
        ns_string!("com.apple.pasteboard.promised-file-content-type"),
    ]);
    // This API checks all items, so a file after a text item still blocks text
    // fallback. Do not resolve URLs, request promised data, or open any files.
    let file_utis = NSArray::from_slice(&[
        unsafe { objc2_app_kit::NSPasteboardTypeFileURL },
        ns_string!("com.apple.pasteboard.promised-file-url"),
        ns_string!("com.apple.pasteboard.promised-file-content-type"),
    ]);
    let files = board.availableTypeFromArray(&file_types).is_some()
        || board.canReadItemWithDataConformingToTypes(&file_utis);
    let content = if files {
        Content::Files
    } else {
        board
            .stringForType(unsafe { NSPasteboardTypeString })
            .filter(|s| s.length() <= crate::message_center::MAX_INLINE_TEXT)
            .map(|s| Content::Text(s.to_string()))
            .unwrap_or(Content::Unsupported)
    };
    // A new copy between inspecting types and reading text invalidates the
    // snapshot. Retry on the next change-count check instead of leaking a name.
    (
        count,
        if board.changeCount() == count {
            content
        } else {
            Content::Unsupported
        },
    )
}

pub fn read_content() -> (isize, Content) {
    autoreleasepool(|_| read_from(&NSPasteboard::generalPasteboard()))
}

pub fn read() -> (isize, Option<String>) {
    let (count, content) = read_content();
    (
        count,
        match content {
            Content::Text(text) => Some(text),
            _ => None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TestBoard(objc2::rc::Retained<NSPasteboard>);
    impl Drop for TestBoard {
        fn drop(&mut self) {
            // SAFETY: This test owns a uniquely named temporary pasteboard.
            unsafe {
                let _: () = objc2::msg_send![&*self.0, releaseGlobally];
            }
        }
    }
    #[test]
    fn native_file_representations_override_filename_text_without_touching_user_clipboard() {
        autoreleasepool(|_| {
            let board = TestBoard(NSPasteboard::pasteboardWithUniqueName());
            #[allow(deprecated)]
            let file_types = [
                unsafe { objc2_app_kit::NSPasteboardTypeFileURL },
                unsafe { objc2_app_kit::NSFilenamesPboardType },
                unsafe { objc2_app_kit::NSFilesPromisePboardType },
                ns_string!("com.apple.pasteboard.promised-file-url"),
            ];
            for (index, kind) in file_types.into_iter().enumerate() {
                board.0.clearContents();
                if matches!(index, 1 | 2) {
                    let values = NSArray::from_slice(&[ns_string!("/synthetic/report.pdf")]);
                    // SAFETY: An array of strings is a valid property list for
                    // the legacy filename/promise representation.
                    assert!(unsafe { board.0.setPropertyList_forType(&values, kind) });
                } else {
                    assert!(
                        board
                            .0
                            .setString_forType(ns_string!("file:///synthetic/report.pdf"), kind)
                    );
                }
                assert!(board.0.setString_forType(ns_string!("report.pdf"), unsafe {
                    NSPasteboardTypeString
                }));
                assert!(matches!(read_from(&board.0).1, Content::Files));
            }
            // A file in a later item also blocks the first item's text fallback.
            {
                use objc2::runtime::ProtocolObject;
                use objc2_app_kit::NSPasteboardWriting;
                use objc2_foundation::NSURL;
                let file =
                    NSURL::URLWithString(ns_string!("file:///synthetic/report.pdf")).unwrap();
                let text: &ProtocolObject<dyn NSPasteboardWriting> =
                    ProtocolObject::from_ref(ns_string!("report.pdf"));
                let file: &ProtocolObject<dyn NSPasteboardWriting> =
                    ProtocolObject::from_ref(&*file);
                board.0.clearContents();
                assert!(board.0.writeObjects(&NSArray::from_slice(&[text, file])));
                assert!(matches!(read_from(&board.0).1, Content::Files));
            }
            // Actual text remains text, even when it resembles a filename or URL.
            for text in [
                "report.pdf",
                "file:///synthetic/report.pdf",
                "/synthetic/report.pdf",
                "正常文本",
            ] {
                board.0.clearContents();
                assert!(
                    board
                        .0
                        .setString_forType(&NSString::from_str(text), unsafe {
                            NSPasteboardTypeString
                        })
                );
                assert!(matches!(read_from(&board.0).1, Content::Text(value) if value == text));
            }
        });
    }
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
