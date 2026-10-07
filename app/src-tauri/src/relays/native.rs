// SPDX-License-Identifier: AGPL-3.0-or-later
//! The part of the relay list that talks to Foundation and UIKit: security-scoped bookmarks and the Files picker.
//! Native Rust over `objc2` like `cover.rs` and `ios.rs`: the app has no Swift plugin of its own (the camera is a
//! Tauri plugin), and a delegate class is the whole of what the picker needs.

use std::cell::RefCell;
use std::path::Path;
use std::sync::{mpsc, Mutex};

use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, ProtocolObject};
use objc2::{define_class, msg_send, MainThreadMarker, MainThreadOnly};
use objc2_foundation::{
    NSArray, NSData, NSObject, NSObjectProtocol, NSString, NSURLBookmarkCreationOptions, NSURLBookmarkResolutionOptions, NSURL,
};
use objc2_ui_kit::{UIApplication, UIDocumentPickerDelegate, UIDocumentPickerViewController};

/// A folder's security scope, held. Dropping it stops the access. `NSURL` is immutable and Apple documents it as
/// thread-safe, which is what lets the guard sit in an async command across the core's answer.
pub struct Scope {
    url: Retained<NSURL>,
    started: bool,
}

// SAFETY: see the type's note; the guard only sends `stopAccessingSecurityScopedResource` to an immutable NSURL.
unsafe impl Send for Scope {}

impl Drop for Scope {
    fn drop(&mut self) {
        if self.started {
            // SAFETY: paired with the successful `startAccessingSecurityScopedResource` in `resolve`.
            unsafe { self.url.stopAccessingSecurityScopedResource() };
        }
    }
}

/// A bookmark that resolved: the scope (held), the path, and fresh bookmark bytes when the old ones went stale.
pub struct Resolved {
    pub scope: Scope,
    pub path: String,
    pub refreshed: Option<Vec<u8>>,
}

fn bookmark_of(url: &NSURL) -> Option<Vec<u8>> {
    url.bookmarkDataWithOptions_includingResourceValuesForKeys_relativeToURL_error(NSURLBookmarkCreationOptions::MinimalBookmark, None, None)
        .ok()
        .map(|d| d.to_vec())
}

/// Resolve a bookmark and start its scope. `None` when it does not resolve (the folder is gone, the volume or the
/// provider is not there) **or the scope could not be started** (the folder is then not this app's to read): the caller
/// says "unavailable", it does not drop the entry. `unscoped_ok` is for the debug seed's plain-folder bookmarks and is
/// honoured in debug builds only.
pub fn resolve(bookmark: &[u8], unscoped_ok: bool) -> Option<Resolved> {
    let data = NSData::with_bytes(bookmark);
    let mut stale = objc2::runtime::Bool::NO;
    // SAFETY: `stale` is a valid pointer for the call.
    let url = unsafe {
        NSURL::URLByResolvingBookmarkData_options_relativeToURL_bookmarkDataIsStale_error(&data, NSURLBookmarkResolutionOptions::empty(), None, &mut stale)
    }
    .ok()?;
    // SAFETY: a plain NSURL message; the result decides whether a stop is owed (see `Scope`).
    let started = unsafe { url.startAccessingSecurityScopedResource() };
    if !scope_allows(started, unscoped_ok) {
        return None; // 19d review #17a: no scope, no path
    }
    let path = url.path().map(|p| p.to_string());
    let refreshed = if stale.as_bool() { bookmark_of(&url) } else { None };
    let scope = Scope { url, started };
    path.map(|path| Resolved { scope, path, refreshed })
}

/// Whether a folder may be used: its scope started, or (debug builds, the seed's plain folders) the entry says it has none.
fn scope_allows(started: bool, unscoped_ok: bool) -> bool {
    started || (cfg!(debug_assertions) && unscoped_ok)
}

/// A bookmark for a folder this app already owns (the debug seed and the tests); the picker's own bookmarks come from
/// [`pick`].
pub fn bookmark_for_path(path: &Path) -> Option<Vec<u8>> {
    let text = path.to_str()?;
    let url = NSURL::fileURLWithPath(&NSString::from_str(text));
    bookmark_of(&url)
}

/// The last two parts of a path, for a line a person can recognise ("Documents / Relay").
pub fn display_of(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    match parts.len() {
        0 => "/".into(),
        1 => parts[0].into(),
        n => format!("{} / {}", parts[n - 2], parts[n - 1]),
    }
}

// ---- the Files picker ----

/// What the picker hands back: the bookmark and the folder's name, or `None` when the person cancelled.
pub type Picked = Option<(Vec<u8>, String)>;

static WAITING: Mutex<Option<mpsc::Sender<Picked>>> = Mutex::new(None);

thread_local! {
    /// UIKit holds a picker's delegate weakly; this keeps it alive until the picker answers (main thread only).
    static HOLD: RefCell<Option<Retained<PickerDelegate>>> = const { RefCell::new(None) };
}

fn finish(answer: Picked) {
    if let Some(tx) = WAITING.lock().ok().and_then(|mut slot| slot.take()) {
        let _ = tx.send(answer);
    }
    HOLD.with(|h| h.borrow_mut().take());
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "DisconectFolderPickerDelegate"]
    struct PickerDelegate;

    unsafe impl NSObjectProtocol for PickerDelegate {}

    unsafe impl UIDocumentPickerDelegate for PickerDelegate {
        #[unsafe(method(documentPicker:didPickDocumentsAtURLs:))]
        fn did_pick(&self, _controller: &UIDocumentPickerViewController, urls: &NSArray<NSURL>) {
            let answer = urls.firstObject().and_then(|url| {
                // SAFETY: paired with the stop below.
                let started = unsafe { url.startAccessingSecurityScopedResource() };
                let bytes = bookmark_of(&url);
                let name = url.lastPathComponent().map(|n| n.to_string()).unwrap_or_default();
                if started {
                    // SAFETY: the start above succeeded.
                    unsafe { url.stopAccessingSecurityScopedResource() };
                }
                bytes.map(|b| (b, name))
            });
            finish(answer);
        }

        #[unsafe(method(documentPickerWasCancelled:))]
        fn cancelled(&self, _controller: &UIDocumentPickerViewController) {
            finish(None);
        }
    }
);

impl PickerDelegate {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = mtm.alloc::<Self>().set_ivars(());
        // SAFETY: NSObject's plain `init`.
        unsafe { msg_send![super(this), init] }
    }
}

/// Present the Files picker for one folder (`UIDocumentPickerViewController(forOpeningContentTypes: [.folder])`) over the
/// topmost view controller. Main thread. The answer arrives on `tx`; an `Err` word says it could not be shown.
pub fn present(mtm: MainThreadMarker, tx: mpsc::Sender<Picked>) -> Result<(), &'static str> {
    let Some(class) = AnyClass::get(c"UTType") else { return Err("unavailable") };
    // SAFETY: `+[UTType typeWithIdentifier:]` takes an NSString and returns an autoreleased UTType or nil.
    let folder: Option<Retained<AnyObject>> = unsafe { msg_send![class, typeWithIdentifier: &*NSString::from_str("public.folder")] };
    let Some(folder) = folder else { return Err("unavailable") };
    let types = NSArray::from_slice(&[&*folder]);
    // SAFETY: `initForOpeningContentTypes:` takes an NSArray of UTType.
    let picker: Retained<UIDocumentPickerViewController> = unsafe { msg_send![mtm.alloc::<UIDocumentPickerViewController>(), initForOpeningContentTypes: &*types] };
    picker.setAllowsMultipleSelection(false);
    let delegate = PickerDelegate::new(mtm);
    picker.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
    #[allow(deprecated)] // the app has one scene; `windows` lists its windows without a scene lookup
    let windows = UIApplication::sharedApplication(mtm).windows();
    let mut top = windows.iter().find_map(|w| w.rootViewController()).ok_or("unavailable")?;
    while let Some(next) = top.presentedViewController() {
        top = next;
    }
    {
        let mut slot = WAITING.lock().map_err(|_| "unavailable")?;
        if slot.is_some() {
            return Err("busy");
        }
        *slot = Some(tx);
    }
    HOLD.with(|h| *h.borrow_mut() = Some(delegate));
    top.presentViewController_animated_completion(&picker, true, None);
    Ok(())
}

/// The picker is gone without an answer (the wait timed out); free the slot.
pub fn abandon() {
    finish(None);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("disconect-relays-native-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_bookmark_of_an_owned_folder_resolves_to_it_and_a_deleted_folder_does_not() {
        let dir = scratch("bookmark");
        let folder = dir.join("Relay");
        std::fs::create_dir_all(&folder).unwrap();
        let bytes = bookmark_for_path(&folder).expect("a bookmark");
        // (the simulator starts every scope, so "did not start" is tested on the rule itself)
        assert!(!scope_allows(false, false), "a bookmark whose scope does not start is unavailable, not a path");
        assert!(scope_allows(true, false));
        assert_eq!(scope_allows(false, true), cfg!(debug_assertions), "only the debug seed's folders may go unscoped, and only in debug");
        {
            let r = resolve(&bytes, true).expect("resolves");
            assert_eq!(std::fs::canonicalize(&r.path).unwrap(), std::fs::canonicalize(&folder).unwrap());
            assert!(std::fs::read_dir(&r.path).is_ok());
        }
        std::fs::remove_dir_all(&folder).unwrap();
        assert!(resolve(&bytes, true).is_none(), "a folder that is gone is unavailable");
        assert!(resolve(b"not a bookmark", true).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_display_line_is_the_last_two_parts() {
        assert_eq!(display_of("/a/b/Documents/Relay"), "Documents / Relay");
        assert_eq!(display_of("/Relay"), "Relay");
        assert_eq!(display_of("/"), "/");
    }
}
