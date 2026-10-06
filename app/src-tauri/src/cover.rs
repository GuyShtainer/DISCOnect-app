// SPDX-License-Identifier: AGPL-3.0-or-later
//! The app-switcher cover (12-F row 5b, S7): while the app is not active, a plain view sits over every window of the
//! app, so the thumbnail iOS keeps for the app switcher shows neither health data nor a pairing code.
//!
//! It is native on purpose. The page cannot do this: a message to JavaScript over IPC arrives after the system has
//! taken the snapshot. UIKit posts `UIApplicationWillResignActiveNotification` on the main thread before the snapshot
//! (also for a pulled-down Control Center, a system alert or the app switcher itself) and
//! `UIApplicationDidBecomeActiveNotification` when the app is active again, with or without a trip through the
//! background; the cover goes on the first and comes off the second, so it cannot stay stuck (Tauri's `Resumed` fires
//! only on entering the foreground, which Control Center never does).
//!
//! The cover is a `UIView` with the system background colour (it follows the phone's light or dark side; the page's own
//! theme is not known here) and the product's name in the secondary label colour. No data, no code, no state.

use std::ptr::NonNull;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::MainThreadMarker;
use objc2_foundation::{NSNotification, NSNotificationCenter, NSOperationQueue, NSString};
use objc2_ui_kit::{
    NSTextAlignment, UIApplication, UIApplicationDidBecomeActiveNotification, UIApplicationWillResignActiveNotification,
    UIColor, UILabel, UIView, UIViewAutoresizing,
};

/// Identifies the cover among a window's subviews (any number no other view of the app uses).
const COVER_TAG: isize = 0x0D15_C001;
const NAME: &str = "DISCOnect";

/// Put a cover on every window that has none.
fn show(mtm: MainThreadMarker) {
    let app = UIApplication::sharedApplication(mtm);
    #[allow(deprecated)] // the app has one scene; `windows` lists its windows without a scene lookup
    let windows = app.windows();
    for window in windows.iter() {
        if window.viewWithTag(COVER_TAG).is_some() {
            continue;
        }
        let cover = UIView::initWithFrame(mtm.alloc::<UIView>(), window.bounds());
        let everywhere = UIViewAutoresizing::FlexibleWidth | UIViewAutoresizing::FlexibleHeight;
        cover.setAutoresizingMask(everywhere);
        cover.setBackgroundColor(Some(&UIColor::systemBackgroundColor()));
        cover.setTag(COVER_TAG);
        let label = UILabel::initWithFrame(mtm.alloc::<UILabel>(), cover.bounds());
        label.setAutoresizingMask(everywhere);
        label.setTextAlignment(NSTextAlignment::Center);
        // SAFETY: a plain colour set on a label this function just made, on the main thread.
        unsafe { label.setTextColor(Some(&UIColor::secondaryLabelColor())) };
        label.setText(Some(&NSString::from_str(NAME)));
        cover.addSubview(&label);
        window.addSubview(&cover);
    }
}

/// Take every cover off.
fn hide(mtm: MainThreadMarker) {
    let app = UIApplication::sharedApplication(mtm);
    #[allow(deprecated)]
    let windows = app.windows();
    for window in windows.iter() {
        while let Some(cover) = window.viewWithTag(COVER_TAG) {
            cover.removeFromSuperview();
        }
    }
}

/// Start observing. Call once, on the main thread, at start-up. The two observers live as long as the process.
pub fn install(mtm: MainThreadMarker) {
    let center = NSNotificationCenter::defaultCenter();
    let main = NSOperationQueue::mainQueue();
    let on_resign = RcBlock::new(|_: NonNull<NSNotification>| {
        if let Some(mtm) = MainThreadMarker::new() {
            show(mtm);
        }
    });
    let on_active = RcBlock::new(|_: NonNull<NSNotification>| {
        if let Some(mtm) = MainThreadMarker::new() {
            hide(mtm);
        }
    });
    // SAFETY: the names are UIKit's own constants; both blocks run on the main queue, where UIKit objects may be used,
    // and capture nothing.
    unsafe {
        let resign: Retained<_> = center.addObserverForName_object_queue_usingBlock(Some(UIApplicationWillResignActiveNotification), None, Some(&main), &on_resign);
        let active: Retained<_> = center.addObserverForName_object_queue_usingBlock(Some(UIApplicationDidBecomeActiveNotification), None, Some(&main), &on_active);
        // the tokens must outlive start-up (dropping one would not remove the observer, but keep them plainly)
        std::mem::forget(resign);
        std::mem::forget(active);
    }
    let _ = mtm;
}
