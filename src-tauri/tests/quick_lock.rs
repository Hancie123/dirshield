//! Quick Lock on generated folders: access is denied while locked (even by
//! full path), and unlocking restores attributes and access exactly.
#![cfg(windows)]

use std::fs;

use dirshield_lib::{fsutil, quicklock, winsec};

fn make(dir: &std::path::Path) {
    fs::create_dir_all(dir.join("sub")).unwrap();
    fs::write(dir.join("sub").join("secret.txt"), b"secret").unwrap();
}

#[test]
fn visible_lock_stays_in_place_and_unhidden() {
    let t = tempfile::tempdir().unwrap();
    let folder = t.path().join("Visible");
    let store = t.path().join("store");
    make(&folder);
    let before = fsutil::get_attrs(&folder).unwrap() & fsutil::RESTORABLE_ATTRS;

    // One child was already not-indexed before locking: it must stay that way.
    let kept = folder.join("sub");
    fsutil::set_attrs(&kept, fsutil::get_attrs(&kept).unwrap() & fsutil::RESTORABLE_ATTRS | fsutil::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED).unwrap();
    let file = folder.join("sub").join("secret.txt");
    let file_before = fsutil::get_attrs(&file).unwrap();

    let st = quicklock::lock(&folder, Some(&store), "vis1", false).unwrap();
    assert!(!st.moved && !st.hidden);
    assert_eq!(st.kept_not_indexed, vec!["sub".to_string()]);
    // Contents can't be listed or opened, even by full path.
    assert!(fs::read_dir(&folder).is_err());
    assert!(fs::read(&file).is_err());
    assert!(folder.exists());
    assert!(winsec::is_restricted(&folder).unwrap());
    let a = fsutil::get_attrs(&folder).unwrap();
    assert!(a & fsutil::FILE_ATTRIBUTE_HIDDEN == 0 && a & fsutil::FILE_ATTRIBUTE_SYSTEM == 0);

    quicklock::unlock(&st, &folder, None).unwrap();
    assert!(!winsec::is_restricted(&folder).unwrap());
    assert_eq!(fsutil::get_attrs(&folder).unwrap() & fsutil::RESTORABLE_ATTRS, before);
    assert_eq!(fsutil::get_attrs(&file).unwrap(), file_before);
    assert!(fsutil::get_attrs(&kept).unwrap() & fsutil::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED != 0);
    assert_eq!(fs::read(&file).unwrap(), b"secret");
}

#[test]
fn in_place_lock_denies_access_and_unlock_restores() {
    let t = tempfile::tempdir().unwrap();
    let folder = t.path().join("Private (in place)");
    make(&folder);
    let before = fsutil::get_attrs(&folder).unwrap() & fsutil::RESTORABLE_ATTRS;

    let st = quicklock::lock(&folder, None, "id1", true).unwrap();
    assert!(!st.moved);
    assert!(winsec::is_restricted(&folder).unwrap());
    let a = fsutil::get_attrs(&folder).unwrap();
    assert!(a & fsutil::FILE_ATTRIBUTE_HIDDEN != 0 && a & fsutil::FILE_ATTRIBUTE_SYSTEM != 0);
    assert!(fs::read(folder.join("sub").join("secret.txt")).is_err(), "full-path access must be denied");
    assert!(fs::read_dir(&folder).is_err(), "listing must be denied");
    assert!(fs::remove_dir_all(&folder).is_err(), "deletion must be denied");

    // hide/unhide keeps the restriction
    let mut st2 = st.clone();
    quicklock::set_hidden(&mut st2, false).unwrap();
    assert!(fsutil::get_attrs(&folder).unwrap() & fsutil::FILE_ATTRIBUTE_HIDDEN == 0);
    assert!(fs::read(folder.join("sub").join("secret.txt")).is_err());

    quicklock::unlock(&st, &folder, None).unwrap();
    assert!(!winsec::is_restricted(&folder).unwrap());
    assert_eq!(fs::read(folder.join("sub").join("secret.txt")).unwrap(), b"secret");
    assert_eq!(fsutil::get_attrs(&folder).unwrap() & fsutil::RESTORABLE_ATTRS, before);
}

#[test]
fn moved_lock_and_unlock_never_overwrites() {
    let t = tempfile::tempdir().unwrap();
    let folder = t.path().join("Ünïcode folder");
    let store = t.path().join("store");
    make(&folder);
    let st = quicklock::lock(&folder, Some(&store), "abc123", true).unwrap();
    assert!(st.moved);
    assert!(!folder.exists());
    assert!(fs::read(store.join("abc123").join("sub").join("secret.txt")).is_err());

    // Something new appeared at the original location: unlock must refuse, not merge/overwrite.
    fs::create_dir_all(&folder).unwrap();
    assert!(quicklock::unlock(&st, &folder, None).is_err());
    assert!(winsec::is_restricted(&store.join("abc123")).unwrap(), "still locked after refused unlock");
    fs::remove_dir(&folder).unwrap();

    let out = quicklock::unlock(&st, &folder, None).unwrap();
    assert_eq!(out, folder);
    assert_eq!(fs::read(folder.join("sub").join("secret.txt")).unwrap(), b"secret");
}

#[test]
fn orphaned_moved_folder_can_be_recovered_without_database() {
    let t = tempfile::tempdir().unwrap();
    let folder = t.path().join("Photos");
    let store = t.path().join("store");
    make(&folder);
    let id = "0123456789abcdef0123456789abcdef";
    quicklock::lock(&folder, Some(&store), id, true).unwrap();
    // Database lost: only the store remains.
    let orphans = quicklock::find_orphans(&store, &[]).unwrap();
    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].original_path.as_deref(), Some(fsutil::display_path(&folder).as_str()));
    assert!(quicklock::find_orphans(&store, &[id.to_string()]).unwrap().is_empty());
    let back = quicklock::recover_orphan(&store, &orphans[0], &folder).unwrap();
    assert_eq!(back, folder);
    assert_eq!(fs::read(folder.join("sub").join("secret.txt")).unwrap(), b"secret");
    assert!(!quicklock::sidecar_path(&store, id).exists());
    let a = fsutil::get_attrs(&folder).unwrap();
    assert!(a & (fsutil::FILE_ATTRIBUTE_HIDDEN | fsutil::FILE_ATTRIBUTE_SYSTEM) == 0);
}
