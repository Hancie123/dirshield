//! Quick Lock on generated folders: access is denied while locked (even by
//! full path), and unlocking restores attributes and access exactly.
#![cfg(windows)]

use std::fs;

use dirshield_lib::platform::fsutil;
use dirshield_lib::quicklock::{self, acl};

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

    let st = quicklock::lock(&folder, Some(&store), "vis1", false, None).unwrap();
    assert!(!st.moved && !st.hidden);
    assert_eq!(st.kept_not_indexed, vec!["sub".to_string()]);
    // Contents can't be listed or opened, even by full path.
    assert!(fs::read_dir(&folder).is_err());
    assert!(fs::read(&file).is_err());
    assert!(folder.exists());
    assert!(acl::is_restricted(&folder).unwrap());
    let a = fsutil::get_attrs(&folder).unwrap();
    assert!(a & fsutil::FILE_ATTRIBUTE_HIDDEN == 0 && a & fsutil::FILE_ATTRIBUTE_SYSTEM == 0);

    quicklock::unlock(&st, &folder, None).unwrap();
    assert!(!acl::is_restricted(&folder).unwrap());
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

    let st = quicklock::lock(&folder, None, "id1", true, None).unwrap();
    assert!(!st.moved);
    assert!(acl::is_restricted(&folder).unwrap());
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
    assert!(!acl::is_restricted(&folder).unwrap());
    assert_eq!(fs::read(folder.join("sub").join("secret.txt")).unwrap(), b"secret");
    assert_eq!(fsutil::get_attrs(&folder).unwrap() & fsutil::RESTORABLE_ATTRS, before);
}

#[test]
fn moved_lock_and_unlock_never_overwrites() {
    let t = tempfile::tempdir().unwrap();
    let folder = t.path().join("Ünïcode folder");
    let store = t.path().join("store");
    make(&folder);
    let st = quicklock::lock(&folder, Some(&store), "abc123", true, None).unwrap();
    assert!(st.moved);
    assert!(!folder.exists());
    assert!(fs::read(store.join("abc123").join("sub").join("secret.txt")).is_err());

    // Something new appeared at the original location: unlock must refuse, not merge/overwrite.
    fs::create_dir_all(&folder).unwrap();
    assert!(quicklock::unlock(&st, &folder, None).is_err());
    assert!(acl::is_restricted(&store.join("abc123")).unwrap(), "still locked after refused unlock");
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
    quicklock::lock(&folder, Some(&store), id, true, None).unwrap();
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

#[test]
fn visible_lock_shows_icon_and_restores_existing_desktop_ini() {
    let t = tempfile::tempdir().unwrap();
    let folder = t.path().join("With Icon");
    let data = t.path().join("data");
    make(&folder);
    let original_ini = b"[.ShellClassInfo]\r\nInfoTip=mine\r\n".to_vec();
    fs::write(folder.join("desktop.ini"), &original_ini).unwrap();
    let before = fsutil::get_attrs(&folder).unwrap() & fsutil::RESTORABLE_ATTRS;

    let st = quicklock::lock(&folder, None, "ico1", false, Some(&data)).unwrap();
    assert!(st.icon);
    assert!(fsutil::get_attrs(&folder).unwrap() & fsutil::FILE_ATTRIBUTE_READONLY != 0);
    // Explorer can read the icon instructions, but nothing else inside.
    let ini = fs::read(folder.join("desktop.ini")).unwrap();
    let text = String::from_utf16_lossy(&ini[2..].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>());
    assert!(text.contains("IconResource=") && text.contains("locked-folder.ico"));
    assert!(data.join("icons").join("locked-folder.ico").exists());
    assert!(fs::read(folder.join("desktop.ini.dirshield")).is_err());
    assert!(fs::read(folder.join("sub").join("secret.txt")).is_err());
    assert!(fs::read_dir(&folder).is_err());

    quicklock::unlock(&st, &folder, None).unwrap();
    assert_eq!(fs::read(folder.join("desktop.ini")).unwrap(), original_ini);
    assert!(!folder.join("desktop.ini.dirshield").exists());
    assert_eq!(fsutil::get_attrs(&folder).unwrap() & fsutil::RESTORABLE_ATTRS, before);
    assert_eq!(fs::read(folder.join("sub").join("secret.txt")).unwrap(), b"secret");
}

/// What the background check relies on: a lock removed outside DirShield
/// (here the way `icacls <folder> /remove:d *S-1-1-0` does it) is detected
/// and can be put back without a password.
#[test]
fn removed_lock_is_detected_and_reapplied() {
    let t = tempfile::tempdir().unwrap();
    let folder = t.path().join("Tampered");
    make(&folder);
    let st = quicklock::lock(&folder, None, "tamp1", false, None).unwrap();
    assert!(acl::is_restricted(&folder).unwrap());

    let out = std::process::Command::new("icacls").arg(&folder).args(["/remove:d", "*S-1-1-0"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    assert!(!acl::is_restricted(&folder).unwrap());
    assert_eq!(fs::read(folder.join("sub").join("secret.txt")).unwrap(), b"secret");

    acl::apply_deny(&folder).unwrap();
    assert!(acl::is_restricted(&folder).unwrap());
    assert!(fs::read(folder.join("sub").join("secret.txt")).is_err());

    quicklock::unlock(&st, &folder, None).unwrap();
    assert_eq!(fs::read(folder.join("sub").join("secret.txt")).unwrap(), b"secret");
}

/// The deny ACE can't stop a rename by someone who may delete children of the
/// parent folder; DirShield finds the folder again by its file id.
#[test]
fn renamed_locked_folder_is_found_again() {
    let t = tempfile::tempdir().unwrap();
    let folder = t.path().join("Renamable");
    make(&folder);
    let mut st = quicklock::lock(&folder, None, "ren1", false, None).unwrap();
    assert!(st.file_id.is_some());
    assert_eq!(quicklock::relocate(&mut st), quicklock::Relocated::No);

    let renamed = t.path().join("Renamed");
    fs::rename(&folder, &renamed).expect("Windows allows renaming a Quick-Locked folder");
    assert_eq!(quicklock::relocate(&mut st), quicklock::Relocated::Moved);
    assert_eq!(fsutil::path_key(std::path::Path::new(&st.current_path)), fsutil::path_key(&fsutil::normalize(&renamed).unwrap()));
    assert!(acl::is_restricted(&renamed).unwrap());

    let back = quicklock::unlock(&st, &folder, None).unwrap();
    assert_eq!(fsutil::path_key(&back), fsutil::path_key(std::path::Path::new(&st.current_path)));
    assert_eq!(fs::read(renamed.join("sub").join("secret.txt")).unwrap(), b"secret");
}

/// Locks recorded before file ids existed get one on their first check.
#[test]
fn old_locks_get_a_file_id() {
    let t = tempfile::tempdir().unwrap();
    let folder = t.path().join("Old");
    make(&folder);
    let mut st = quicklock::lock(&folder, None, "old1", false, None).unwrap();
    st.file_id = None;
    assert_eq!(quicklock::relocate(&mut st), quicklock::Relocated::Updated);
    assert!(st.file_id.is_some());
    quicklock::unlock(&st, &folder, None).unwrap();
}

/// While DirShield holds a locked folder it can't be renamed, moved (the
/// Recycle Bin is a move) or deleted, and it stays unreadable.
#[test]
fn held_folder_cannot_be_renamed_or_deleted() {
    let t = tempfile::tempdir().unwrap();
    let folder = t.path().join("Held");
    make(&folder);
    let st = quicklock::lock(&folder, None, "held1", false, None).unwrap();
    let path = st.current_path.clone();
    quicklock::hold("held1", &path).unwrap();
    // The folder's own restriction is back in full after pinning.
    assert!(acl::is_restricted(&folder).unwrap());
    assert!(fs::read_dir(&folder).is_err());
    assert!(fs::rename(&folder, t.path().join("Elsewhere")).is_err());
    assert!(fs::remove_dir_all(&folder).is_err());
    assert!(folder.is_dir());

    quicklock::release("held1");
    quicklock::unlock(&st, &folder, None).unwrap();
    assert_eq!(fs::read(folder.join("sub").join("secret.txt")).unwrap(), b"secret");
    fs::rename(&folder, t.path().join("Elsewhere")).unwrap();
}
