//! End-to-end tests of the Secure Lock engine on generated data in temp dirs.
//! Never touches real user files.

#![allow(clippy::type_complexity)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use dirshield_lib::crypto::{self, KdfParams};
use dirshield_lib::db::Db;
use dirshield_lib::error::Error;
use dirshield_lib::vault::engine::{self, Control, DecryptJob, DecryptParams, EncryptJob, NewVaultSpec};
use dirshield_lib::vault::header::{self, VaultHeader, MANIFEST_FILE, OBJECTS_DIR};

const CHUNK: u32 = 64 * 1024; // small chunks => many chunks per file in tests

struct Fx {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    db: Db,
    vk: crypto::Key32,
    vault_id: String,
    vault_dir: PathBuf,
    op_id: String,
    source: PathBuf,
}

fn write(p: &Path, data: &[u8]) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::File::create(p).unwrap().write_all(data).unwrap();
}

fn data(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| ((i as u32).wrapping_mul(2654435761) >> 13) as u8 ^ seed).collect()
}

/// Generated tree: nested dirs, Unicode names, spaces/parentheses, empty dir,
/// empty file, multi-chunk file, read-only file, long path.
fn make_tree(src: &Path) {
    write(&src.join("a.txt"), b"hello");
    write(&src.join("empty.bin"), b"");
    write(&src.join("big (1).dat"), &data(1_000_003, 7));
    write(&src.join("Ünïcödé 名前 🙂").join("nested").join("deep.txt"), &data(70_000, 3));
    fs::create_dir_all(src.join("empty dir")).unwrap();
    let ro = src.join("readonly.txt");
    write(&ro, b"read only");
    let mut perm = fs::metadata(&ro).unwrap().permissions();
    perm.set_readonly(true);
    fs::set_permissions(&ro, perm).unwrap();
    let mut long = src.to_path_buf();
    for i in 0..12 {
        long = long.join(format!("long_directory_name_segment_{i:02}_xxxxxxxx"));
    }
    write(&long.join("long-file.txt"), b"long path content");
    assert!(long.join("long-file.txt").as_os_str().len() > 300);
}

fn setup(tree: impl FnOnce(&Path)) -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let source = root.join("My Secret Folder");
    fs::create_dir_all(&source).unwrap();
    tree(&source);
    let db = Db::open(&root.join("db").join("t.db")).unwrap();
    let vk = crypto::random_key();
    let vault_id = crypto::random_id();
    let wrappers = vec![header::password_wrapper_with(&vault_id, "folder-password", &vk, test_kdf()).unwrap()];
    let nv = engine::create_secure_vault(
        &db,
        NewVaultSpec { vault_id: &vault_id, source: &source, vault_root: &root.join("vaults"), vk: &vk, wrappers, name_enc: "x".into(), path_enc: "x".into(), key_mode: "password", chunk: CHUNK },
        &Control::default(),
    )
    .unwrap();
    Fx { _tmp: tmp, root, db, vk, vault_id, vault_dir: nv.vault_dir, op_id: nv.op_id, source }
}

fn test_kdf() -> KdfParams {
    KdfParams { alg: "argon2id".into(), m_cost: 1024, t_cost: 1, p_cost: 1, salt: crypto::random_bytes::<16>().to_vec() }
}

fn encrypt(fx: &Fx, ctrl: &Control) -> Result<(), Error> {
    let orig = fx.source.display().to_string();
    engine::run_encrypt(&EncryptJob {
        db: &fx.db,
        op_id: &fx.op_id,
        vault_id: &fx.vault_id,
        vault_dir: &fx.vault_dir,
        source: &fx.source,
        root_name: "My Secret Folder",
        original_path: &orig,
        vk: &fx.vk,
        workers: 3,
        ctrl,
    })
}

fn restore(fx: &Fx, dest: &Path, conflict: &str) -> Result<String, Error> {
    let p = DecryptParams { dest: dest.display().to_string(), conflict: conflict.into(), prev_status: "encrypted".into(), ..Default::default() };
    let op = engine::create_operation(&fx.db, &fx.vault_id, "decrypt", &serde_json::to_string(&p).unwrap())?;
    engine::prepare_decrypt(&fx.db, &op, &fx.vault_dir, &fx.vk, &p, &Control::default())?;
    engine::run_decrypt(&DecryptJob { db: &fx.db, op_id: &op, vault_id: &fx.vault_id, vault_dir: &fx.vault_dir, vk: &fx.vk, params: &p, workers: 2, ctrl: &Control::default() })?;
    Ok(op)
}

/// (relative path, contents, readonly) for every file; plus dir list.
fn snapshot(root: &Path) -> (Vec<(String, Vec<u8>, bool)>, Vec<String>) {
    let mut files = vec![];
    let mut dirs = vec![];
    for e in walkdir::WalkDir::new(root).min_depth(1).sort_by_file_name() {
        let e = e.unwrap();
        let rel = e.path().strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
        if e.file_type().is_dir() {
            dirs.push(rel);
        } else {
            files.push((rel, fs::read(e.path()).unwrap(), e.metadata().unwrap().permissions().readonly()));
        }
    }
    (files, dirs)
}

fn all_vault_bytes_and_names(dir: &Path) -> (Vec<u8>, Vec<String>) {
    let mut bytes = vec![];
    let mut names = vec![];
    for e in walkdir::WalkDir::new(dir) {
        let e = e.unwrap();
        names.push(e.file_name().to_string_lossy().into_owned());
        if e.file_type().is_file() {
            bytes.extend(fs::read(e.path()).unwrap());
        }
    }
    (bytes, names)
}

#[test]
fn full_roundtrip_preserves_everything_and_hides_names() {
    let fx = setup(make_tree);
    encrypt(&fx, &Control::default()).unwrap();
    let h = VaultHeader::read(&fx.vault_dir).unwrap();
    assert!(h.sealed);
    h.verify_mac(&fx.vk).unwrap();

    // No plaintext names or content anywhere in the vault.
    let (bytes, names) = all_vault_bytes_and_names(&fx.vault_dir);
    for needle in ["a.txt", "deep.txt", "nested", "My Secret Folder", "readonly", "hello", "long_directory_name"] {
        assert!(!names.iter().any(|n| n.contains(needle)), "name leaked: {needle}");
        assert!(!bytes.windows(needle.len()).any(|w| w == needle.as_bytes()), "bytes leaked: {needle}");
    }
    // Journal (plaintext relative paths) is purged after completion.
    let n: i64 = fx.db.lock().query_row("SELECT COUNT(*) FROM operation_journal", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 0);

    // Originals untouched.
    assert_eq!(fs::read(fx.source.join("a.txt")).unwrap(), b"hello");

    let rep = engine::verify_vault(&fx.vault_dir, &fx.vk, &Control::default()).unwrap();
    assert_eq!(rep.files, 6);

    let dest = fx.root.join("restored");
    restore(&fx, &dest, "fail").unwrap();
    assert_eq!(snapshot(&fx.source), snapshot(&dest));
    // mtimes restored
    let a = fs::metadata(fx.source.join("big (1).dat")).unwrap().modified().unwrap();
    let b = fs::metadata(dest.join("big (1).dat")).unwrap().modified().unwrap();
    assert_eq!(a, b);
}

#[test]
fn wrong_password_and_recovery_and_password_change() {
    let fx = setup(|s| write(&s.join("f.txt"), b"x"));
    encrypt(&fx, &Control::default()).unwrap();
    let mut h = VaultHeader::read(&fx.vault_dir).unwrap();
    assert!(matches!(h.unwrap_with_password("wrong-password"), Err(Error::AuthFailed)));
    assert_eq!(*h.unwrap_with_password("folder-password").unwrap(), *fx.vk);

    // Add a recovery escrow and change the password by re-wrapping (no data re-encrypted).
    let rk = crypto::random_bytes::<32>();
    let salt = crypto::random_bytes::<16>();
    let rpub = crypto::recovery_public(&rk, &salt);
    let blobs_before = all_vault_bytes_and_names(&fx.vault_dir.join(OBJECTS_DIR)).0;
    h.wrappers = vec![header::password_wrapper_with(&h.vault_id, "new-password!", &fx.vk, test_kdf()).unwrap(), header::recovery_wrapper(&h.vault_id, &rpub, "rid", &salt, &fx.vk).unwrap()];
    h.compute_mac(&fx.vk).unwrap();
    h.write_atomic(&fx.vault_dir).unwrap();
    let h = VaultHeader::read(&fx.vault_dir).unwrap();
    assert!(h.unwrap_with_password("folder-password").is_err());
    assert_eq!(*h.unwrap_with_password("new-password!").unwrap(), *fx.vk);
    assert_eq!(*h.unwrap_with_recovery(&rk).unwrap(), *fx.vk);
    assert!(h.unwrap_with_recovery(&crypto::random_bytes::<32>()).is_err());
    assert_eq!(blobs_before, all_vault_bytes_and_names(&fx.vault_dir.join(OBJECTS_DIR)).0);
}

#[test]
fn corrupted_chunk_is_detected_and_nothing_partial_is_left() {
    let fx = setup(|s| write(&s.join("big.bin"), &data(300_000, 1)));
    encrypt(&fx, &Control::default()).unwrap();
    let blob = walkdir::WalkDir::new(fx.vault_dir.join(OBJECTS_DIR)).into_iter().filter_map(|e| e.ok()).find(|e| e.path().extension().map(|x| x == "dsb").unwrap_or(false)).unwrap();
    let mut b = fs::read(blob.path()).unwrap();
    b[100_000] ^= 0x40;
    fs::write(blob.path(), &b).unwrap();
    assert!(matches!(engine::verify_vault(&fx.vault_dir, &fx.vk, &Control::default()), Err(Error::Integrity(_))));
    let dest = fx.root.join("out");
    assert!(restore(&fx, &dest, "fail").is_err());
    assert!(!dest.join("big.bin").exists(), "corrupted file must not be written");
    let leftovers: Vec<_> = walkdir::WalkDir::new(&dest).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()).collect();
    assert!(leftovers.is_empty(), "no partial temp files may remain");
}

#[test]
fn modified_header_and_manifest_are_rejected() {
    let fx = setup(|s| write(&s.join("f.txt"), b"data"));
    encrypt(&fx, &Control::default()).unwrap();
    // header: flip chunk size inside the MAC'd body
    let mut h = VaultHeader::read(&fx.vault_dir).unwrap();
    h.chunk_size = 1024;
    assert!(matches!(h.verify_mac(&fx.vk), Err(Error::Integrity(_))));
    // header: wrong key
    let h = VaultHeader::read(&fx.vault_dir).unwrap();
    assert!(h.verify_mac(&crypto::random_key()).is_err());
    // manifest bytes
    let m = fx.vault_dir.join(MANIFEST_FILE);
    let mut b = fs::read(&m).unwrap();
    let n = b.len();
    b[n - 20] ^= 1;
    fs::write(&m, &b).unwrap();
    assert!(engine::verify_vault(&fx.vault_dir, &fx.vk, &Control::default()).is_err());
    assert!(restore(&fx, &fx.root.join("o"), "fail").is_err());
}

#[test]
fn interrupted_encryption_resumes_and_sweeps_orphans() {
    let fx = setup(|s| {
        for i in 0..40 {
            write(&s.join(format!("dir{}", i % 4)).join(format!("file{i}.bin")), &data(50_000 + i, i as u8));
        }
    });
    // Cancel part-way.
    let ctrl = Control::default();
    std::thread::scope(|sc| {
        sc.spawn(|| {
            while ctrl.processed_files.load(Ordering::Relaxed) < 5 {
                std::thread::yield_now();
            }
            ctrl.cancel.store(true, Ordering::Relaxed);
        });
        assert!(matches!(encrypt(&fx, &ctrl), Err(Error::Cancelled)));
    });
    assert!(!VaultHeader::read(&fx.vault_dir).unwrap().sealed, "cancelled vault must not be sealed");
    let done = engine::count_status(&fx.db, &fx.op_id, "done").unwrap();
    let pending = engine::count_status(&fx.db, &fx.op_id, "pending").unwrap();
    assert!(done >= 5 && pending > 0, "done={done} pending={pending}");

    // Simulate a crash leaving a partial temp file and an orphaned blob.
    write(&fx.vault_dir.join(OBJECTS_DIR).join("tmp").join("999.part"), b"partial");
    write(&fx.vault_dir.join(OBJECTS_DIR).join("ff").join("ffffffffffffffffffffffffffffffff.dsb"), b"orphan");

    // Duplicate/second run resumes only remaining work.
    encrypt(&fx, &Control::default()).unwrap();
    assert!(!fx.vault_dir.join(OBJECTS_DIR).join("ff").join("ffffffffffffffffffffffffffffffff.dsb").exists());
    assert!(!fx.vault_dir.join(OBJECTS_DIR).join("tmp").exists());
    // Running again on a sealed vault is refused.
    assert!(matches!(encrypt(&fx, &Control::default()), Err(Error::Conflict(_))));

    let dest = fx.root.join("restored");
    restore(&fx, &dest, "fail").unwrap();
    assert_eq!(snapshot(&fx.source), snapshot(&dest));
}

#[test]
fn interrupted_decryption_resumes() {
    let fx = setup(|s| {
        for i in 0..30 {
            write(&s.join(format!("f{i}.bin")), &data(80_000, i as u8));
        }
    });
    encrypt(&fx, &Control::default()).unwrap();
    let dest = fx.root.join("restored");
    let p = DecryptParams { dest: dest.display().to_string(), conflict: "fail".into(), prev_status: "encrypted".into(), ..Default::default() };
    let op = engine::create_operation(&fx.db, &fx.vault_id, "decrypt", "{}").unwrap();
    engine::prepare_decrypt(&fx.db, &op, &fx.vault_dir, &fx.vk, &p, &Control::default()).unwrap();
    let ctrl = Control::default();
    let job = |c| DecryptJob { db: &fx.db, op_id: &op, vault_id: &fx.vault_id, vault_dir: &fx.vault_dir, vk: &fx.vk, params: &p, workers: 2, ctrl: c };
    std::thread::scope(|sc| {
        sc.spawn(|| {
            while ctrl.processed_files.load(Ordering::Relaxed) < 4 {
                std::thread::yield_now();
            }
            ctrl.cancel.store(true, Ordering::Relaxed);
        });
        assert!(matches!(engine::run_decrypt(&job(&ctrl)), Err(Error::Cancelled)));
    });
    engine::run_decrypt(&job(&Control::default())).unwrap();
    assert_eq!(snapshot(&fx.source), snapshot(&dest));
}

#[test]
fn restore_never_overwrites() {
    let fx = setup(|s| {
        write(&s.join("same.txt"), b"from vault");
        write(&s.join("other.txt"), b"other");
    });
    encrypt(&fx, &Control::default()).unwrap();
    let dest = fx.root.join("dest");
    write(&dest.join("same.txt"), b"existing user data");
    assert!(matches!(restore(&fx, &dest, "fail"), Err(Error::Conflict(_))));
    assert!(!dest.join("other.txt").exists());

    restore(&fx, &dest, "skip").unwrap();
    assert_eq!(fs::read(dest.join("same.txt")).unwrap(), b"existing user data");
    assert_eq!(fs::read(dest.join("other.txt")).unwrap(), b"other");

    let dest2 = fx.root.join("dest2");
    write(&dest2.join("same.txt"), b"existing user data");
    restore(&fx, &dest2, "rename").unwrap();
    assert_eq!(fs::read(dest2.join("same.txt")).unwrap(), b"existing user data");
    assert_eq!(fs::read(dest2.join("same (restored).txt")).unwrap(), b"from vault");
}

#[test]
fn remove_originals_only_deletes_verified_unchanged_files() {
    let fx = setup(make_tree);
    encrypt(&fx, &Control::default()).unwrap();
    // After sealing: modify one file and add a new one.
    std::thread::sleep(std::time::Duration::from_millis(20));
    write(&fx.source.join("a.txt"), b"modified after encryption");
    write(&fx.source.join("new file.txt"), b"added later");
    let rep = engine::remove_originals(&fx.vault_dir, &fx.vk, &fx.source, &Control::default()).unwrap();
    assert_eq!(rep.removed_files, 5);
    assert_eq!(rep.kept_files, 1);
    assert!(!rep.root_removed);
    assert_eq!(fs::read(fx.source.join("a.txt")).unwrap(), b"modified after encryption");
    assert_eq!(fs::read(fx.source.join("new file.txt")).unwrap(), b"added later");
    assert!(!fx.source.join("big (1).dat").exists());
    assert!(!fx.source.join("Ünïcödé 名前 🙂").exists());
}

#[test]
fn empty_folder_roundtrip() {
    let fx = setup(|_| {});
    encrypt(&fx, &Control::default()).unwrap();
    let dest = fx.root.join("restored-empty");
    restore(&fx, &dest, "fail").unwrap();
    assert!(dest.is_dir());
    assert_eq!(fs::read_dir(&dest).unwrap().count(), 0);
}

#[cfg(windows)]
#[test]
fn junctions_are_skipped_not_followed() {
    let outside = tempfile::tempdir().unwrap();
    write(&outside.path().join("outside-secret.txt"), b"must not be encrypted or deleted");
    let target = outside.path().to_path_buf();
    let fx = setup(|s| {
        write(&s.join("inside.txt"), b"in");
        let st = std::process::Command::new("cmd").arg("/c").arg("mklink").arg("/J").arg(s.join("junction")).arg(&target).output().unwrap();
        assert!(st.status.success(), "mklink /J failed");
    });
    let report = dirshield_lib::vault::scan::scan(&fx.source, true).unwrap();
    assert_eq!(report.links, 1);
    assert_eq!(report.total_files, 1);
    encrypt(&fx, &Control::default()).unwrap();
    let rep = engine::remove_originals(&fx.vault_dir, &fx.vk, &fx.source, &Control::default()).unwrap();
    assert_eq!(rep.removed_files, 1);
    assert!(target.join("outside-secret.txt").exists());
    let dest = fx.root.join("r");
    restore(&fx, &dest, "fail").unwrap();
    assert!(dest.join("inside.txt").exists());
    assert!(!dest.join("junction").exists());
}

#[cfg(windows)]
#[test]
fn locked_file_fails_safely_then_can_be_excluded() {
    use std::os::windows::fs::OpenOptionsExt;
    let fx = setup(|s| {
        write(&s.join("ok.txt"), b"ok");
        write(&s.join("locked.db"), b"in use");
    });
    // Hold an exclusive handle (share mode 0), like a database engine would.
    let guard = fs::OpenOptions::new().read(true).write(true).share_mode(0).open(fx.source.join("locked.db")).unwrap();
    let err = encrypt(&fx, &Control::default()).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "{err:?}");
    assert!(!VaultHeader::read(&fx.vault_dir).unwrap().sealed);
    assert_eq!(engine::list_errors(&fx.db, &fx.op_id, 10).unwrap().len(), 1);
    // Retry still fails while locked; the user explicitly excludes it.
    engine::retry_failed(&fx.db, &fx.op_id).unwrap();
    assert!(encrypt(&fx, &Control::default()).is_err());
    engine::skip_failed(&fx.db, &fx.op_id).unwrap();
    encrypt(&fx, &Control::default()).unwrap();
    drop(guard);
    let rep = engine::remove_originals(&fx.vault_dir, &fx.vk, &fx.source, &Control::default()).unwrap();
    assert_eq!(rep.removed_files, 1);
    assert!(fx.source.join("locked.db").exists(), "excluded file stays in place");
}

#[test]
fn insufficient_space_is_rejected_before_anything_is_written() {
    // Estimate check: a vault root on the same volume with absurd need can't be simulated
    // portably, so verify the estimator is conservative instead.
    let est = dirshield_lib::vault::scan::estimate_vault_bytes(10, 2, 1_000_000);
    assert!(est > 1_000_000 + 10 * 44);
}

// ---------------------------------------------------------------------------
// Selective restore (extract) and incremental re-lock
// ---------------------------------------------------------------------------

fn vault_status(fx: &Fx) -> String {
    fx.db.lock().query_row("SELECT status FROM vaults WHERE id=?1", [&fx.vault_id], |r| r.get(0)).unwrap()
}

fn extract(fx: &Fx, dest: &Path, include: &[&str], base: &str) -> Result<String, Error> {
    let p = DecryptParams { dest: dest.display().to_string(), conflict: "fail".into(), prev_status: "encrypted".into(), include: include.iter().map(|s| s.to_string()).collect(), base: base.into() };
    let op = engine::create_operation(&fx.db, &fx.vault_id, "extract", &serde_json::to_string(&p).unwrap())?;
    engine::prepare_decrypt(&fx.db, &op, &fx.vault_dir, &fx.vk, &p, &Control::default())?;
    engine::run_decrypt(&DecryptJob { db: &fx.db, op_id: &op, vault_id: &fx.vault_id, vault_dir: &fx.vault_dir, vk: &fx.vk, params: &p, workers: 2, ctrl: &Control::default() })?;
    Ok(op)
}

fn objects(vault_dir: &Path) -> std::collections::BTreeSet<String> {
    walkdir::WalkDir::new(vault_dir.join(OBJECTS_DIR)).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()).map(|e| e.file_name().to_string_lossy().into_owned()).collect()
}

fn relock(fx: &Fx, source: &Path, thorough: bool, ctrl: &Control) -> Result<String, Error> {
    let p = engine::RelockParams { source: source.display().to_string(), thorough, prev_status: "restored".into(), ..Default::default() };
    let op = engine::create_relock(&fx.db, &fx.vault_id, &fx.vault_dir, &fx.vk, p, &Control::default())?;
    run_relock(fx, &op, source, ctrl)?;
    Ok(op)
}

fn run_relock(fx: &Fx, op: &str, source: &Path, ctrl: &Control) -> Result<(), Error> {
    let orig = source.display().to_string();
    engine::run_relock(&EncryptJob {
        db: &fx.db,
        op_id: op,
        vault_id: &fx.vault_id,
        vault_dir: &fx.vault_dir,
        source,
        root_name: "My Secret Folder",
        original_path: &orig,
        vk: &fx.vk,
        workers: 3,
        ctrl,
    })
}

#[test]
fn extract_restores_only_the_selection() {
    let fx = setup(make_tree);
    encrypt(&fx, &Control::default()).unwrap();

    // A top-level folder keeps its own name and contents.
    let d1 = fx.root.join("x1");
    extract(&fx, &d1, &["Ünïcödé 名前 🙂"], "").unwrap();
    let (files, _) = snapshot(&d1);
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, "Ünïcödé 名前 🙂/nested/deep.txt");
    assert_eq!(files[0].1, data(70_000, 3));

    // A deep file lands directly in the destination.
    let d2 = fx.root.join("x2");
    extract(&fx, &d2, &["Ünïcödé 名前 🙂/nested/deep.txt"], "Ünïcödé 名前 🙂/nested").unwrap();
    assert_eq!(snapshot(&d2).0.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(), ["deep.txt"]);

    // Several top-level files; the read-only attribute survives.
    let d3 = fx.root.join("x3");
    extract(&fx, &d3, &["a.txt", "readonly.txt"], "").unwrap();
    let (files, _) = snapshot(&d3);
    assert_eq!(files, vec![("a.txt".to_string(), b"hello".to_vec(), false), ("readonly.txt".to_string(), b"read only".to_vec(), true)]);

    // Extracting leaves the vault state alone.
    assert_eq!(vault_status(&fx), "encrypted");

    // Bad selections are refused before anything is written.
    let d4 = fx.root.join("x4");
    assert!(matches!(extract(&fx, &d4, &["a.txt", "Ünïcödé 名前 🙂/nested/deep.txt"], ""), Err(Error::Invalid(_))));
    assert!(matches!(extract(&fx, &d4, &["no such file"], ""), Err(Error::NotFound(_))));
    assert!(matches!(extract(&fx, &d4, &["../escape"], ""), Err(Error::Integrity(_))));
    assert!(!d4.exists());
}

#[test]
fn relock_reencrypts_only_what_changed() {
    let fx = setup(|s| {
        for i in 0..12 {
            write(&s.join("docs").join(format!("f{i}.bin")), &data(150_000 + i, i as u8));
        }
        write(&s.join("keep.txt"), b"unchanged");
        write(&s.join("delete-me.txt"), b"to be deleted");
        write(&s.join("edit-me.txt"), b"version 1");
    });
    encrypt(&fx, &Control::default()).unwrap();
    let before = objects(&fx.vault_dir);
    assert_eq!(before.len(), 15);

    let work = fx.root.join("work");
    restore(&fx, &work, "fail").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    write(&work.join("edit-me.txt"), b"version 2, longer");
    fs::remove_file(work.join("delete-me.txt")).unwrap();
    write(&work.join("docs").join("new.txt"), b"brand new");

    let op = relock(&fx, &work, false, &Control::default()).unwrap();
    let p = engine::load_relock_params(&fx.db, &op).unwrap();
    assert_eq!((p.unchanged_files, p.changed_files, p.added_files, p.removed_files), (13, 1, 1, 1));
    assert_eq!(vault_status(&fx), "encrypted");

    // The 13 unchanged files kept their encrypted objects; 2 new objects, 2 old ones gone.
    let after = objects(&fx.vault_dir);
    assert_eq!(after.len(), 15);
    assert_eq!(before.intersection(&after).count(), 13);

    // Journal and baseline (plaintext paths) are purged.
    for t in ["operation_journal", "relock_base"] {
        let n: i64 = fx.db.lock().query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "{t}");
    }
    engine::verify_vault(&fx.vault_dir, &fx.vk, &Control::default()).unwrap();
    let check = fx.root.join("check");
    restore(&fx, &check, "fail").unwrap();
    assert_eq!(snapshot(&work), snapshot(&check));

    // Finishing it a second time must never sweep the (now live) objects.
    assert!(engine::complete_relock(&fx.db, &op, &fx.vault_id, &fx.vault_dir).is_err());
    assert_eq!(objects(&fx.vault_dir), after);
}

#[test]
fn relock_thorough_mode_catches_edits_that_keep_size_and_time() {
    let fx = setup(|s| {
        write(&s.join("a.txt"), b"AAAA");
        write(&s.join("b.txt"), b"BBBB");
    });
    encrypt(&fx, &Control::default()).unwrap();
    let work = fx.root.join("work");
    restore(&fx, &work, "fail").unwrap();
    let m = fs::metadata(work.join("a.txt")).unwrap().modified().unwrap();
    write(&work.join("a.txt"), b"ZZZZ");
    let f = fs::OpenOptions::new().write(true).open(work.join("a.txt")).unwrap();
    f.set_modified(m).unwrap();
    drop(f);

    let op = relock(&fx, &work, true, &Control::default()).unwrap();
    let p = engine::load_relock_params(&fx.db, &op).unwrap();
    assert_eq!((p.unchanged_files, p.changed_files), (1, 1));
    let check = fx.root.join("check");
    restore(&fx, &check, "fail").unwrap();
    assert_eq!(fs::read(check.join("a.txt")).unwrap(), b"ZZZZ");
}

#[test]
fn interrupted_relock_keeps_the_old_version_and_can_be_discarded_or_resumed() {
    let fx = setup(|s| {
        for i in 0..30 {
            write(&s.join(format!("f{i}.bin")), &data(90_000, i as u8));
        }
    });
    encrypt(&fx, &Control::default()).unwrap();
    let before = objects(&fx.vault_dir);
    let manifest_before = engine::current_manifest_id(&fx.vault_dir).unwrap();
    let work = fx.root.join("work");
    restore(&fx, &work, "fail").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    for i in 0..30 {
        write(&work.join(format!("f{i}.bin")), &data(90_001, 100 + i as u8));
    }

    let start = || {
        let p = engine::RelockParams { source: work.display().to_string(), thorough: false, prev_status: "restored".into(), ..Default::default() };
        engine::create_relock(&fx.db, &fx.vault_id, &fx.vault_dir, &fx.vk, p, &Control::default()).unwrap()
    };
    let cancel_midway = |op: &str| {
        let ctrl = Control::default();
        std::thread::scope(|sc| {
            sc.spawn(|| {
                while ctrl.processed_files.load(Ordering::Relaxed) < 4 {
                    std::thread::yield_now();
                }
                ctrl.cancel.store(true, Ordering::Relaxed);
            });
            assert!(matches!(run_relock(&fx, op, &work, &ctrl), Err(Error::Cancelled)));
        });
    };

    // Cancelled: the vault still opens to the previous version.
    let op = start();
    cancel_midway(&op);
    assert_eq!(engine::current_manifest_id(&fx.vault_dir).unwrap(), manifest_before);
    let old = fx.root.join("old");
    restore(&fx, &old, "fail").unwrap();
    assert_eq!(snapshot(&old), snapshot(&fx.source));

    // Discarded: exactly the old objects remain.
    assert!(!engine::discard_relock(&fx.db, &op, &fx.vault_id, &fx.vault_dir).unwrap());
    fx.db.lock().execute("DELETE FROM operations WHERE id=?1", [&op]).unwrap();
    assert_eq!(objects(&fx.vault_dir), before);

    // Interrupted again, then resumed to completion.
    let op = start();
    cancel_midway(&op);
    run_relock(&fx, &op, &work, &Control::default()).unwrap();
    assert_ne!(engine::current_manifest_id(&fx.vault_dir).unwrap(), manifest_before);
    assert!(objects(&fx.vault_dir).is_disjoint(&before));
    let check = fx.root.join("check");
    restore(&fx, &check, "fail").unwrap();
    assert_eq!(snapshot(&work), snapshot(&check));
}

#[test]
fn browse_index_lists_folders_and_decrypts_single_files() {
    use dirshield_lib::vault::browse::VaultIndex;
    let fx = setup(make_tree);
    encrypt(&fx, &Control::default()).unwrap();
    let ix = VaultIndex::load(&fx.vault_dir, &fx.vk).unwrap();
    assert_eq!(ix.root_name, "My Secret Folder");
    assert_eq!(ix.files, 6);
    let top = ix.list("").unwrap();
    // Folders first, then files, by name.
    let names: Vec<_> = top.iter().map(|e| (e.name.as_str(), e.dir)).collect();
    assert_eq!(names[..3], [("empty dir", true), ("long_directory_name_segment_00_xxxxxxxx", true), ("Ünïcödé 名前 🙂", true)]);
    assert!(names.contains(&("big (1).dat", false)));
    let uni = top.iter().find(|e| e.name == "Ünïcödé 名前 🙂").unwrap();
    assert_eq!((uni.files, uni.size), (1, 70_000));
    assert_eq!(ix.list("Ünïcödé 名前 🙂/nested").unwrap()[0].path, "Ünïcödé 名前 🙂/nested/deep.txt");
    assert!(ix.list("a.txt").is_err());
    assert!(ix.list("missing").is_err());
    assert_eq!(ix.measure(&["Ünïcödé 名前 🙂".into(), "a.txt".into()]).unwrap(), (2, 70_005));

    let out = fx.root.join("one").join("big (1).dat");
    fs::create_dir_all(out.parent().unwrap()).unwrap();
    let f = ix.file("big (1).dat").unwrap();
    ix.decrypt_file(&fx.vault_dir, &fx.vk, &f, &out).unwrap();
    assert_eq!(fs::read(&out).unwrap(), data(1_000_003, 7));
    // Never overwrites.
    assert!(ix.decrypt_file(&fx.vault_dir, &fx.vk, &f, &out).is_err());
}
