//! Journaled, resumable vault operations.
//!
//! Every operation is backed by rows in `operations` + `operation_journal`, so
//! a crash, power loss or cancellation leaves a state that can be resumed or
//! rolled back. Content is processed in bounded memory: each worker holds one
//! 1 MiB read buffer and one 4 MiB chunk; at most `workers` files are open.
//!
//! Encryption never touches the originals. A vault is only marked sealed after
//! every journaled item has been encrypted, written, flushed, re-read and
//! verified, and the encrypted manifest has itself been verified.

const READ_BUF: usize = 1024 * 1024;
const PAGE: i64 = 1000;
const BATCH: usize = 2000;

mod cleanup;
mod control;
mod encrypt;
mod journal;
mod relock;
mod restore;
mod verify;

pub use cleanup::{remove_originals, CleanupReport};
pub use control::Control;
pub use encrypt::{create_secure_vault, current_manifest_id, discard_vault_storage, run_encrypt, EncryptJob, EncryptParams, NewVault, NewVaultSpec};
pub use journal::{blob_path, count_status, create_operation, list_errors, load_counters, retry_failed, save_op_progress, set_op_status, set_vault_status, skip_failed, Item, ItemError, Outcome};
pub use relock::{complete_relock, create_relock, discard_relock, load_relock_params, run_relock, RelockParams};
pub use restore::{prepare_decrypt, run_decrypt, DecryptJob, DecryptParams};
pub use verify::{manifest_summary, verify_vault, VerifyReport};
