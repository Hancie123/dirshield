//! NTFS access restriction used by Quick Lock.
//!
//! We add one explicit, inheritable *deny* ACE for Everyone (S-1-1-0) covering
//! reading, listing, traversing, writing and deleting. Because it is inherited
//! by every child, files cannot be opened even by full path.
//!
//! Recoverability: the folder's owner always keeps READ_CONTROL and WRITE_DAC
//! (implicit owner rights), so DirShield, running as the same user, can always
//! remove the ACE again - no administrator rights needed. Administrators can
//! also take ownership. We never change the owner and never remove existing
//! allow ACEs, so removing our ACE restores the original permissions exactly.
//!
//! This is an access-control measure, NOT encryption: an administrator, another
//! OS, or offline disk access can bypass it.

use std::path::Path;

use crate::error::{Error, Result};

/// RD | WD/AD | AD/AS | REA | WEA | X/TRAVERSE | DC | DELETE
pub const DENY_MASK: u32 = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0001_0000;

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::fsutil::wide;
    use std::ffi::c_void;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
    use windows::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, DENY_ACCESS, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID,
        TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        CreateWellKnownSid, DeleteAce, EqualSid, GetAce, GetAclInformation, WinWorldSid, AclSizeInformation, ACCESS_DENIED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION,
        DACL_SECURITY_INFORMATION, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    };

    const ACCESS_DENIED_ACE_TYPE: u8 = 1;
    const INHERITED_ACE: u8 = 0x10;

    fn everyone_sid() -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 68];
        let mut size = buf.len() as u32;
        unsafe { CreateWellKnownSid(WinWorldSid, None, Some(PSID(buf.as_mut_ptr() as *mut c_void)), &mut size) }.map_err(|e| Error::Win(format!("CreateWellKnownSid: {e}")))?;
        buf.truncate(size as usize);
        Ok(buf)
    }

    struct Sd(PSECURITY_DESCRIPTOR);
    impl Drop for Sd {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
            }
        }
    }

    fn get_dacl(path: &Path) -> Result<(Sd, *mut ACL)> {
        let w = wide(path);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let rc = unsafe { GetNamedSecurityInfoW(PCWSTR(w.as_ptr()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, None, None, Some(&mut dacl), None, &mut sd) };
        if rc != ERROR_SUCCESS {
            return Err(Error::Win(format!("GetNamedSecurityInfo failed ({})", rc.0)));
        }
        Ok((Sd(sd), dacl))
    }

    fn set_dacl(path: &Path, dacl: *const ACL) -> Result<()> {
        let w = wide(path);
        let rc = unsafe {
            SetNamedSecurityInfoW(PCWSTR(w.as_ptr()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, None, None, Some(dacl), None)
        };
        if rc != ERROR_SUCCESS {
            return Err(Error::Win(format!("SetNamedSecurityInfo failed ({})", rc.0)));
        }
        Ok(())
    }

    /// Index list of our explicit deny ACEs in `dacl`.
    fn find_ours(dacl: *mut ACL, sid: &[u8]) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        if dacl.is_null() {
            return Ok(out);
        }
        let mut info = ACL_SIZE_INFORMATION::default();
        unsafe { GetAclInformation(dacl, &mut info as *mut _ as *mut c_void, std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32, AclSizeInformation) }
            .map_err(|e| Error::Win(format!("GetAclInformation: {e}")))?;
        for i in 0..info.AceCount {
            let mut ace: *mut c_void = std::ptr::null_mut();
            unsafe { GetAce(dacl, i, &mut ace) }.map_err(|e| Error::Win(format!("GetAce: {e}")))?;
            let hdr = unsafe { &*(ace as *const ACE_HEADER) };
            if hdr.AceType != ACCESS_DENIED_ACE_TYPE || hdr.AceFlags & INHERITED_ACE != 0 {
                continue;
            }
            let denied = unsafe { &*(ace as *const ACCESS_DENIED_ACE) };
            if denied.Mask != DENY_MASK {
                continue;
            }
            let ace_sid = PSID(&denied.SidStart as *const u32 as *mut c_void);
            if unsafe { EqualSid(ace_sid, PSID(sid.as_ptr() as *mut c_void)) }.is_ok() {
                out.push(i);
            }
        }
        Ok(out)
    }

    pub fn is_restricted(path: &Path) -> Result<bool> {
        let sid = everyone_sid()?;
        let (_sd, dacl) = get_dacl(path)?;
        Ok(!find_ours(dacl, &sid)?.is_empty())
    }

    pub fn apply_deny(path: &Path) -> Result<()> {
        let mut sid = everyone_sid()?;
        let (_sd, old) = get_dacl(path)?;
        if !find_ours(old, &sid)?.is_empty() {
            return Ok(());
        }
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: DENY_MASK,
            grfAccessMode: DENY_ACCESS,
            grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: PWSTR(sid.as_mut_ptr() as *mut u16),
            },
        };
        let mut new_acl: *mut ACL = std::ptr::null_mut();
        let rc = unsafe { SetEntriesInAclW(Some(&[ea]), Some(old), &mut new_acl) };
        if rc != ERROR_SUCCESS {
            return Err(Error::Win(format!("SetEntriesInAcl failed ({})", rc.0)));
        }
        let r = set_dacl(path, new_acl);
        unsafe { LocalFree(Some(HLOCAL(new_acl as *mut c_void))) };
        r
    }

    /// Replaces the DACL with a single "allow Everyone `mask`" entry and blocks
    /// inheritance, so the parent's deny ACE does not apply to this item.
    pub fn set_protected_everyone(path: &Path, mask: u32) -> Result<()> {
        let mut sid = everyone_sid()?;
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: SET_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: PWSTR(sid.as_mut_ptr() as *mut u16),
            },
        };
        let mut acl: *mut ACL = std::ptr::null_mut();
        let rc = unsafe { SetEntriesInAclW(Some(&[ea]), None, &mut acl) };
        if rc != ERROR_SUCCESS {
            return Err(Error::Win(format!("SetEntriesInAcl failed ({})", rc.0)));
        }
        let w = wide(path);
        let rc = unsafe { SetNamedSecurityInfoW(PCWSTR(w.as_ptr()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, None, None, Some(acl), None) };
        unsafe { LocalFree(Some(HLOCAL(acl as *mut c_void))) };
        if rc != ERROR_SUCCESS {
            return Err(Error::Win(format!("SetNamedSecurityInfo failed ({})", rc.0)));
        }
        Ok(())
    }

    pub fn remove_deny(path: &Path) -> Result<()> {
        let sid = everyone_sid()?;
        let (_sd, dacl) = get_dacl(path)?;
        let idx = find_ours(dacl, &sid)?;
        if idx.is_empty() {
            return Ok(());
        }
        for i in idx.into_iter().rev() {
            unsafe { DeleteAce(dacl, i) }.map_err(|e| Error::Win(format!("DeleteAce: {e}")))?;
        }
        set_dacl(path, dacl)
    }
}

#[cfg(windows)]
pub use imp::{apply_deny, is_restricted, remove_deny, set_protected_everyone};

#[cfg(not(windows))]
pub fn set_protected_everyone(_p: &Path, _mask: u32) -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn apply_deny(_p: &Path) -> Result<()> {
    Ok(())
}
#[cfg(not(windows))]
pub fn remove_deny(_p: &Path) -> Result<()> {
    Ok(())
}
#[cfg(not(windows))]
pub fn is_restricted(_p: &Path) -> Result<bool> {
    Ok(false)
}
