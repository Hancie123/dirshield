; DirShield NSIS installer hooks.
; - Registers the per-user Explorer context menu after install (on by default,
;   no prompt; it can be turned off in DirShield Settings).
; - Removes the context menu and startup entry on uninstall.
; - NEVER deletes vaults, Quick-Locked folders or the database
;   (%LOCALAPPDATA%\DirShield is outside the app-data folders Tauri's
;   "delete app data" checkbox removes). The user is told where they are.
; - Windows 11 top-level menu: builds signed with a code-signing certificate
;   also install dirshield-shell.msix + dirshield_shell.dll; DirShield
;   registers that sparse package for the current user (no admin) and removes
;   it on uninstall. Other builds don't ship it and skip these steps.
; Keep the entries in sync with VERBS in src/platform/menu_spec.rs.

!define DS_MENU "Software\Classes\Directory\shell\DirShield"

!macro DS_VERB KEY LABEL VERB
  WriteRegStr HKCU "${DS_MENU}\shell\${KEY}" "MUIVerb" "${LABEL}"
  WriteRegStr HKCU "${DS_MENU}\shell\${KEY}" "Icon" '"$INSTDIR\dirshield.exe",0'
  WriteRegStr HKCU "${DS_MENU}\shell\${KEY}\command" "" '"$INSTDIR\dirshield.exe" --action ${VERB} "%1"'
!macroend

!macro NSIS_HOOK_PREINSTALL
  ; Explorer may still have the Windows 11 menu handler loaded. A loaded DLL
  ; can be renamed but not overwritten, so move it aside; the old copy is
  ; deleted now if possible, otherwise at the next restart.
  IfFileExists "$INSTDIR\dirshield_shell.dll" 0 ds_dll_free
  Delete "$INSTDIR\dirshield_shell.dll.old"
  Rename "$INSTDIR\dirshield_shell.dll" "$INSTDIR\dirshield_shell.dll.old"
  Delete /REBOOTOK "$INSTDIR\dirshield_shell.dll.old"
  ds_dll_free:
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Clear entries from older versions first.
  DeleteRegKey HKCU "${DS_MENU}"
  WriteRegStr HKCU "${DS_MENU}" "MUIVerb" "DirShield"
  WriteRegStr HKCU "${DS_MENU}" "Icon" '"$INSTDIR\dirshield.exe",0'
  WriteRegStr HKCU "${DS_MENU}" "SubCommands" ""
  !insertmacro DS_VERB "01lock" "Lock Folder" "lock"
  !insertmacro DS_VERB "02lockhide" "Lock and Hide Folder" "quick-lock"
  !insertmacro DS_VERB "03secure" "Secure Lock (encrypt)" "secure-lock"
  !insertmacro DS_VERB "04unlock" "Unlock Folder" "unlock"
  !insertmacro DS_VERB "05unhide" "Unhide Folder" "unhide"
  !insertmacro DS_VERB "06settings" "DirShield Settings" "settings"
  WriteRegDWORD HKCU "${DS_MENU}\shell\06settings" "CommandFlags" 0x20
  ; Windows 11 top-level menu (only signed builds ship the package).
  IfFileExists "$INSTDIR\dirshield-shell.msix" 0 ds_no_sparse
  ExecWait '"$INSTDIR\dirshield.exe" --register-shell-ext'
  ds_no_sparse:
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; Ask for the master password before removing anything. DirShield exits
  ; with 0 when it is confirmed (or no master password exists yet) and 1 when
  ; the user cancels. Silent runs (used by the installer when upgrading)
  ; skip the check.
  IfSilent ds_confirmed
  IfFileExists "$INSTDIR\dirshield.exe" 0 ds_confirmed
  ClearErrors
  ExecWait '"$INSTDIR\dirshield.exe" --confirm-uninstall' $0
  IfErrors ds_confirmed
  StrCmp $0 "0" ds_confirmed
  MessageBox MB_OK|MB_ICONEXCLAMATION "Uninstall was cancelled. DirShield's master password is required to uninstall it."
  Abort "Uninstall cancelled: master password not confirmed."
  ds_confirmed:

  DeleteRegKey HKCU "${DS_MENU}"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "DirShield"
  IfFileExists "$INSTDIR\dirshield-shell.msix" 0 ds_no_sparse_u
  ExecWait '"$INSTDIR\dirshield.exe" --unregister-shell-ext'
  ds_no_sparse_u:
  IfSilent +2
  MessageBox MB_OK|MB_ICONINFORMATION "DirShield will be removed, but your protected data is kept:$\r$\n$\r$\n  $LOCALAPPDATA\DirShield$\r$\n$\r$\nSecure Lock vaults, Quick-Locked folders and the DirShield database stay there. Reinstall DirShield to unlock them. Unlock folders before uninstalling if you no longer need protection."
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; Explorer may still hold the menu handler open. Move it aside and delete
  ; that copy at the next restart; a delete scheduled for the original name
  ; would also remove the DLL a following install puts there.
  Delete "$INSTDIR\dirshield_shell.dll"
  IfFileExists "$INSTDIR\dirshield_shell.dll" 0 ds_dll_gone
  Delete "$INSTDIR\dirshield_shell.dll.old"
  Rename "$INSTDIR\dirshield_shell.dll" "$INSTDIR\dirshield_shell.dll.old"
  ds_dll_gone:
  Delete /REBOOTOK "$INSTDIR\dirshield_shell.dll.old"
!macroend
