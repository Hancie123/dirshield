; DirShield NSIS installer hooks.
; - Registers the per-user Explorer context menu after install (on by default,
;   no prompt; it can be turned off in DirShield Settings).
; - Removes the context menu and startup entry on uninstall.
; - NEVER deletes vaults, Quick-Locked folders or the database
;   (%LOCALAPPDATA%\DirShield is outside the app-data folders Tauri's
;   "delete app data" checkbox removes). The user is told where they are.
; Keep the entries in sync with VERBS in src/shell.rs.

!define DS_MENU "Software\Classes\Directory\shell\DirShield"

!macro DS_VERB KEY LABEL VERB
  WriteRegStr HKCU "${DS_MENU}\shell\${KEY}" "MUIVerb" "${LABEL}"
  WriteRegStr HKCU "${DS_MENU}\shell\${KEY}" "Icon" '"$INSTDIR\dirshield.exe",0'
  WriteRegStr HKCU "${DS_MENU}\shell\${KEY}\command" "" '"$INSTDIR\dirshield.exe" --action ${VERB} "%1"'
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
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DeleteRegKey HKCU "${DS_MENU}"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "DirShield"
  IfSilent +2
  MessageBox MB_OK|MB_ICONINFORMATION "DirShield will be removed, but your protected data is kept:$\r$\n$\r$\n  $LOCALAPPDATA\DirShield$\r$\n$\r$\nSecure Lock vaults, Quick-Locked folders and the DirShield database stay there. Reinstall DirShield to unlock them. Unlock folders before uninstalling if you no longer need protection."
!macroend
