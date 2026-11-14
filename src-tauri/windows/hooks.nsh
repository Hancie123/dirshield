; DirShield NSIS installer hooks.
; - Registers the per-user Explorer context menu after install.
; - Removes the context menu and startup entry on uninstall.
; - NEVER deletes vaults, Quick-Locked folders or the database
;   (%LOCALAPPDATA%\DirShield is outside the app-data folders Tauri's
;   "delete app data" checkbox removes). The user is told where they are.

!macro NSIS_HOOK_POSTINSTALL
  WriteRegStr HKCU "Software\Classes\Directory\shell\DirShield" "MUIVerb" "DirShield"
  WriteRegStr HKCU "Software\Classes\Directory\shell\DirShield" "Icon" '"$INSTDIR\dirshield.exe",0'
  WriteRegStr HKCU "Software\Classes\Directory\shell\DirShield" "SubCommands" ""
  WriteRegStr HKCU "Software\Classes\Directory\shell\DirShield\shell\01quick" "MUIVerb" "Quick Lock"
  WriteRegStr HKCU "Software\Classes\Directory\shell\DirShield\shell\01quick\command" "" '"$INSTDIR\dirshield.exe" --action quick-lock "%1"'
  WriteRegStr HKCU "Software\Classes\Directory\shell\DirShield\shell\02secure" "MUIVerb" "Secure Lock (encrypt)"
  WriteRegStr HKCU "Software\Classes\Directory\shell\DirShield\shell\02secure\command" "" '"$INSTDIR\dirshield.exe" --action secure-lock "%1"'
  WriteRegStr HKCU "Software\Classes\Directory\shell\DirShield\shell\03unlock" "MUIVerb" "Unlock Folder"
  WriteRegStr HKCU "Software\Classes\Directory\shell\DirShield\shell\03unlock\command" "" '"$INSTDIR\dirshield.exe" --action unlock "%1"'
  WriteRegStr HKCU "Software\Classes\Directory\shell\DirShield\shell\04unhide" "MUIVerb" "Unhide Folder"
  WriteRegStr HKCU "Software\Classes\Directory\shell\DirShield\shell\04unhide\command" "" '"$INSTDIR\dirshield.exe" --action unhide "%1"'
  WriteRegStr HKCU "Software\Classes\Directory\shell\DirShield\shell\05settings" "MUIVerb" "DirShield Settings"
  WriteRegDWORD HKCU "Software\Classes\Directory\shell\DirShield\shell\05settings" "CommandFlags" 0x20
  WriteRegStr HKCU "Software\Classes\Directory\shell\DirShield\shell\05settings\command" "" '"$INSTDIR\dirshield.exe" --action settings "%1"'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DeleteRegKey HKCU "Software\Classes\Directory\shell\DirShield"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "DirShield"
  IfSilent +2
  MessageBox MB_OK|MB_ICONINFORMATION "DirShield will be removed, but your protected data is kept:$\r$\n$\r$\n  $LOCALAPPDATA\DirShield$\r$\n$\r$\nSecure Lock vaults, Quick-Locked folders and the DirShield database stay there. Reinstall DirShield to unlock them. Unlock folders before uninstalling if you no longer need protection."
!macroend
