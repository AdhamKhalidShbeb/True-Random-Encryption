; NSIS Installer Script for True Random Encryption
; Builds a Windows installer with Start Menu shortcuts and uninstaller

!include "MUI2.nsh"

; ─── Configuration ──────────────────────────────────────────────────────
!ifndef VERSION
  !define VERSION "1.0.0"
!endif

!ifndef OUTDIR
  !define OUTDIR "."
!endif

Name "True Random Encryption ${VERSION}"
OutFile "${OUTDIR}\TRE-${VERSION}-windows-x64-setup.exe"
InstallDir "$PROGRAMFILES64\True Random Encryption"
InstallDirRegKey HKLM "Software\TrueRandomEncryption" "InstallDir"
RequestExecutionLevel admin

; ─── Modern UI Settings ─────────────────────────────────────────────────
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; ─── Pages ──────────────────────────────────────────────────────────────
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\LICENSE.md"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ─── Install Section ────────────────────────────────────────────────────
Section "Install"
  SetOutPath "$INSTDIR"

  ; Copy all files from the release_package directory
  File /r "..\..\release_package\*.*"

  ; Write registry keys
  WriteRegStr HKLM "Software\TrueRandomEncryption" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\TrueRandomEncryption" "Version" "${VERSION}"

  ; Add/Remove Programs entry
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueRandomEncryption" \
    "DisplayName" "True Random Encryption ${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueRandomEncryption" \
    "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueRandomEncryption" \
    "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueRandomEncryption" \
    "Publisher" "Adham Khalid Shbeb"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueRandomEncryption" \
    "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueRandomEncryption" \
    "NoRepair" 1

  ; Create uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Start Menu shortcuts
  CreateDirectory "$SMPROGRAMS\True Random Encryption"
  CreateShortCut "$SMPROGRAMS\True Random Encryption\True Random Encryption.lnk" "$INSTDIR\tre-gui.exe"
  CreateShortCut "$SMPROGRAMS\True Random Encryption\Uninstall.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

; ─── Uninstall Section ──────────────────────────────────────────────────
Section "Uninstall"
  ; Remove files (recursively clean the install directory)
  RMDir /r "$INSTDIR"

  ; Remove Start Menu shortcuts
  RMDir /r "$SMPROGRAMS\True Random Encryption"

  ; Remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrueRandomEncryption"
  DeleteRegKey HKLM "Software\TrueRandomEncryption"
SectionEnd
