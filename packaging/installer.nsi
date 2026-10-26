Unicode True
!include "MUI2.nsh"
!define APP_NAME "ARES Studio"
!define APP_VERSION "0.1.0"
Name "${APP_NAME}"
OutFile "..\dist\ARES-Studio-Setup-${APP_VERSION}.exe"
InstallDir "$PROGRAMFILES64\ARES Studio"
RequestExecutionLevel admin
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
Section "Install"
  SetOutPath "$INSTDIR"
  File /r "..\dist\ARES-Studio\*"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\ARES Studio"
  CreateShortCut "$SMPROGRAMS\ARES Studio\ARES Studio.lnk" "$INSTDIR\ARES-Studio.exe"
  CreateShortCut "$DESKTOP\ARES Studio.lnk" "$INSTDIR\ARES-Studio.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARESStudio" "DisplayName" "ARES Studio"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARESStudio" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARESStudio" "DisplayVersion" "${APP_VERSION}"
SectionEnd
Section "Uninstall"
  RMDir /r "$INSTDIR"
  RMDir /r "$SMPROGRAMS\ARES Studio"
  Delete "$DESKTOP\ARES Studio.lnk"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARESStudio"
SectionEnd
