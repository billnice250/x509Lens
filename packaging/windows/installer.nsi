Unicode true
!include "MUI2.nsh"
!ifndef BINARY
!error "Pass /DBINARY=path-to-X509Lens.exe"
!endif
!ifndef OUTPUT
!define OUTPUT "X509Lens-setup.exe"
!endif
!ifndef APP_VERSION
!define APP_VERSION "1.0.0"
!endif
!ifndef PUBLISHER_DISPLAY_NAME
!define PUBLISHER_DISPLAY_NAME "X509 Lens"
!endif
Name "X509 Lens"
OutFile "${OUTPUT}"
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\Programs\X509Lens"
VIProductVersion "${APP_VERSION}.0"
VIAddVersionKey "ProductName" "X509 Lens"
VIAddVersionKey "FileDescription" "X509 Lens Certificate Viewer Installer"
VIAddVersionKey "FileVersion" "${APP_VERSION}"
VIAddVersionKey "ProductVersion" "${APP_VERSION}"
VIAddVersionKey "CompanyName" "${PUBLISHER_DISPLAY_NAME}"
!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

!macro Associate EXT
 WriteRegStr HKCU "Software\Classes\X509Lens.${EXT}" "" "X509 Lens ${EXT} File"
 WriteRegStr HKCU "Software\Classes\X509Lens.${EXT}\DefaultIcon" "" '$"$INSTDIR\X509Lens.exe$",0'
 WriteRegStr HKCU "Software\Classes\X509Lens.${EXT}\shell\open\command" "" '$"$INSTDIR\X509Lens.exe$" $"%1$"'
 WriteRegStr HKCU "Software\Classes\.${EXT}\OpenWithProgids" "X509Lens.${EXT}" ""
 WriteRegStr HKCU "Software\X509Lens\Capabilities\FileAssociations" ".${EXT}" "X509Lens.${EXT}"
!macroend
!macro Unassociate EXT
 DeleteRegValue HKCU "Software\Classes\.${EXT}\OpenWithProgids" "X509Lens.${EXT}"
 DeleteRegKey /ifempty HKCU "Software\Classes\.${EXT}\OpenWithProgids"
 DeleteRegKey /ifempty HKCU "Software\Classes\.${EXT}"
 DeleteRegKey HKCU "Software\Classes\X509Lens.${EXT}"
!macroend
Section "X509 Lens"
 SetShellVarContext current
 SetOutPath "$INSTDIR"
 File /oname=X509Lens.exe "${BINARY}"
 WriteUninstaller "$INSTDIR\Uninstall.exe"
 CreateShortcut "$SMPROGRAMS\X509Lens.lnk" "$INSTDIR\X509Lens.exe"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\X509Lens" "DisplayName" "X509 Lens"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\X509Lens" "DisplayVersion" "${APP_VERSION}"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\X509Lens" "Publisher" "${PUBLISHER_DISPLAY_NAME}"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\X509Lens" "DisplayIcon" '$"$INSTDIR\X509Lens.exe$",0'
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\X509Lens" "InstallLocation" "$INSTDIR"
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\X509Lens" "UninstallString" '$"$INSTDIR\Uninstall.exe$"'
 WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\X509Lens" "QuietUninstallString" '$"$INSTDIR\Uninstall.exe$" /S'
 WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\X509Lens" "NoModify" 1
 WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\X509Lens" "NoRepair" 1
 WriteRegStr HKCU "Software\X509Lens\Capabilities" "ApplicationName" "X509 Lens"
 WriteRegStr HKCU "Software\X509Lens\Capabilities" "ApplicationDescription" "Certificate and cryptographic object viewer"
 WriteRegStr HKCU "Software\RegisteredApplications" "X509Lens" "Software\X509Lens\Capabilities"
 !insertmacro Associate "cer"
 !insertmacro Associate "crt"
 !insertmacro Associate "csr"
 !insertmacro Associate "req"
 !insertmacro Associate "pem"
 !insertmacro Associate "der"
 !insertmacro Associate "p7b"
 !insertmacro Associate "p7c"
 !insertmacro Associate "p12"
 !insertmacro Associate "pfx"
 !insertmacro Associate "crl"
 !insertmacro Associate "key"
 !insertmacro Associate "pub"
 System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'
SectionEnd
Section "Uninstall"
 SetShellVarContext current
 Delete "$INSTDIR\X509Lens.exe"
 Delete "$INSTDIR\Uninstall.exe"
 RMDir "$INSTDIR"
 Delete "$SMPROGRAMS\X509Lens.lnk"
 !insertmacro Unassociate "cer"
 !insertmacro Unassociate "crt"
 !insertmacro Unassociate "csr"
 !insertmacro Unassociate "req"
 !insertmacro Unassociate "pem"
 !insertmacro Unassociate "der"
 !insertmacro Unassociate "p7b"
 !insertmacro Unassociate "p7c"
 !insertmacro Unassociate "p12"
 !insertmacro Unassociate "pfx"
 !insertmacro Unassociate "crl"
 !insertmacro Unassociate "key"
 !insertmacro Unassociate "pub"
 DeleteRegValue HKCU "Software\RegisteredApplications" "X509Lens"
 DeleteRegKey HKCU "Software\X509Lens"
 DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\X509Lens"
 System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'
SectionEnd
