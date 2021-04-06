; example2.nsi
;
; This script is based on example1.nsi, but it remember the directory, 
; has uninstall support and (optionally) installs start menu shortcuts.
;
; It will install example2.nsi into a directory that the user selects,
!include "python.nsh"
!include "EnvVarUpdate.nsh"
;--------------------------------
var PyExe
;--------------------------------
; The name of the installer
Name "Verifone Testharness tool"

; The file to write
OutFile "testharness-install.exe"

; The default installation directory
InstallDir $PROGRAMFILES\Verifone\TestHarness

; Registry key to check for directory (so if you install again, it will 
; overwrite the old one automatically)
InstallDirRegKey HKLM "Software\Verifone\TestHanrness" "Install_Dir"

; Request application privileges for Windows Vista
RequestExecutionLevel admin

;--------------------------------

; Pages

Page components
Page directory
Page instfiles

UninstPage uninstConfirm
UninstPage instfiles

;--------------------------------

; The stuff to install
Section "Python 3.4 and libraries(required)"

  SectionIn RO
  
  ; Set output path to the installation directory.
  SetOutPath $INSTDIR
  
  ; Check for python
  ;Call CheckForPython
  ; Write the installation path into the registry
  WriteRegStr HKLM SOFTWARE\Verifone\TestHarness "Install_Dir" "$INSTDIR"
  ${CheckForPython} $0 $2 $PyExe
  DetailPrint "Check python status Version [$0] Exec [$PyExe] IS64Bit [$2]"
  ${VersionCheckNew} $0 "3.4" $1
  ${If} $0 == "" 
  ${OrIf} $PyExe == ""
  	 ${If} $PyExe != ""
  	; Python not installed please install it
	  Abort "Python not installed please install python>=3.4"
	 ${Else}
		SetOutPath "$TEMP\thtmp"
		File "download\python-3.4.1.msi"
		nsExec::ExecToStack '"msiexec" /i "$TEMP\thtmp\python-3.4.1.msi"'
		Pop $0 #Error code
		Pop $1 #String
		DetailPrint $1
		${If} $0 != 0 
			DetailPrint "$1"
			Abort "Unable to execute installer"
		${Endif}
		; After installing python rettriger again
		${CheckForPython} $0 $2 $PyExe
		${If} $0 == ""
		${OrIf} $PyExe == ""
			Abort "Python installation unsucessfull - Aborting"
		${EndIf}
	 ${Endif}
  ${Endif}
  ${If} $1 == 2
  	Abort "Installed python is too old please uninstall Python$0 and install again python>=3.4"
  ${EndIf}
	; Save the python root directory
	push  "$PyExe"
	Call GetParent
	pop $0
	WriteRegStr HKLM SOFTWARE\Verifone\Testharness "PythonRoot" $0
	WriteRegStr HKLM SOFTWARE\Verifone\TestHarness "Install_Dir" "$INSTDIR"
	;Set Output Path
	SetOutPath "$TEMP\thtmp"
	File "download\colorama-0.3.2.zip"
	nsisunz::UnzipToLog "$TEMP\thtmp\colorama-0.3.2.zip" "$TEMP\thtmp"
	Pop $0
	${if} $0 != "success"
		DetailPrint "$0"
		Abort "Unable to unzip colorama package"
	${endif}
	SetOutPath "$TEMP\thtmp\colorama-0.3.2"
	nsExec::ExecToStack '"$PyExe" setup.py bdist_wininst'
	Pop $0 #Error code
	Pop $1 #String
	DetailPrint $1
	${If} $0 != 0 
		DetailPrint "$1"
		Abort "Unable to execute installer"
	${Endif}
	nsExec::ExecToStack '"dist\colorama-0.3.2.win32.exe"'
	Pop $0 #Error code
	Pop $1 #String
	DetailPrint $1
	${If} $0 != 0 
		DetailPrint "$1"
		Abort "Unable to execute installer"
	${Endif}
	
	;Install Pyserial
    SetOutPath "$TEMP\thtmp"
	File "download\pyserial-2.7.win32_py3k.exe"
	nsExec::ExecToStack '"pyserial-2.7.win32_py3k.exe"'
	Pop $0 #Error code
	Pop $1 #String
	DetailPrint $1
	${If} $0 != 0 
		DetailPrint "$1"
		Abort "Unable to execute installer"
	${Endif}
   
   ; Process HTTPLIB2 
    SetOutPath "$TEMP\thtmp"
	File "download\httplib2-0.9.zip"
	nsisunz::UnzipToLog "$TEMP\thtmp\httplib2-0.9.zip" "$TEMP\thtmp"
	Pop $0
	${if} $0 != "success"
		DetailPrint "$0"
		Abort "Unable to unzip httplib package"
	${endif}
	SetOutPath "$TEMP\thtmp\httplib2-0.9"
	nsExec::ExecToStack '"$PyExe" setup.py bdist_wininst'
	Pop $0 #Error code
	Pop $1 #String
	DetailPrint $1
	${If} $0 != 0 
		DetailPrint "$1"
		Abort "Unable to execute installer"
	${Endif}
	nsExec::ExecToStack '"dist\httplib2-0.9.win32.exe"'
	Pop $0 #Error code
	Pop $1 #String
	DetailPrint $1
	${If} $0 != 0 
		DetailPrint "$1"
		Abort "Unable to execute installer"
	${Endif}

   ;Install pyparsing
    SetOutPath "$TEMP\thtmp"
	File "download\pyparsing-2.0.2.win32-py3.4.exe"
	nsExec::ExecToStack '"pyparsing-2.0.2.win32-py3.4.exe"'
	Pop $0 #Error code
	Pop $1 #String
	DetailPrint $1
	${If} $0 != 0 
		DetailPrint "$1"
		Abort "Unable to execute installer"
	${Endif}
   ; All required components are installed and now install test harness core
   SetOutPath "$TEMP\thtmp"
   File /r "testharness"
   File "setup.py"
	nsExec::ExecToStack '"$PyExe" setup.py bdist_wininst'
	Pop $0 #Error code
	Pop $1 #String
	DetailPrint $1
	${If} $0 != 0 
		DetailPrint "$1"
		Abort "Unable to execute installer"
	${Endif}
	nsExec::ExecToStack '"dist\testharness-2.0.0.win32.exe"'
	Pop $0 #Error code
	Pop $1 #String
	DetailPrint $1
	${If} $0 != 0 
		DetailPrint "$1"
		Abort "Unable to execute installer"
	${Endif}
	;Copy important testharness file
	SetOutPath "$INSTDIR\scripts"
	File getfile.py
	File putfile.py
	File oldthscript_interpreter.py
	File transtest_all.py
	SetOutPath "$INSTDIR\bin"
	File "download\PTR.exe"
	File "download\unicows.dll"
	File "download\INIFileParser.dll"
	File "download\XMLViewer.exe"

	FileOpen $4 "$INSTDIR\bin\vipaputfile.bat" w
	FileWrite $4 "@echo off$\r$\n"
	FileWrite $4 '"$PyExe" "$INSTDIR\scripts\putfile.py" %*$\r$\n'
	FileClose $4

	FileOpen $4 "$INSTDIR\bin\vipagetfile.bat" w
	FileWrite $4 "@echo off$\r$\n"
	FileWrite $4 '"$PyExe" "$INSTDIR\scripts\getfile.py" %*$\r$\n'
	FileClose $4

	FileOpen $4 "$INSTDIR\bin\vipaoldthscript.bat" w
	FileWrite $4 "@echo off$\r$\n"
	FileWrite $4 '"$PyExe" "$INSTDIR\scripts\oldthscript_interpreter.py" %*$\r$\n'
	FileClose $4
	
	;Create ini string for ptr
	push  "$PyExe"
	Call GetParent
	pop $0
	WriteINIStr "$INSTDIR\bin\default.ini" Locations python_path "$0"
	WriteINIStr "$INSTDIR\bin\default.ini" Locations testharness_path "$INSTDIR\scripts"
	WriteINIStr "$INSTDIR\bin\default.ini" Locations test_repository_path ""
	WriteINIStr "$INSTDIR\bin\default.ini" Communication server_mode "--tcp-server E"
	WriteINIStr "$INSTDIR\bin\default.ini" Communication client_mode "--tcp-client A.B.C.D:E"
	WriteINIStr "$INSTDIR\bin\default.ini" Communication rs232 "COM1"
	SetOutPath "$PROFILE\Scripts"
	File getfile.py
	File putfile.py
	File oldthscript_interpreter.py
	File transtest_all.py
	File "download\keyword_file.txt"
	SetOutPath "$INSTDIR\bin"
	WriteUninstaller "testharness-uninstall.exe"
  ; Write the uninstall keys for Windows
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\vfitestharness" "VERIFONE Testharness" "VERIFONE Testharness"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\vfitestharness" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\vfitestharness" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\vfitestharness" "NoRepair" 1
  ${EnvVarUpdate} $0 "PATH" "A" "HKLM" "$INSTDIR\bin" ; Append  
  Rmdir /r "$TEMP\thtmp"
SectionEnd

; Optional section (can be disabled by the user)
Section "Start Menu Shortcuts"

  CreateDirectory "$SMPROGRAMS\Verifone Testharness"
  CreateShortcut  "$SMPROGRAMS\Verifone Testharness\Uninstall.lnk" "$INSTDIR\testharness-uninstall.exe" "" "$INSTDIR\testharness-uninstall.exe" 0
  CreateShortcut  "$SMPROGRAMS\Verifone Testharness\PtrGUI.lnk" "$INSTDIR\bin\PTR.exe"
  CreateShortcut  "$SMPROGRAMS\Verifone Testharness\XMLView.lnk" "$INSTDIR\bin\XMLViewer.exe"
SectionEnd

;--------------------------------

; Uninstaller

Section "Uninstall"
  ; Uninstall pythons
  ReadRegStr $0 HKLM SOFTWARE\Verifone\TestHarness "PythonRoot"
  ${If} ${FileExists} "$0\RemoveColorama.exe"
 		DetailPrint "Removing the colorama  $0\RemoveColorama.exe"
		nsExec::ExecToStack '"$0\RemoveColorama.exe" -u "$0\colorama-wininst.log"'
		Pop $0 #Error code
		Pop $1 #String
		DetailPrint $1
		${If} $0 != 0 
			DetailPrint "$1"
			Abort "$1"
		${Endif}
  ${Endif}
  ;Uninstall pyserial
  ReadRegStr $0 HKLM SOFTWARE\Verifone\TestHarness "PythonRoot"
  ${If} ${FileExists} "$0\RemovePyserial.exe"
 		DetailPrint "Removing the Pyserial  $0\RemovePyserial.exe"
		nsExec::ExecToStack '"$0\RemovePyserial.exe" -u "$0\pyserial-wininst.log"'
		Pop $0 #Error code
		Pop $1 #String
		DetailPrint $1
		${If} $0 != 0 
			DetailPrint "$1"
			Abort "$1"
		${Endif}
  ${Endif}
  ;Uninstall httplib2
  ReadRegStr $0 HKLM SOFTWARE\Verifone\TestHarness "PythonRoot"
  ${If} ${FileExists} "$0\Removehttplib2.exe"
 		DetailPrint "Removing the httplib2  $0\httplib2.exe"
		nsExec::ExecToStack '"$0\RemoveHttplib2.exe" -u "$0\httplib2-wininst.log"'
		Pop $0 #Error code
		Pop $1 #String
		DetailPrint $1
		${If} $0 != 0 
			DetailPrint "$1"
			Abort "$1"
		${Endif}
  ${Endif}
  ;Uninstall pyparsing
  ReadRegStr $0 HKLM SOFTWARE\Verifone\TestHarness "PythonRoot"
  ${If} ${FileExists} "$0\Removepyparsing.exe"
 		DetailPrint "Removing the pyparsing  $0\pyparsing.exe"
		nsExec::ExecToStack '"$0\RemovePyparsing.exe" -u "$0\pyparsing-wininst.log"'
		Pop $0 #Error code
		Pop $1 #String
		DetailPrint $1
		${If} $0 != 0 
			DetailPrint "$1"
			Abort "$1"
		${Endif}
  ${Endif}
  ;Uninstall testharness
  ReadRegStr $0 HKLM SOFTWARE\Verifone\TestHarness "PythonRoot"
  ${If} ${FileExists} "$0\RemoveTestharness.exe"
 		DetailPrint "Removing the testharness  $0\testharness.exe"
		nsExec::ExecToStack '"$0\RemoveTestharness.exe" -u "$0\Testharness-wininst.log"'
		Pop $0 #Error code
		Pop $1 #String
		DetailPrint $1
		${If} $0 != 0 
			DetailPrint "$1"
			Abort "$1"
		${Endif}
  ${Endif}
  ; Remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\vfitestharness"
  DeleteRegKey HKLM SOFTWARE\Verifone\Testharness

  ; Remove files and uninstaller
  RmDir /r $INSTDIR\scripts
  RMDir /r $INSTDIR\bin

  ; Remove shortcuts, if any
  Delete "$SMPROGRAMS\Verifone Testharness\*.*"

  ; Remove directories used
  RMDir "$SMPROGRAMS\Verifone Testharness"
  RMDir /r "$INSTDIR"
  ${un.EnvVarUpdate} $0 "PATH" "R" "HKLM" "$INSTDIR\bin"
SectionEnd
