:: ASSUMPTION: BASE PYTHON IS IN C:\Python
:: Modify as needed for your configuration
::

@if "%1"=="" goto USAGE

:: COMPORT AS PARAMETER
@set COMPORT=%1
@if NOT "%COMPORT:~0,3%"=="COM" GOTO USAGE

@if "%2"=="UX" goto UX
@if "%2"=="CAPK" goto CAPK
@if "%2"=="TTQ" goto TTQ
@if "%2"=="NOPIN" goto ATTENDEDNOPIN

:: ICC CONFIGS - DEFAULTS TO ATTENDED
:ENGAGE
@set TARGER_DIR="upload\config\emv\ICC\attended"
goto CONFIGS

:: ICC CONFIGS - ATTENDEDNOPIN
:ATTENDEDNOPIN
@set TARGER_DIR="upload\config\emv\ICC\attendednopin"
goto CONFIGS

:UX
:: ICC CONFIGS - UNATTENDED
@set TARGER_DIR="upload\config\emv\ICC\unattended"
goto CONFIGS

:TEST
::@set TARGER_DIR="upload\config\emv\ICC\test"
goto UPLOAD

:OLD
::@set TARGER_DIR="upload\config\emv\ICC\attended\old"
goto UPLOAD

:: CAPK FILES
:CAPK
@set TARGER_DIR="upload\config\emv\ICC\capk\PROD"
goto UPLOAD

:: TTQ - MSD
:TTQ
@set TARGER_DIR="upload\config\emv\TTQ"
goto UPLOAD

:CONFIGS
@SET /A COUNT=0
@for /r %%i in (%TARGER_DIR%\VIPA_cfg\*) do (
  putfile.py --file %%i --serial %COMPORT%
  @SET /A COUNT+=1
)
@for /r %%i in (%TARGER_DIR%\VIPA_emv\*) do (
  putfile.py --file %%i --serial %COMPORT%
  @SET /A COUNT+=1
)
@ECHO.
@ECHO FILES UPLOADED: %COUNT%
@ECHO.

@GOTO END


:UPLOAD
@SET /A COUNT=0
@for /r %%i in (%TARGER_DIR%\*) do (
  putfile.py --file %%i --serial %COMPORT%
  @SET /A COUNT+=1
)
@ECHO.
@ECHO FILES UPLOADED: %COUNT%
@ECHO.

@GOTO END

:USAGE
@echo.
@echo USAGE: %0 COMXX
@echo.

:END
@echo.
@set COMPORT=
@set COUNT=
