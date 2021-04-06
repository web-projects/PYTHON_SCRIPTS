:: ASSUMPTION: BASE PYTHON IS IN C:\Python
:: File location is relative to the BASE path:
:: i.e. C:\Python\upload\keys\VRK\...
::
:: Modify as needed for your configuration
::

@if "%1"=="" goto USAGE
@if "%2"=="" goto USAGE

:: COMPORT AS PARAMETER
@set COMPORT=%1
@if NOT "%COMPORT:~0,3%"=="COM" GOTO USAGE

@if "%2"=="attended" goto ATTENDED
@if "%2"=="unattended" goto UNATTENDED
goto USAGE

:ATTENDED
:: CHANGE SERIAL NUMBER AS NEEDED
@set TARGER_DIR="upload\keys\VRK\attended\275-209-472"
GOTO NEXTSTEP

:UNATTENDED
:: CHANGE SERIAL NUMBER AS NEEDED
@set TARGER_DIR="upload\keys\VRK\unattended\987-091-636"
GOTO NEXTSTEP

:NEXTSTEP
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
@echo USAGE: %0 COMXX "[attended | unattended]"
@echo.

:END
@echo.
@set COMPORT=
@set COUNT=
@set TARGER_DIR=
