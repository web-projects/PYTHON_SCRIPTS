:: ASSUMPTION: BASE PYTHON IS IN C:\Python
:: Modify as needed for your configuration
::

@if "%1"=="" goto USAGE

:: COMPORT AS PARAMETER
@set COMPORT=%1
@if NOT "%COMPORT:~0,3%"=="COM" GOTO USAGE

:NEXTSTEP
@set TARGER_DIR="upload\config"

@for /r %%i in (%TARGER_DIR%\*) do (
  delfile.py %%~nxi --serial %COMPORT%
)
GOTO END

:USAGE
@echo.
@echo USAGE: %0 COMXX
@echo.

:END
@echo.
@set COMPORT=1
