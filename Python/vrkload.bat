:: COM PORT
@if "%1"=="" GOTO USAGE
@if "%2"=="" set COMPORT=COM11
@if NOT "%2"=="" set COMPORT="%2"
 
::
:: Generate Current HMAC
::
:: D1F8827DD9276F9F-80F8890D3E607AC0-3CA022BA91B80243-56DCDF54AD434F83
::

@ECHO OFF

:KEYS
IF "%1"=="1" (
  SET KEYFILE=./upload/keys/VRK/RTC54_275-209-472.tgz
) ELSE IF "%1"=="2" (
  SET KEYFILE=./upload/keys/VRK/RTC56_275-209-472.tgz
) ELSE IF "%1"=="3" (
  SET KEYFILE=./upload/keys/VRK/RTC58_275-209-472.tgz
) ELSE IF "%1"=="4" (
  SET KEYFILE=./upload/keys/VRK/RTC510_275-209-472.tgz
) ELSE (
  @ECHO NO OPTION FOUND FOR %1
  @GOTO USAGE
)

@ECHO ON

putfile.py --serial %COMPORT% --file %KEYFILE%
TC_reset_device.py --serial %COMPORT%
goto DONE

:USAGE
@echo.
@echo USAGE %0 [KEY 1,2,3,4] [COMPORT]
@echo.

:DONE
@set KEYFILE=
