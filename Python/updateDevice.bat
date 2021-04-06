:: COM PORT
@if "%1"=="" set COMPORT=COM11
@if "%1"=="" goto NEXTSTEP
@if "%1"=="HELP" goto HELP

@set COMPORT="%1"

:: SKIP KEYS
@goto HMAC

:: PIN KEYS
@if NOT "%2"=="" set ENCKEYS="%2"
@if NOT "%2"=="" got KEYS

:NEXTSTEP
:: P200
::set ENCKEYS=RTCMv2_275-263-231
::set ENCKEYS=RTCOMv_275-258-147
::goto KEYS
:: P400
::set ENCKEYS=RTCOMv_803-314-198
:: UX300
@set ENCKEYS=RADExx_987-091-636
::set ENCKEYS=RADEa8_987-091-636
::set ENCKEYS=RTCMv2_987-091-636
::set ENCKEYS=RTCOMv_986-227-188
::set ENCKEYS=RTCMv2_986-227-188

::putfile.py --serial COM12 --file ./upload/keys/ADE/RTCMv2_987-091-636.tgz

:KEYS
putfile.py --serial %COMPORT% --file ./upload/keys/ADE/%ENCKEYS%.tgz

TC_reset_device.py --serial %COMPORT%

:HMAC
TC_load_hmac_keys.py --serial %COMPORT%

:: expected HMAC for TC test secrets: d1f8827dd9276f9f80f8890d3e607ac03ca022ba91b8024356dcdf54ad434f83
TC_4111_generate_hmac_ASCII.py --serial %COMPORT%
pause

:CONFIGURATION
:: BASIC CONFIGURATION
putfile.py --file ./upload/mapp.cfg --serial %COMPORT%

putfile.py --file ./upload/verifone/contlemv.cfg --serial %COMPORT%
@echo.
@echo READY TO LOAD AID CONFIGURATION...
@echo.
pause

:: CARDWORKFLOW CONFIGURATION
putfile.py --file ./upload/cless/a000000384.c1 --serial %COMPORT%

putfile.py --file ./upload/cless/cicapp.cfg --serial %COMPORT%

:: putfile.py --file ./upload/dl.bundle.Sphere_config2.tar --serial %COMPORT%

:: ADA
::putfile.py --file ./upload/SphereConfig/dl.bundle.Sphere_config20200401s0.tar --serial %COMPORT%
::putfile.py --file ./upload/SphereConfig/dl.bundle.Sphere_config20200411s8.tar --serial %COMPORT%
putfile.py --file ./upload/SphereConfig/slot/dl.bundle.Sphere_Config3-s8.tar --serial %COMPORT%

::HMAC
::putfile.py --file ./upload/SphereConfig/hmac/dl.bundle.Sphere_UpdKeyCmd_Disable.tar --serial %COMPORT%

::
:: *** TO CHECK DEVICE IS PROPERLY LOCKDOWN, AFTER REBOOT RUN: ***
::
:: TC_load_hmac_encrypted_keys.py --serial COM9
::
:: !!!    EXPECTED ERROR: 9F50 - EC_SECURITY_VIOLATION    !!!
::

::TC_reset_device.py --serial %COMPORT%
@echo.
@echo RESET DEVICE TO APPLY CONFIGURATION CHANGES
@echo.

::
:: *** CHECK FOR PROPER SECURITY CONFIGURATION ***
::
:: TC_get_security_configuration.py --serial COM9
::
:: search for tags dfdf10 (encrypted data), dfdf11 (KSN), dfdf12 (InitVector)
::

goto DONE

:HELP
@echo.
@echo %0 [COMX] --- [RTCOMv_XXX-XXX-XXX]

:DONE
@set COMPORT=
@set ENCKEYS=
