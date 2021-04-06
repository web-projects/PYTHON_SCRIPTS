Overview:
The updated Test Harness files that have been prefixed with TC_* are created for Sphere/TrustCommerce specific updates to existing Verifone Test Harness programs.   Changes reflect expected changes for use by Sphere (such as changing the country/currency code to US / USD).   Others reflect specific tests expected in the Sphere integration.


Requirements:
Use of the Sphere_MSR_TestHarness expects that the original Verifone Test Harness has been installed and is working as expected with a Verifone device.

The normal test harness requires the following Python modules (beyond those packaged with Python3):
Package    Version
---------- -------
colorama   0.4.3
httplib2   0.14.0
pip        19.3.1
pyDes      2.0.1
pyparsing  2.4.5
pyserial   3.4
pywin32    227
setuptools 41.2.0


In addition, the following updates should also be done:
- Update C:\Windows\System32\drivers\etc\hosts file (requires Admin access)
	Add/update entry for pgw1.trustcommerce.com using the IPv4 address of PN97.   For example:
	
		10.11.2.193	pgw1.trustcommerce.com

	Note: remove this entry before testing against the actual PGW1
	
- Install Python PyWin32 COM handler   (required to use Win32 TCLink component)
	pip install pywin32
	
- Install latest TCLink Win32 component
	Version 4.4.0 can be found at: https://vault.trustcommerce.com/downloads/tclink-4.4.0-COM.zip
	
- Reboot to add C:\Program Files (x86)\TCLink to the path



Usage:
TC_transtest_all_autoselect_MSR.py [--custid CUSTID] [--password PASSWORD] [--action ACTION] [--serial SERIAL_PORT]
	If not supplied, the default CUSTID is 1152701
	If not supplied, the default PASSWORD is the current password for the default CUSTID
	If not supplied, the default ACTION is sale

 

