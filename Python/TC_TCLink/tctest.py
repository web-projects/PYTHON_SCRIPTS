#!/usr/bin/python
#
# Test script for TCLink Python client.
#

import tclink

print 'Using TCLink version', tclink.getVersion()

params = {
	'custid':    'TestMerchant',
	'password':  'password',
	'action':    'preauth',
	'cc':        '4111111111111111',
	'exp':       '0404',
	'amount':    '100',
	'avs':       'n'
}

result = tclink.send(params)

if result['status'] == 'approved':
	print 'The transaction was approved!'
elif result['status'] == 'decline':
	print 'The transaction was declined.'
else:
	print 'There was an error.'

print 'Here are the full details:'
print result

