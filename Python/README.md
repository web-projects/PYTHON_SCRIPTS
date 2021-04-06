# Needed:
* python3
* python3 -m pip install pyserial colorama httplib2 pyparsing pydes

# Stream encryption setup
## Terminal setup
* mapp_prot.cfg has to have Stream encryption setup. i.e:
`[stream_encryption]
EncryptionEnabled=1
ClearCommands=00A4,00A5,00D6,00AB,00AA,D0D0,D000,DD21,DD22,DD23,D2D0,D0FF,D061,D2A1,D0B1,C001,C0C0,C000`
* `exclusions.dat` has to be set so that you could upload `p7s` for ssl certificates

## Test harness setup
To use stream encryption with ( any ) scripts one need to: 
* Use `generate_rsa.py` to process mutual authentication key  
    * First run needs to be proceed folowing: Yes to generation Yes to upload
    * Any next run: select default values ( N and Y )
* In any command used with Stream Encryption provide *warning* in fact all three parameters are needed for transactions
    * `--se_cert .certs/mutual_sek.dec` default used 3des key agreed throug generate_rsa.py
    * `--se_whitelist 00A4,00A5,00D6,00AB,00AA,D0D0,D000,DD21,DD22,DD23,D2D0,D0FF,D061,D2A1,D0B1,C001,C0C0,C000` where propper whitelist is in mapp_prot.cfg on terminal, that one is an example.
       it's needed so that testharness will know which commands shouldn't be cipherred
    * `--seq_num 420` incremential sequential number, it has to be bigger after each tests, for transtest_all.py where is ~10 to ~30 commands it's safe to increase it by 30 after each run.

*Warning*   When command is send with stream encryption on, in test harness log there will be in transaction: '-- SE --True' 
*warning*   In generall stream encryption is described in chapter '9' in docs.
