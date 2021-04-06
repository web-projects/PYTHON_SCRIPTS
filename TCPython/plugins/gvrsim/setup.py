from distutils.core import setup, Extension

module1 = Extension('gvrsim',
                    define_macros = [('MAJOR_VERSION', '1'),
                                     ('MINOR_VERSION', '2')],
                    extra_compile_args = ['-Werror=implicit-function-declaration'],
                    include_dirs = ['./gvrsim/gvr_upm/include'],
                    libraries = ['ssl', 'crypto' ],
                    #library_dirs = [''],
                    sources = ['gvrsimmodule.c', 'gvrsim/gvr_upm/source/des.c',
                        'gvrsim/gvr_upm/source/rsa.c',
                        'gvrsim/gvr_upm/source/sha256.c','gvrsim/gvr_upm/source/upm_vault.c'])

setup (name = 'gvrsim',
       version = '1.2',
       description = 'GVR sim UX protocol',
       author = 'Lucjan Bryndza',
       author_email = 'Lucjan_B1@verifone.com',
       url = 'http://www.verifone.com',
       long_description = '''
       GVR sim simulation module
''',
       ext_modules = [module1])
