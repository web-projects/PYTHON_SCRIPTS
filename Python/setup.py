from distutils.core import setup

setup(
    name='Testharness',
    version='2.0.0',
    author='Lucjan Bryndza - Verifone',
    author_email='Lucjan_B1@verifone.com',
    packages=['testharness'],
    depends=[ 'serial>=2.6', 'httplib2>=0.7.4', 'pyparsing>=2.0.2', 'colorama>=0.2.4' ],
    package_data={'testharness': ['config/analyse.ini', 'config/testharness.xsl']},
    url='http://verifone.com/',
	license='GPLv2',
    description='Testharness utility',
    long_description="Testharness library classes for test VERIFONE terminals using vipa protocol",
    platforms="any"
    
)

