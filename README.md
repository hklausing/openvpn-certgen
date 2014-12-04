openvpn-certgen
===============

openvpn-certgen.pl is a self-signed certificate generator tool, used 
for OpenVPN. It covers multiple functions to get up a running OpenVPN 
installation on server and on client systems.

The script is able to install required packages and tools to set up an
OpenVPN server. This is done automatically if the script is started and
the required tools are not found. For each client a zip file will be
created with Windows and Linux data. This allows a convenient handling 
of different client certificates.

Currently supported client systems are Windows and 
Linux (Debian, Mint, Ubuntu).

Example usages
--------------

* First start of this script

	~~~
	# openvpn-certgen.pl  -t /tmp/etc/openvpn   		# run as root !
	~~~

	This prepares the required packages and tools to generate 
	certificates.
	
* Adjust config-file

	The config with default data needs to be adjusted with real data.

* Make client certificate

	~~~
	$ openvpn-certgen.pl -t /tmp/etc/openvpn client1
	~~~
	
	Creates a test environment to play with the server certificate and a
	client certificate for client1.

* More client certificates

	~~~
	$ openvpn-certgen.pl -t /tmp/etc/openvpn client1 client2 clinet3
	~~~
	
	Creates certificate for client2, client3. client1 will be ignored,
	a certificate is already existing.

* Configuration for working environment

	Next call is used if real certificates are required. The rest is 
	working as in the examples above.

	~~~
	# openvpn-certgen.pl  			 		# root !
	~~~

	This is used to create certificates under real conditions.
	
More Details
------------

The script has a detailed help information included. It can be checked
by ```openvpn-certgen --help```


Install project openvpn-certgen
===============================

There some options to install the script openvpn-certgen to a 
Linux system:

*   cpanm
*   manual
*   copy script

For all options the package openvpn-certgen-<version>.tar.gz needs 
to be download.


cpanm
-----

Using the tool cpanm is a simple and fast step to install 
openvpn-certgen to the system. Required Perl packages will be loaded, 
tests and installation will be made automatically.

1.  $ cpanm openvpn-certgen-<version>.tar.gz


manual
------

This option is used if cpanm is not existing on the target system. The
Perl module Module::Build is required for this step.

1.  $ tar -zxf openvpn-certgen-<version>.tar.gz
2.  $ cd openvpn-certgen 
3.  $ perl Build.pl
4.  $ perl Build
5.  $ sudo perl Build test
6.  $ sudo perl Build install


copy script
-----------

This step is for lazy people :-) It's required, that the use takes 
care for the correct execution environment.

1.  $ tar -zxf openvpn-certgen-<version>.tar.gz
2.  $ cp openvpn-certgen/script/openvpn-certgen.pl <target>

