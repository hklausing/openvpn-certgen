#!/usr/bin/perl
################################################################################
#
# File:     openvpn-certgen.pl
# Date:     2014-10-12
# Author:   H. Klausing
#
# openvpn-certgen.pl - Certification generator tool
# This script can be used to execute all required steps to a a privat set of
# certificates. It was designed to use mainly for OpenVPN.
#
# Function flow:
# - get distribution information
#
# Tidy: -l=128 -pt=2 -sbt=2 -bt=2 -bbt=2 -csc -csci=28 -bbc -bbb -lbl=1 -sob -bar -nsfs -nolq -iscl -sbc -ce -anl -blbs=4
#
# License:  See the attached file "LICENSE" for the full license GPL 3
#           governing this code.
#
################################################################################
# Update list:
# 2014-10-12    v0.001 H. Klausing
#               initial script
################################################################################
#
#
################################################################################
#
#
#
#
#--- perl restrictions -----------------
use strict;
use warnings;
#
#
#--- modulino function -----------------
package openvpn_certgen;    # for script testability

#--- used packages ---------------------
use Readonly;
use English qw( -no_match_vars );
use File::Basename;
use File::Copy qw(copy);                  # for copy()
use File::Copy::Recursive qw(dircopy);    # for dircopy()
use File::Path qw(make_path remove_tree);
use File::Spec;
use Getopt::Long;
use Config::Tiny;
use Cwd qw(abs_path);
use Archive::Zip qw( :ERROR_CODES :CONSTANTS );
use Archive::Tar;
use File::Find;
use Pod::Usage;
use Carp qw(croak);                       # required for croak()
#
#
#
#--- constants -------------------------
our $VERSION = '0.001';
my $RELEASE_DATE = '2014-09-24';
Readonly::Hash my %DISTRIBUTION_LIST => (
    'Debian' => {
        'easyrsa_trg'  => '/usr/share/doc/openvpn/examples/easy-rsa',
        'easyrsa_path' => '/usr/share/doc/openvpn/examples/easy-rsa/2.0',
        'install'      => 'apt-get install -y',
        'package'      => 'openvpn',
        'installcheck' => 'dpkg-query -W openvpn > /dev/null 2>&1',         # true if package is installed
        'installhint'  => 'apt-get install openvpn'
    },
);
Readonly::Scalar my $EASY_RSA_URI => 'http://build.openvpn.net/downloads/releases/easy-rsa-2.2.0_master.tar.gz';
#
#
#
Readonly my $SCRIPTNAME => File::Basename::basename($0);
#
#
#
#--- global variables --------------------------------------------------
my %g_options     = ();
my %g_distributor = ();
my %g_paths       = ();
my $g_dist_ref    = undef;    #reference to found distributor value
my $g_config      = undef;    # reference to configuration file value
#
#
#--- script function start -------------
__PACKAGE__->main(@ARGV) unless caller();    # based on Modulino
#main();
#
#
#
################################################################################
#
# Function block
#
################################################################################
#
#
#
sub main {
    ############################################################################
    # Main script entry
    # Param1:   -
    # Return:   -
    ############################################################################
    #    my $pkg = shift;    # remove package name from option list
    my $sts = 0;

    # define options default values
    %g_options = (
        'clean'   => 0,                 # 1: removes copied path structure and all generated certificates
        'force'   => 0,                 # 1= force recreation of client certificate
        'help'    => 0,                 # 1: will display a help text
        'keep'    => 0,                 # 1= keep unused paths and files
        'list'    => 0,                 # lists defined settings
        'setup'   => 0,                 # 1= installes the configuration file and the certificates to /etc/openvnc directory
        'target'  => '/etc/openvpn',    # target directry for certificates
        'verbose' => 0,                 # verbose level: 0: silent, 1: standard, 2: many, 3: debug, 4:detailed
    );
    my $result = GetOptions(
        'c|clean'     => \$g_options{'clean'},
        'f|force'     => \$g_options{'force'},
        'h|help'      => sub {help();},
        'k|keep'      => \$g_options{'keep'},
        'l|list'      => \$g_options{'list'},
        's|setup'     => \$g_options{'setup'},
        't|target=s'  => \$g_options{'target'},
        'v|verbose=i' => \$g_options{'verbose'},
        'version'     => sub {version();},
        'man'         => sub {information();},
    );

    #check option scan result
    if (not $result) {
        errorHelp("wrong script argument");
    }

    # prepare check
    my $testuser = (-W getLastExistingDir($g_options{'target'}))? 0 : 1;
    $sts = checkExecutionRequirements('TestUser' => $testuser);

    if ($g_options{'clean'} == 0 && !$sts) {

        # get list of clients if option 'clean' is not active
        foreach my $client (@ARGV) {

            if ($client =~ /^\w+$/) {
                push(@{$g_options{'clients'}}, $client);
                notify(3, "Client found: '$client'");
            } else {
                error("Found client name '$client' is wrong; only these characters are allowed: a-z, A-Z, 0-9, _");
                $sts = 1;
            }
        }
    }
    $sts = getDistributionData()    unless ($sts);
    $sts = setDefaultValues()       unless ($sts);
    $sts = updatePaths()            unless ($sts);
    $sts = checkSystemEnvironment() unless ($sts);
    $sts = processFlow()            unless ($sts);
    notify(1, "... done");
    return $sts;
} ## end sub main




sub processFlow {
    ############################################################################
    # Process the script flow depending of the current script options.
    # Param1:   Reference to JSON setting data
    # Return:   0: execution was successful
    #           1: JSON file not found
    ############################################################################
    my $sts = 0;

    if ($g_options{'clean'}) {

        # delete copied path structure and all certificates
        $sts = doClean();
    } else {
        $sts = activateKeysFiles();                   # directory keys must be existing
        $sts = initCertificatPaths() unless ($sts);
        $sts = activateKeysFiles() unless ($sts);
        $sts = updateVars() unless ($sts);

        if ($g_options{'list'}) {

            # list the content of the script configuration file
            $sts = listParameter() unless ($sts);
        } else {

            # start certificate generation
            $sts = makeMasterCertificateAndKey() unless ($sts);
            $sts = buildDiffieHellmanKey()       unless ($sts);
            $sts = makeServerCertificate()       unless ($sts);

            foreach my $client (@{$g_options{'clients'}}) {
                if ($sts == 0) {
                    $sts = makeClientCertificate($client);
                    notify(1, "Client certificate and key for '$client' generated") unless $sts;
                }
            }

            # create a zip file of created certificates and log-files
            $sts = storeKeysFiles() unless ($sts);

            if ($g_options{'keep'} == 0) {

                # remove not required directories
                remove_tree($g_paths{'OVPN-easy-rsa'});
            }
        }
    } ## end else [ if ($g_options{'clean'...})]
    return $sts;
} ## end sub processFlow




sub doClean {
    ############################################################################
    # Execute the clean procedure.
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts = 0;

    if (-d $g_paths{'OVPN-easy-rsa'}) {

        #        isRoot();    # checks if the current user is root
        remove_tree($g_paths{'OVPN-easy-rsa'});
        notify(3, "Path '$g_paths{'OVPN-easy-rsa'}' deleted.");
    }

    if (-d $g_paths{'OVPN-certificates'}) {

        #        isRoot();    # checks if the current user is root
        remove_tree($g_paths{'OVPN-certificates'});
        notify(3, "Path '$g_paths{'OVPN-certificates'}' deleted.");
    }
    return $sts;
} ## end sub doClean




sub initCertificatPaths {
    ############################################################################
    # Checks if all required paths and files created and/or copied
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts = 0;

    # target path
    my $path = $g_paths{'OVPN-target'};

    if (!-d $path) {
        make_path($path);
        notify(2, "Path '$path' created");
    }

    # certificate path
    $path = $g_paths{'OVPN-certificates'};

    if (!-d $path) {
        make_path($path);
        notify(2, "Path '$path' created");
    }

    # easy-rsa path
    $path = $g_paths{'OVPN-easy-rsa'};

    if (!-d $path) {
        make_path($path);
        notify(2, "Path '$path' created");
        $sts = copyEasyRsa() unless ($sts);
    }

    # easy-rsa keys path
    $path = $g_paths{'OVPN-easy-rsa-keys'};

    if (!-d $path) {
        make_path($path);
        notify(2, "Path '$path' created");
    }

    # easy-rsa config path
    $path = $g_paths{'OVPN-config'};

    if (!-d $path) {
        make_path($path);
        notify(2, "Path '$path' created");
    }
    $sts = getConfigFile() unless ($sts);
    return $sts;
} ## end sub initCertificatPaths




sub activateKeysFiles {
    ############################################################################
    # If the archive file keys.zip is existing it will be unpacked to the
    # certificates directory.
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts          = 0;
    my $archive_file = File::Spec->rel2abs($g_paths{'OVPN-certificates'} . '/keys.tar.gz');

    if (-e $archive_file) {

        # change current directory
        my $current_directory = cwd();
        chdir($g_paths{'OVPN-easy-rsa'});

        # restore content of archived file
        my $tar = Archive::Tar->new();
        $tar->read($archive_file);
        my @extracted = $tar->extract();

        # restore current directory
        chdir($current_directory);

        if (!@extracted) {
            error("Archive file '$archive_file' extraction failed!");
            $sts = 1;
        } else {
            notify(3, "Archive file '$archive_file' restored.");
        }
    } else {
        notify(3, "Archive file '$archive_file' not existing.");
    }
    return $sts;
} ## end sub activateKeysFiles




sub storeKeysFiles {
    ############################################################################
    # Stores all files aund directories of the keys folder for lateretConfigFile
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    # Create inventory of files & directories
    my $sts               = 0;
    my $archive_file      = File::Spec->rel2abs($g_paths{'OVPN-certificates'} . '/keys.tar.gz');
    my $current_directory = cwd();
    chdir($g_paths{'OVPN-easy-rsa'});
    my @inventory = ();
    find(sub {push @inventory, $File::Find::name}, './keys');

    if (@inventory) {
        my $result = Archive::Tar->create_archive($archive_file, COMPRESS_GZIP, @inventory);

        unless ($result) {
            error("Archive file creation '$archive_file' failed!");
            $sts = 1;
        } else {
            notify(3, "tar file '$archive_file' created.");
        }
    } else {
        error("No content in '$archive_file' stored!");
        $sts = 1;
    }
    chdir($current_directory);
    return $sts;
} ## end sub storeKeysFiles




sub getConfigFile {
    ############################################################################
    # SetConfigFile creates a new script configuration file if it not existing.
    # If the config file is existing this function reads the content.
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    #           2: stop script
    ############################################################################
    my (%values)   = @_;
    my $sts        = 0;
    my $configFile = $g_paths{'OVPN-config'} . '/openvpn-certgen.conf';

    if (-f $configFile) {

        # read config file if it is existing
        $g_config = Config::Tiny->read($configFile);
        notify(2, "Config file '$configFile' read");
    } else {

        # create a default configuration file
        $sts = createConfigFile($configFile);
    }
    return $sts;
} ## end sub getConfigFile




sub createConfigFile {
    ############################################################################
    # Creates a default configuration file.
    # Param1:   file name of config file.
    # Return:   0: check was successful
    #           1: one or more options are bad
    #           2: stop script
    ############################################################################
    my ($file) = @_;
    my $sts = 0;
    $g_config = Config::Tiny->new;
    $g_config->{'vars'} = {
        'KEY_SIZE'     => '2048',                  # 1024/2048
        'CA_EXPIRE'    => '3650',
        'KEY_EXPIRE'   => '3650',
        'KEY_COUNTRY'  => "DE",                    # Country Name (2 letter code)
        'KEY_PROVINCE' => "Bavaria",               #
        'KEY_CITY'     => "Munich",                # Locality Name (eg, city)
        'KEY_ORG'      => "HappyProgramming",      # Organization Name (eg, company)
        'KEY_EMAIL'    => 'me@myhost.mydomain',    # Email Address
        'KEY_CN'       => 'server',                # Common Name
        'KEY_NAME'     => 'Ja Mei',                # Name
        'KEY_OU'       => 'IT-Fun',                # Organizational Unit Name (eg, section)
    };
    $g_config->{'controls'} = {
        'dev'      => 'tun',                          # server and client device type
        'proto'    => 'udp',                          # server and client protocol
        'port'     => '1194',                         # server and client port
        'server'   => '10.8.0.0 255.255.255.0',       # virtual network address
        'cipher'   => 'AES-256-CBC',                  # cipher type
        'remote'   => 'tomy.homenet.org',             # server address for clients to get the server
        'route'    => '192.168.1.0 255.255.255.0',    # local routing for clients
        'localadr' => '192.168.1.1',                  # local server network address
        'domain'   => 'my.homenet.local',             # fqdn of local server
    };
    $g_config->write($file);
    notify(2, "Config file '$file' with default values created");
    warning("It is proposed to update the file '$file' to you needs!\nScript execution was stopped ->  vi $file");
    $sts = 2;
    return $sts;
} ## end sub createConfigFile




sub updateVars {
    ############################################################################
    # This subfunction updates the vars file with the required values from the
    # configuration file.
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts          = 0;
    my $content_vars = '';
    my $vars_file    = $g_paths{'OVPN-easy-rsa'} . '/vars';

    # read file content
    {
        local $INPUT_RECORD_SEPARATOR = undef;
        open(my $fh, '<', $vars_file) or croak("Error: file '$vars_file' open failed!");
        $content_vars = <$fh>;
        close $fh or croak("Error: file '$vars_file' close failed!");
    }

    #  update values
    foreach my $key (keys(%{$g_config->{'vars'}})) {
        my $value = $g_config->{'vars'}{$key};
        $content_vars =~ s/^(export\s+$key="?).*?("?\s*)$/$1$value$2/m;
    }

    # write file content back
    open(my $fh, '>', $vars_file) or croak("Error: file '$vars_file' open failed!");
    print $fh $content_vars;
    close $fh or croak("Error: file '$vars_file' close failed!");
    notify(2, "File '$vars_file' updated");
    return $sts;
} ## end sub updateVars




sub listParameter {
    ############################################################################
    # Lists used parameters
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts = 0;
    print("Section: vars\n");

    foreach my $key (sort(keys(%{$g_config->{'vars'}}))) {
        my $value = $g_config->{'vars'}{$key};
        print("  $key = \"$value\"\n");
    }
    print("\nSection: controls\n");

    foreach my $key (sort(keys(%{$g_config->{'controls'}}))) {
        my $value = $g_config->{'controls'}{$key};
        print("  $key = \"$value\"\n");
    }
    $sts = 1;
    return $sts;
}




sub makeMasterCertificateAndKey {
    ############################################################################
    # Build a root certificate and a root key if these values not existing
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts    = 0;
    my $ca_crt = $g_paths{'OVPN-easy-rsa-keys'} . '/ca.crt';
    my $ca_key = $g_paths{'OVPN-easy-rsa-keys'} . '/ca.key';

    if (not(-f $ca_crt) || not(-f $ca_key)) {
        doCleanAll();
        notify(3, "Clean-up of paths done.");
        doBuildCa();
        notify(2, "Private master key and certificate generated -> ca.key & ca.crt");
    } else {
        notify(2, "Private master key and certificate were existing");
    }
    return $sts;
}




sub makeServerCertificate {
    ############################################################################
    # Build a root certificate and a root key if these values not existing
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts      = 0;
    my $name_crt = $g_paths{'OVPN-easy-rsa-keys'} . '/' . $g_config->{'vars'}{'KEY_CN'} . '.crt';

    if (not(-f $name_crt) || $g_options{'force'}) {
        doBuildKeyServer();
        notify(2, "Server certificate generated -> server.crt & server.key");
        buildServerCertificatePackage();
    } else {
        notify(2, "Server certificate was existing");
    }
    return $sts;
}




sub buildDiffieHellmanKey {
    ############################################################################
    # Build Diffie-Hellman parameter for server.
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my ($client) = @_;
    my $sts      = 0;
    my $fileDh   = 'dh' . $g_config->{'vars'}{'KEY_SIZE'} . '.pem';
    my $dh_pem   = $g_paths{'OVPN-easy-rsa-keys'} . '/' . $fileDh;

    if (not(-f $dh_pem)) {
        doBuildDiffieHellman($client);
        notify(2, "Diffie-Hellman parameter generated -> $fileDh");
    } else {
        notify(2, "Diffie-Hellman parameter file was existing.");
    }

    #$sts = 1;
    return $sts;
}




sub makeClientCertificate {
    ############################################################################
    # Build a clinet certificate.
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my ($client)   = @_;
    my $sts        = 0;
    my $client_crt = $g_paths{'OVPN-easy-rsa-keys'} . '/' . $client . '.crt';
    my $client_key = $g_paths{'OVPN-easy-rsa-keys'} . '/' . $client . '.key';

    if (not(-f $client_crt) || not(-f $client_key) || ((-s $client_crt) == 0) || $g_options{'force'}) {
        doBuildKeyClient($client);

        # check if *.crt file contains information
        if (-s $client_crt) {
            notify(2, "Client certificate for '$client' generated");
            buildClientCertificatePackage($client);
        } else {

            # *.crt data has no content, delete client files and inform the user
            unlink(glob($g_paths{'OVPN-easy-rsa-keys'} . '/' . $client . '.*'));
            error("Certificate for '$client' is empty; all generated files for this client were deleted!");
            $sts = 1;
        }
    } else {
        notify(2, "Client '$client' certificate was existing");
    }
    return $sts;
} ## end sub makeClientCertificate




sub doCleanAll {
    runCommand("./clean-all");
    return 0;
}




sub doBuildCa {
    runCommand('EASY_RSA="${EASY_RSA:-.}"', './pkitool --initca');
    return 0;
}




sub doBuildKeyServer {
    runCommand('EASY_RSA="${EASY_RSA:-.}"', './pkitool --server');
    return 0;
}




sub doBuildKeyClient {
    my ($client) = @_;
    runCommand('KEY_CN=$client', './build-key --batch ' . $client);
    return 0;
}




sub doBuildDiffieHellman {
    runCommand('./build-dh');
    return 0;
}




sub runCommand {
    my (@list) = @_;
    my $command = '. ./vars;' . join(';', @list);
    notify(2, "Command: $command");
    my $currentDir = cwd();
    chdir($g_paths{'OVPN-easy-rsa'});
    system("sh -c '$command'");
    chdir($currentDir);
    return 0;
}




sub buildServerCertificatePackage {
    ############################################################################
    # This subfunction builds a package for the processed server certificate and
    # key that can be used directly on the client PC. The package contains a
    # Linux and a Windows OpenVPN configuration file.
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts = 0;

    # create a temporary directory structure and copy required files to it.
    my $dirServer = $g_paths{'OVPN-certificates'} . '/server';
    make_path($dirServer);
    my $dirLinux = $g_paths{'OVPN-certificates'} . '/server/linux';
    make_path($dirLinux);
    my $dirWindows = $g_paths{'OVPN-certificates'} . '/server/win';
    make_path($dirWindows);
    my $dirSource = $g_paths{'OVPN-easy-rsa-keys'};
    my $dh_file   = 'dh' . $g_config->{'vars'}{'KEY_SIZE'} . '.pem';
    copy($dirSource . '/ca.crt',      $dirLinux . '/ca.crt')      or croak("Copy failed: $!");
    copy($dirSource . '/' . $dh_file, $dirLinux . '/' . $dh_file) or croak("Copy failed: $!");
    copy($dirSource . '/server.crt',  $dirLinux . '/server.crt')  or croak("Copy failed: $!");
    copy($dirSource . '/server.key',  $dirLinux . '/server.key')  or croak("Copy failed: $!");
    buildReadmeFile($dirLinux, 'linux', $dirLinux . '/server.crt');
    copy($dirSource . '/ca.crt',      $dirWindows . '/ca.crt')      or croak("Copy failed: $!");
    copy($dirSource . '/' . $dh_file, $dirWindows . '/' . $dh_file) or croak("Copy failed: $!");
    copy($dirSource . '/server.crt',  $dirWindows . '/server.crt')  or croak("Copy failed: $!");
    copy($dirSource . '/server.key',  $dirWindows . '/server.key')  or croak("Copy failed: $!");
    buildReadmeFile($dirWindows, 'windows', $dirWindows . '/server.crt');
    notify(3, "Server path structure created and files copied.");

    # create a OpenVPN configuration file
    my $content = <<"EOF";
# Automatic generated OpenVPN configuration file for server.
# Defined for 1 Server and multiple Clients.
# Generator program: $SCRIPTNAME
# Generator version: $VERSION
# BS Version:        (ostype)
# File:              /etc/openvpn/server.conf

dev             $g_config->{'controls'}{'dev'}
proto           $g_config->{'controls'}{'proto'}
port            $g_config->{'controls'}{'port'}
dh              ./certs/$dh_file
ca              ./certs/ca.crt
cert            ./certs/server.crt
key             ./certs/server.key
ifconfig-pool-persist ipp.txt
server          $g_config->{'controls'}{'server'}
push            "dhcp-option DOMAIN $g_config->{'controls'}{'domain'}"
push            "dhcp-option DNS  $g_config->{'controls'}{'localadr'}"
push            "dhcp-option NTP  $g_config->{'controls'}{'localadr'}"
push            "dhcp-option WINS $g_config->{'controls'}{'localadr'}"
push            "route $g_config->{'controls'}{'route'}"
push            "redirect-gateway"
cipher          $g_config->{'controls'}{'cipher'}
user            openvpn
group           openvpn
status          /var/log/openvpn-status.log
comp-lzo
verb            3
keepalive       10 120
link-mtu
persist-key
persist-tun
client-to-client
tun-mtu         1500
tun-mtu-extra   32
fragment        1300
mssfix

EOF
    my $linuxOutput = $content;
    $linuxOutput =~ s/\(ostype\)/Linux/;
    open(my $fh, '>', $dirLinux . '/server.conf') or croak();
    print $fh $linuxOutput;
    close($fh);

    # create a directory /etc/openvpn with config and certificate files
    if ($sts == 0 and $g_options{'setup'}) {
        my $dirEtc      = '/etc/openvpn';
        my $dirEtcCerts = $dirEtc . '/certs';
        make_path($dirEtc);
        make_path($dirEtcCerts);
        copy($dirSource . '/' . $dh_file, $dirEtcCerts . '/' . $dh_file) or croak("Copy failed: $!");
        copy($dirSource . '/ca.crt',      $dirEtcCerts . '/ca.crt')      or croak("Copy failed: $!");
        copy($dirSource . '/server.crt',  $dirEtcCerts . '/server.crt')  or croak("Copy failed: $!");
        copy($dirSource . '/server.key',  $dirEtcCerts . '/server.key')  or croak("Copy failed: $!");
        copy($dirLinux . '/server.conf',  $dirEtc . '/server.conf')      or croak("Copy failed: $!");
    }
    my $winOutput = $content;
    $winOutput =~ s/\(ostype\)/Windows/;
    open($fh, '>', $dirWindows . '/server.conf') or croak();
    print $fh $winOutput;
    close($fh);
    notify(3, "Server configuration file created and copied.");

    # create a zip file from the created path structure
    my $zip = Archive::Zip->new();
    $zip->addTree($dirServer, 'server');    # Add a directory

    unless ($zip->writeToFileNamed($g_paths{'OVPN-certificates'} . '/server.zip') == AZ_OK) {
        croak('write error');
    }
    notify(3, "Server certificate package created.");

    if ($g_options{'keep'} == 0) {

        # delete path structure
        remove_tree($dirServer);
    }
    return $sts;
} ## end sub buildServerCertificatePackage




sub buildClientCertificatePackage {
    ############################################################################
    # This subfunction builds a package for the processed client certificate and
    # key that can be used directly on the client PC. The package contains a
    # Linux and a Windows OpenVPN configuration file.
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my ($client) = @_;
    my $sts = 0;

    # create a temporary directory structure and copy required files to it.
    my $dirClient = $g_paths{'OVPN-certificates'} . '/' . $client;
    make_path($dirClient);
    my $dirLinux = $g_paths{'OVPN-certificates'} . '/' . $client . '/linux';
    make_path($dirLinux);
    my $dirWindows = $g_paths{'OVPN-certificates'} . '/' . $client . '/win';
    make_path($dirWindows);
    my $dirSource = $g_paths{'OVPN-easy-rsa-keys'};
    copy($dirSource . '/ca.crt',              $dirLinux . '/ca.crt');
    copy($dirSource . '/' . $client . '.crt', $dirLinux . '/client.crt');
    copy($dirSource . '/' . $client . '.key', $dirLinux . '/client.key');
    buildReadmeFile($dirLinux, 'linux', $dirLinux . '/client.crt');
    copy($dirSource . '/ca.crt',              $dirWindows . '/ca.crt');
    copy($dirSource . '/' . $client . '.crt', $dirWindows . '/client.crt');
    copy($dirSource . '/' . $client . '.key', $dirWindows . '/client.key');
    buildReadmeFile($dirWindows, 'windows', $dirWindows . '/client.crt');
    notify(3, "Client path structure created and files copied.");

    # create a OpenVPN configuration file
    my $content = <<"EOF";
# Automatic generated OpenVPN configuration file for client.
# Generator program: $SCRIPTNAME
# Generator version: $VERSION
# BS Version:        (ostype)
# File:              /etc/openvpn/client.conf

dev             $g_config->{'controls'}{'dev'}
proto           $g_config->{'controls'}{'proto'}
port            $g_config->{'controls'}{'port'}
remote          $g_config->{'controls'}{'remote'}
resolv-retry    infinite
nobind
ca              ./certs/ca.crt
cert            ./certs/client.crt
key             ./certs/client.key
client
cipher          $g_config->{'controls'}{'cipher'}
comp-lzo
verb            3
persist-key
persist-tun
script-security 3
ns-cert-type    server
tun-mtu         1532
fragment        1400
user            openvpn
group           openvpn
EOF
    my $linuxOutput = $content;
    $linuxOutput =~ s/\(ostype\)/Linux/;
    open(my $fh, '>', $dirLinux . '/client.conf') or croak();
    print $fh $linuxOutput;
    close($fh);
    my $winOutput = $content;
    $winOutput =~ s/\(ostype\)/Windows/;
    open($fh, '>', $dirWindows . '/client.conf') or croak();
    print $fh $winOutput;
    close($fh);
    notify(3, "Client configuration file created and copied.");

    # create a zip file from the created path structure
    my $zip = Archive::Zip->new();
    $zip->addTree($dirClient, $client);    # Add a directory

    unless ($zip->writeToFileNamed($g_paths{'OVPN-certificates'} . '/' . $client . '.zip') == AZ_OK) {
        croak('write error');
    }
    notify(3, "Client certificate package created.");

    if ($g_options{'keep'} == 0) {

        # delete path structure
        remove_tree($dirClient);
    }
    return $sts;
} ## end sub buildClientCertificatePackage




sub buildReadmeFile {
    ############################################################################
    # Builds a readme ASCII test file with some text informations about the
    # start and end time of the certificate.
    # Param1:   Name of the target directory for the read me file. This
    #           directory must be existing.
    # Param2:   Name of the Operating System
    # Param2:   Name of the certificate with start and stop date/time
    #           information.
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my ($target_dir, $os, $certificate) = @_;
    my $sts = 0;
    my %info = ('start' => 'not found', 'end' => 'not found');
    open(my $fh, '<', $certificate) or croak("File not found, $!");

    foreach my $line (<$fh>) {

        #notify(3, "::$line");
        if ($line =~ /Not Before: (.+)$/) {
            $info{'start'} = $1;
            notify(3, "Certificate start date/time found: $info{'start'}");
        } elsif ($line =~ /Not After : (.+)$/) {
            $info{'end'} = $1;
            notify(3, "Certificate end date/time found: $info{'end'}");
            last;
        }
    }
    close($fh);
    my %comments;

    if ($os =~ /linux/i) {
        $comments{'os'}    = 'Linux';
        $comments{'usage'} = <<'EOF';
For linux clients it is recommented to use the networkmanager. Add the package
'network-manager-openvpn' and let it handle the OpenVPN communication.
After installation execute following steps:
 1) create path: /home/<user>/openvpn/certs
 2) copy all files of this directory to the new one
 3) select networkmanager
 4) add new VPN setting
 5) select connction type OpenVPN
 6) set connection name: e.g. OpenVPN-Hostname
 7) set gateway address to access the OpenVPN server: e.g. abc.dyndns.com
 8) Authentification type: Certificate (TLS)
 9) select file of Certificate user (CA): /home/<user>/openvpn/certs/client.crt
10) select file of Certificate of ...: /home/<user>/openvpn/certs/ca.crt
11) select file of Privat Key: /home/<user>/openvpn/certs/client.key
12) select Optional …
13) select renogoration interval with 60
14) activate LZO-Compression
15) unselect TCP protocal related to the settings
16) unselect TAB device related to the settings
17) select TUN for tunnel with 1532
18) select UDP fragment with 1400

EOF
    } ## end if ($os =~ /linux/i)
    elsif ($os =~ /windows/i) {
        $comments{'os'}    = 'Windows';
        $comments{'usage'} = <<'EOF';
For Windows clients it is recommented to use ...
EOF
    }
    my $readme = <<"EOF";
Information about the generated certificate is listed below.

Operating System:     $comments{'os'}
Start of Certificate: $info{'start'}
End of Certificate:   $info{'end'}

$comments{'usage'}
EOF
    open($fh, '>', $target_dir . '/readme.txt') or croak("File creation failed, $!");
    print $fh $readme;
    close($fh);
    return $sts;
} ## end sub buildReadmeFile




sub getDistributionData {
    ############################################################################
    # Gets the distributor information of the current environment. The results
    # stored in the global variable %g_distributor:
    # 'name'    - name of the distribution
    # 'id'      - ID of the distribution
    # 'group'   - group of distribution like debian, suse, redhat, ...
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts = 0;

    # get distribution, start with lsb_release
    my $executable = `whereis lsb_release` // '';
    $executable =~ s/^.*://;    # remove search file and get path info

    if ($executable) {
        if ($executable) {
            $g_distributor{'name'} = `lsb_release --id` // 'unknown';
            $g_distributor{'name'} =~ s/.*:\s*(.*)\s*$/$1/;

            if ($g_distributor{'name'} =~ /(Ubuntu|Mint)/i) {
                $g_distributor{'group'} = 'Debian';
            }
            $g_distributor{'id'} = `lsb_release --release` // 'unknown';
            $g_distributor{'id'} =~ s/.*:\s*(.*)\s*$/$1/;
        }
    }

    if (not defined($g_distributor{'group'})) {

        # distribution not detected
        error("Distribution not detected, check getDistributionData()");
        $sts = 1;
    } elsif (not defined($DISTRIBUTION_LIST{$g_distributor{'group'}})) {

        # distribution not detected
        error("Distribution not supported, check getDistributionData()");
        $sts = 1;
    } else {
        $g_dist_ref = $DISTRIBUTION_LIST{$g_distributor{'group'}};
        notify(3, "Distribution version is supported.");
    }
    return $sts;
} ## end sub getDistributionData




sub checkSystemEnvironment {
    ############################################################################
    # Check the environment of the system against required programs, file and
    # similar stuff.
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts = 0;

    #    $sts = isPackageInstalled_OpenVPN() unless ($sts);
    $sts = getEasyRsaData()          unless ($sts);
    $sts = checkEasyRsaExamplePath() unless ($sts);
    return $sts;
}




sub checkExecutionRequirements {
    ############################################################################
    # Check the if all require programs, permissions and settings available to
    # execute this script.
    # Param1:   List of optional test flag names
    #           'TestOS' - 1 (default) = Operation system has to be checked
    #           'TestDist' - 1 (default) = Distribution is checked
    #           'TestUser' - 1 (default) = user root is required
    #           'TestPackage' - 1 (default) = OpenVPN package is required
    # Return:   0: check was successful, all requirements fulfilled
    #           1: one or more requirements not found
    ############################################################################
    my (%options) = @_;
    my $sts = 0;

    # check OS, Linux is required
    if ($options{'TestOS'} // '1') {

        if (!($OSNAME =~ /linux/i)) {
            error("Required OS is not Linux!");
            $sts = 1;
        } else {
            notify(2, "OS is Linux.");
        }
    }

    # check if distribution is supported
    if ($options{'TestDist'} // '1') {
        use Linux::Distribution qw(distribution_name distribution_version);
        my $linux  = Linux::Distribution->new;
        my $distro = $linux->distribution_name();

        if (!($distro =~ /^(linuxmint|debian|ubuntu)$/i)) {
            error("distribution '$distro' is not supported!");
            $sts = 1;
        } else {
            notify(2, "Distribution '$distro' is supported.");
        }
    }

    # check if user is root
    if ($options{'TestUser'} // '1') {

        if ($REAL_USER_ID != 0) {
            error("User is not root!");
            $sts = 1;
        } else {
            notify(2, "User is root");
        }
    }

    # check OpenVPN package
    if ($options{'TestUser'} // '1') {
        $sts = isPackageInstalled_OpenVPN() unless ($sts);
    }
    return $sts;
} ## end sub checkExecutionRequirements




sub isPackageInstalled_OpenVPN {
    ############################################################################
    # Check if the OpenVPN distribution package is installed. If it is
    # installed return with 0, otherwise display an error message.
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts = 0;

    # check if openvpn package is installed
    my $result = system($DISTRIBUTION_LIST{$g_distributor{'group'}}{'installcheck'});

    if ($result) {
        error(    "OpenVPN package $DISTRIBUTION_LIST{$g_distributor{'group'}}{'package'} not found!\n"
                . "Use following command:\n\n"
                . "  $DISTRIBUTION_LIST{$g_distributor{'group'}}{'installhint'}\n\n"
                . "to install OpenVPN package.");
        $sts = 1;
    } else {
        notify(3, "OpenVPN package $DISTRIBUTION_LIST{$g_distributor{'group'}}{'installhint'} is installed.");
    }
    return $sts;
} ## end sub isPackageInstalled_OpenVPN




sub getEasyRsaData {
    ############################################################################
    # Check if the OpenVPN distribution package is installed. If it is
    # installed return with 0, otherwise display an error message.
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts        = 0;
    my $target_dir = $DISTRIBUTION_LIST{$g_distributor{'group'}}{'easyrsa_trg'};

    if (-d $target_dir) {
        ## easy-rsa path exist
        notify(3, "Original easy-rsa path '$target_dir' found.");
    } else {
        ## easy-rsa path not found, try to load it from the web location
        if ($EFFECTIVE_USER_ID) {
            error(    "The path with easy-rsa data was not found! To fetch the easy-rsa data,\n"
                    . "you have to execute this script as root!");
            exit 1;
        }
        my $extract_path = '/tmp/';

        # load from web
        use File::Fetch;
        my $ff = File::Fetch->new('uri' => $EASY_RSA_URI);
        my $where = $ff->fetch('to' => $extract_path);

        if ($where) {
            notify(3, "easy-rsa data download successfull");

            # restore content of downloaded, archived file
            my $root_dir = extractTarGzFile($where, $extract_path);

            if ($root_dir eq '') {
                error("extraction of file $where failed!");
                exit 1;
            }
            my $copies = dircopy($root_dir . 'easy-rsa', $target_dir);

            if ($copies > 0) {
                notify(3, "easy-rsa data copied to '$target_dir'");

                # delete file and path
                unlink($where);
                remove_tree($root_dir);
            }
        } else {
            error("download of easy_rsa failed!\n" . "Check URI '$EASY_RSA_URI'");
            exit 1;
        }
        notify(3, "Original easy-rsa path '$target_dir' created.");
    } ## end else [ if (-d $target_dir) ]
    return $sts;
} ## end sub getEasyRsaData




sub checkEasyRsaExamplePath {
    ############################################################################
    # Check if the OpenVPN example path is existing
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts = 0;
    ## check paths
    if (-d $g_paths{'OVPN-installed'}) {
        notify(3, "Original path '$g_paths{'OVPN-installed'}' of OpenVPN found.");
    } else {
        error(    "OpenVPN example directory '$g_paths{'OVPN-installed'}' not found!\n"
                . "Use following command:\n\n"
                . "  $DISTRIBUTION_LIST{$g_distributor{'group'}}{'installhint'}\n\n"
                . "to install the required package.");
        $sts = 1;
    }
    return $sts;
}




sub setDefaultValues {
    ############################################################################
    # Check the content of given options. If one or more errors are detected,
    # inform the user and stop the script.
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts = 0;
    return $sts;
}




sub updatePaths {
    ############################################################################
    # Check the content of given options. If one or more errors are detected,
    # inform the user and stop the script.
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts = 0;
    $g_paths{'OVPN-installed'}     = $DISTRIBUTION_LIST{$g_distributor{'group'}}{'easyrsa_path'};
    $g_paths{'OVPN-target'}        = $g_options{'target'};
    $g_paths{'OVPN-easy-rsa'}      = $g_options{'target'} . '/easy-rsa';
    $g_paths{'OVPN-easy-rsa-keys'} = $g_options{'target'} . '/easy-rsa/keys';
    $g_paths{'OVPN-certificates'}  = $g_options{'target'} . '/certificates';
    $g_paths{'OVPN-config'}        = $g_options{'target'} . '/config';
    notify(3, "Path lists updated.");
    return $sts;
}




sub copyEasyRsa {
    ############################################################################
    # Check the content of given options. If one or more errors are detected,
    # inform the user and stop the script.
    # Param1:   -
    # Return:   0: check was successful
    #           1: one or more options are bad
    ############################################################################
    my $sts = 0;
    make_path($g_paths{'target'});

    if (-d $g_paths{'OVPN-installed'}) {
        dircopy($g_paths{'OVPN-installed'}, $g_paths{'OVPN-easy-rsa'});
        notify(2, "Path '$g_paths{'OVPN-installed'}' copied to '$g_paths{'OVPN-easy-rsa'}'");
    } else {
        error("OpenVPN example directory '$g_paths{'OVPN-installed'}' not found!");
    }
    return $sts;
}




sub extractTarGzFile {
    ############################################################################
    # Extract a tar.gz-file.
    # Param1:   file name of tar.gz-file
    # Param2:   target path [Optional]; if not listed the current directory
    #           will be used.
    # Return:   root directory name of extracted file if extraction was pass,
    #           otherwise the content is empty.
    ############################################################################
    my $targz_file = shift;
    my $extract_path = (shift // '.') . '/';
    $extract_path =~ s| \/ \/ |\/|smxg;

    # restore content of downloaded, archived file
    my $tar = Archive::Tar->new();
    $tar->read($targz_file);

    foreach my $file ($tar->list_files()) {
        my $target_file = ${extract_path} . ${file};
        my $sts = $tar->extract_file($file, $target_file);

        if (!$sts) {
            error("-> $target_file failed, $tar->{'_error'}");
            exit 1;
        }
    }
    return ($extract_path . $tar->{'_data'}[0]{name}) // '';
} ## end sub extractTarGzFile




sub getLastExistingDir {
    ############################################################################
    # Tests the given directory string and returns a value of the last
    # existing directory.
    # Param1:   directory name
    # Return:   existing directory based on the given string
    ############################################################################
    my ($dir) = @_;

    if($dir !~ /^ \/ /smx){
        ## directory is a relative name, add the current directory to it
        $dir = abs_path($dir) // '/';
    }
    while(! -d $dir) {
        $dir =~ s/ \w+ \/? $//smx;
    }
    return $dir;
} ## end sub extractTarGzFile




sub notify {
    ############################################################################
    # Outputs a text information if the current verbose level is less or
    # equal than the assigned test-output-level.
    # Param1:   assigned output level
    # Param2:   text information; can be a scalar or an array of output text.
    # Param3:   (option) if this parameter is designed to 0 no NEW-LINE
    #           character will be send after the text output.
    # Return:   -
    ############################################################################
    my ($level, $text, $lineend) = @_;

    if ($level <= $g_options{'verbose'}) {
        $lineend = $lineend // 1;

        # handle $text as string or array
        my $outLine;

        if (ref($text) eq 'ARRAY') {
            $outLine = join("", @{$text});
        } else {
            $outLine = ("$text");
        }
        $outLine .= $lineend ? "\n" : '';
        print($outLine);
    }
    return;
} ## end sub notify




sub warning {
    ############################################################################
    # Writes a text to the standard error device and adds a new line at the end.
    # Param1:   Name of the current class.
    # Param2:   text for display
    # Return:   -
    ############################################################################
    my ($text) = @_;
    $text //= "No output text defined";
    warn("$text\n");
    close(STDERR) or croak("unable to close: $!");    # keep the error text before help text
    return;
}




sub error {
    ############################################################################
    # Writes a text to the standard error device and adds a new line at the end.
    # Param1:   Name of the current class.
    # Param2:   text for display
    # Return:   -
    ############################################################################
    my ($text) = @_;

    if (not(defined($text))) {
        croak("No output text defined");
    } else {
        warning("ERROR: $text\n");
    }
    return;
}




sub errorHelp {
    ############################################################################
    # Writes a text to the standard error device and adds a new line at the end.
    # Param1:   Name of the current class.
    # Param2:   text for display
    # Return:   -
    ############################################################################
    my ($text) = @_;
    pod2usage('-message' => $text, '-verbose' => 2, '-noperldoc' => 1);
    exit 0;
}




sub version {
    ############################################################################
    # Displays a version information of the script.
    # Param1:   -
    # Return:   -
    ############################################################################
    print("v${VERSION}  (Release date: ${RELEASE_DATE})\n");
    exit 0;
}




sub information {
    ############################################################################
    # Displays a full script documentation about this script.
    # Param1:   -
    # Return:   -
    ############################################################################
    pod2usage('-verbose' => 2, '-noperldoc' => 1);
    exit 0;
}




sub help {
    ############################################################################
    # Displays a help information extracted from the POD of this script.
    # Param1:   -
    # Return:   -
    ############################################################################
    pod2usage('-verbose' => 1, '-noperldoc' => 1);
    exit 0;
}
#
#
#
__END__


=pod



=head1 NAME

openvpn-certgen.pl - Certificate Generator for OpenVPN

=head1 SYNOPSIS

 openvpn-certgen.pl [-c|--clean] [-f|--force] [-l|--list] [-s|--setup]
            [-t|--target PATH] [-v|--verbose LEVEL] [CLIENT ...]
 openvpn-certgen.pl -h|--help
 openvpn-certgen.pl --man

options:

=over 4

=item -c  --clean

Deletes created directories and files to restart a complete OpenVPN
configuration procedure. The configuration file will be kept to avoid inserting
required configuration parameters again.

=item -f | --force

Recreates a server and client certificate if it is existing.

=item -h | --help

Prints a short help information to the display.

=item -l | --list

Lists the content of the current configuration file to the display.

=item     --man

Prints more details about this script to the display.

=item -s | --setup

Installs a path F</etc/openvpn> with a configuration file and a path F<./certs> with
certificate files.

=item -t | --target  PATH

Sets the path name of target for certificates and temporary copies. If this
option is omitted the default value F</etc/openvpm> will be used.

=item -v | --verbose  LEVEL

Prints additional information during the script execution to the display. Higher
numbers will result more information.

=item CLIENT

It is possible to add names of clients. A package with a client certificate and
confguration files for Windows and Linux system will be packed.

The name of client can have the following characters: a-z, A-Z, 0-9, '_', '-' or
'.'. The size should not exceed 16 characters for easier handling.

=back




=head1 DESCRIPTION

openvpn-certgen.pl is a self-signed certificate generator tool, used for OpenVPN.
It covers multiple functions to get up a running OpenVPN installation on
server and on client systems.

The script is able to install required packages and tools to setup an
OpenVPN server. This is done automatically if the script is started and
the required tools are not found.

This tool has no functions to cancel certificates.

The script is using the OpenVPN easy-rsa tools.


=head2 Directories

If the option '--target path' is not used the default value F</etc/openvpn> will
be used. Otherwise the found path name will be used. Based on this path other
directory names will be used too. The following list gives an overview of these
paths.

=over 4

=item F<[basepath]>

This name defines the default value or a user defined directory name.

=item F<[basepath]/easy-rsa>

This path contains a copy of all files and directories of the installed
OpenVPN original easy-rsa directory. The original location will not modified
by this script.

=item F<[basepath]/easy-rsa/keys>

This path stores the generated keys, certificates and log files. The content
of this folder will be archived after each script session. This allows later
certifcate generations.

=item F<[basepath]/certificates>

The directory F<certificates> stores archive files of the server (server.zip)
and of each generated client (clientname.zip). This directory also stores
the archived F</easy-rsa/keys> path.

=item F<[basepath]/config>

This path contains the configuration data that are required by this script.
No other values required, except the required client names.

=back


=head1 WORKFLOW

On of the targets to start this script was to get an easy usable tool for
quick bring up an OpenVPN server and the required clients.

After installation of the tool OpenVPN and the package Easy-RSA this script
creates an default configuration file that has to be prepared by the user
with corrected data to bring get the openVPn in a operational status.

The statement 'easy usable tool' is shown in the following text that gives a
typically work flow which was tested with Mint 16 & 17.


=head2 Easy Usage

In the next chapters is the usage idea presented.

=head3 Step 1 (Prepare environment and create a default config file)

=over 4

=item - Required environment

If the OpenVPN package path is not found openvpn-certgen.pl trys to install
the required packages and tools.

=item - Required directory structure

All required directories will be created. The OpenVPN easy-rsa path
will be copied.

=item - Create configuration file

If openvpn-certgen.pl is started for the first time, a configuration file will
be created with default values. After the creation the script asks the
user to update the content of these file and stops execution.

If the configuration file is already existing the content will be read be
the script. openvpn-certgen.pl never overwrites or deletes an existing config file.

=back


=head3 Step 2 (Prepare config file)

The configuration file .../config/openvpn-certgen.conf has to be modified. Details
for the file content are listed in L<CONFIG FILE>.

It is proposed to rebuild all certificates if a modification was done after
a certificate was created (execution Step3 and Step4).


=head3 Step 3 (Create OpenVPN server certificate and configuration file)

If the configuration files is prepared a second execution of openvpn-certgen.pl
will create automatically all required file to build a server certificate
in one shot.

The second or all following calls can be used with a client name. If a
client name if found in the parameter list a zip-file will be created.
It includes Linux and Windows configuration files and certificate
data that are usable on the target systems.

If a client name is used multiple times the first zip-file will be
kept - no changes will be done.


=head3 Step 4 (Create OpenVPN client certificate and configuration file)

As mentioned in Step 3 if the server certificate is created than
certificates for clients can be created.


=head2 Range of Functions

=over 4

=item * Self-signed certificate

Build the private master certificate files ca.cert, ca.key and the
Diffie-Hellman file in the required size dimension. This part will be script,
if the files are existing.

=item * Creation of Server certificate and OpenVPN configuration file

If the server certificate and key files (server.crt & server.key) not
existing than these files will be created.

=item * Creation of Client certificates and OpenVPN configuration files

If the client certificate and key files (<client>.crt & <client>.key) not
existing than these files will be created.

=item * Creation of packages with certificates, keys and configuration files for
        server and clients

For the server and for each client an archive file will be created with the
required certificate, key and configuration files. This archive file contains
also a version for Windows and Linux for easier handling.

=back

=head2 Examples of Script Usage

=over 4

=item * Start requirements

This script requires root rights to create paths, files and certificates during
a session. Without these rights the function help and manual can be displayed.

If the user is not root and creation of certificate is chosen the user will be
informed that this script can not continue.

=item * First start

To do first tests it is easy to execute the script with an test path for the
certificate and key files.

    sudo openvpn-certgen -t=/tmp/etc/openvpn -v=3

This execution will create a configuration file with some dummy values. The
location of the file will be listed for easier access. The script does not
check if the content was changed.

=item * Second start

Now all required master and server configuration files will be created. Two
client names are also given and this information will be used to generated
client packages.

    sudo openvpn-certgen -t=/tmp/etc/openvpn -v=3 clientname1 clientname2

The packages are stored in F</tmp/etc/openvpn/certificates>.

=item * New client

A certificate for a new client can easily be created by executing the script
with the new client name.

    sudo openvpn-certgen -t=/tmp/etc/openvpn -v=3 clientname3

The package for clientname3 is stored in F</tmp/etc/openvpn/certificates>.

=item * Start a new round

If the generated certificates and keys needs to be deleted than the following
execution will do that.

    sudo openvpn-certgen -t=/tmp/etc/openvpn -c

The paths F</tmp/etc/openvpn/certificates> & F</tmp/etc/openvpn/easy-rsa> are
deleted.

=item * Keep result files

If it is required to have an simple access to the generated certificates and
keys than disallow deleting of the path easy-rsa.

    sudo openvpn-certgen -t=/tmp/etc/openvpn -k

The path F</tmp/etc/openvpn/easy-rsa> will be kept after script execution.

=back




=head1 CONFIG FILE

The configuration file is an ASCII ini-file. Two sections are used to
build the certificates and the needed configurations files for server
and the clients:


=head2 Section [controls]

This section is used to build the configuration files for the server
and clients. The following list shows the used keys:

=over 4

=item * cipher

Cipher defines the encryption between OpenVPN server and the clients,
details can be found in the OpenVPN documentation
L<http://openvpn.net/index.php/access-server/docs/admin-guides/437-how-to-change-the-cipher-in-openvpn-access-server.html>

Default setting: cipher=AES-256-CBC

=item * dev

Key dev defines the virtual network device for OpenVPN.

Default setting: dev=tun

=item * domain

Key domain is a FQDN of the local OpenVPN server.

Default setting: domain=my.homenet.local

=item * localadr

Key localadr defines the local server IP address.

Default setting: localadr=192.168.1.1

=item * port

Key port defines the port number for OpenVPN server access.

Default setting: port=1194

=item * proto

Key proto defines the used protocol for communicating with remote host.

Default setting: proto=udp

=item * remote

key remote is used to have access via the internet to the OpenVPN server.
This could be an fixed IP-Address or an dynamic DNS information.

Default setting: remote=tomy.homenet.org

=item * route

Key route will be copied directly to config file.

Default setting: route=192.168.1.0 255.255.255.0

=item * server

Key server will be copied directly to config file.

Default setting: server=10.8.0.0 255.255.255.0


=back


=head2 Section [vars]

In this section are mainly all parameter listed that are used to create
the certificates for server and clients. The key/values pairs makes the
the certificates generation process independent from any user activities.

=over 4

=item * CA_EXPIRE

Default setting: CA_EXPIRE=3650

=item * KEY_CITY

Default setting: KEY_CITY=Munich

=item * KEY_CN

Default setting: KEY_CN=server

=item * KEY_COUNTRY

Default setting: KEY_COUNTRY=DE

=item * KEY_EMAIL

Default setting: KEY_EMAIL=me@myhost.mydomain

=item * KEY_EXPIRE

Default setting: KEY_EXPIRE=3650

=item * KEY_NAME

Default setting: KEY_NAME=Ja Mei

=item * KEY_ORG

Default setting: KEY_ORG=HappyProgramming

=item * KEY_OU

Default setting: KEY_OU=IT-Fun

=item * KEY_PROVINCE

Default setting: KEY_PROVINCE=Bavaria

=item * KEY_SIZE

Default setting: KEY_SIZE=2048

=back




=head1 VERSION

Current script version is 0.001 (release date 2014-10-12).




=head1 Requirements

=over 4

=item * This script requires root permissions to be executed.

=item * Script required one of the following OS:

=over 4

=item + Ubuntu, Mint, Debian

=back

=back




=head1 BUGS

No bugs have been reported.

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2013, 2014 H. Klausing. All permissions reserved. This program is
free software; you can redistribute it and/or modify it under the same terms
as Perl itself.

Author can be reached at h dot klausing at gmx dot de




=head1 Author

H. Klausing

openvpn-certgen.pl was designed by H. Klausing.

=cut

