################################################################################
#
# File:     10_icu.t
# Date:     2014-10-12
# Author:   H.Klausing (h.klausing@gmx.de)
# Version:  0.001
#
# Description:
#   Tests for script openvpn-certgen.pl.
#
################################################################################
#
#-------------------------------------------------------------------------------
# TODO -
#-------------------------------------------------------------------------------
#
#
#
#--- process requirements ---------------
use warnings;
use strict;
#use feature qw();
#
#
#
#--- test handling package --------------
use English;
use Test::More(tests => 7);
use Test::Output;

#--- package for testes -----------------
#
#
#
#--- start script -----------------------
my $name = 'openvpn-certgen';
my $script = getScriptPath() . "/$name.pl";
#diag "$name.pl script options";
{
    # Script existing check
    is(-f $script, 1, "script $name.pl exists.");
}
my $run = "perl -I../lib -Ilib $script";
{
    # Check if Option '--help' returns a value
    like(`$run --help`, qr(^Usage:), 'Command line option check (--help)');
}
{
    # Check if Option '-h' returns a value
    like(`$run -h`, qr(^Usage:), 'Command line option check (-h)');
}
{
    # Check if Option '--man' returns a value
    like(`$run --man`, qr(openvpn-certgen\.pl)sm, 'Command line option check (--man)');
}
{
    # Check if Option '--version' returns a value
    like(`$run --version`, qr(^v\d.\d\d\d), 'Command line option check (--version)');
}
{
    # Check if not valid option is detected, long form
    stderr_like(sub{`$run --ABC`}, qr(^Unknown option: abc$), 'Command line option check (not valid option, long form)');
}
{
    # Check if not valid option is detected, short form
    stderr_like(sub{`$run -Z`}, qr(^Unknown option: z$), 'Command line option check (not valid option, short form)');
}




sub getScriptPath {
    ##--------------------------------------------------------------------------
    # Get the relative path of the test data directory within ./t.
    # Param1:   -
    #---------------------------------------------------------------------------
    foreach my $path ('../script', 'script') {
        return $path if (-d $path);
    }
    return '';
}




sub getTestDataDir {
    ##--------------------------------------------------------------------------
    # Get the relative path of the test data directory within ./t.
    # Param1:   -
    #---------------------------------------------------------------------------
    foreach my $path ('t/etc', 'etc') {
        return $path if (-d $path);
    }
    diag("test directory 'etc' not found; test script stopped\n");
    exit 1;
}
#
#
#
__END__
