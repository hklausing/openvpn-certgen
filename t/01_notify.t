################################################################################
#
# File:     01_notify.t
# Date:     2014-10-27
# Author:   H.Klausing (h.klausing@gmx.de)
# Version:  0.002
#
# Description:
#   Tests for subfunction notify
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
#
#
#
#--- test handling package --------------
use English;
use Test::More(tests => 10);
use Test::Output;

use lib ('script');
use lib ('../script');

require_ok('openvpn-certgen.pl');


##--- package for testes -----------------


#
#
#
#--- start script -----------------------
##diag "openvpn-certgen.pl script options";

{
    # existing of subfunction
    ok( openvpn_certgen->can("notify"), "notify(): subfunction existing test" );
}

{
    # empty input data
    stdout_like( sub{openvpn_certgen::notify(0, '')}, qr(\n), "notify(0): empty input, emtpy line output" );
}

{
    # test input, test output
    stdout_like( sub{openvpn_certgen::notify(0, 'test')}, qr(test\n), "notify(0): test input, test output" );
}

{
    # empty input, emtpy line output
    stdout_like( sub{openvpn_certgen::notify(1, '')}, qr(\n), "notify(1): empty input, emtpy line output" );
}

{
    # test input, test output
    stdout_like( sub{openvpn_certgen::notify(1, 'test')}, qr(test\n), "notify(1): test input, test output" );
}

{
    # empty input, no output
    stdout_like( sub{openvpn_certgen::notify(2, '')}, qr(^$), "notify(2): empty input, no output" );
}

{
    # test input, no output
    stdout_like( sub{openvpn_certgen::notify(2, 'test')}, qr(^$), "notify(2): test input, no output" );
}

{
    # test array input, multiple lines output
    stdout_like( sub{openvpn_certgen::notify(0, ['test1','test2'])}, qr(test1\ntest2\n), "notify(0): test array input, multiple lines output" );
}

{
    # test array input, multiple lines output, no end LF
    stdout_like( sub{openvpn_certgen::notify(0, ['test1','test2'], 1)}, qr(test1\ntest2), "notify(0): test array input, multiple lines output, no end LF" );
}
