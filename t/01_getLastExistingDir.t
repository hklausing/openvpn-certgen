################################################################################
#
# File:     01_getLastExistingDir.t
# Date:     2014-10-13
# Author:   H.Klausing (h.klausing@gmx.de)
# Version:  0.001
#
# Description:
#   Tests for subfunction getLastExistingDir
#
################################################################################
#
# Updates:
# 2014-10-13 v0.001   H.Klausing
#           Initial test version
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
#use warnings;
#use strict;
#
#
#
#--- test handling package --------------
use English;
use Test::More(tests => 4);

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
    ok( openvpn_certgen->can("getLastExistingDir"), "getLastExistingDir(): subfunction existing test" );
}

{
    # empty input data
    like( openvpn_certgen::getLastExistingDir(''), qr(.+), "getLastExistingDir(): empty input, no output" );
}

{
    # Existing dir
    is( openvpn_certgen::getLastExistingDir('/tmp/openvpn/abc'), '/tmp/', "getLastExistingDir(): Existing dir" );
}
