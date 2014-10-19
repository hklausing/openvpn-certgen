#!/ust/bin/perl
use 5.014;
use strict;
use warnings FATAL => 'all';
use Test::More;
plan tests => 4;




sub not_in_file_ok {
    my ($filename, %regex) = @_;

    if (not -e $filename) {
        $filename = '../' . $filename;
    }
    open(my $fh, '<', $filename)
        or die "couldn't open $filename for reading: $!";
    my %violated;

    while (my $line = <$fh>) {
        while (my ($desc, $regex) = each %regex) {

            if ($line =~ $regex) {
                push @{$violated{$desc} ||= []}, $.;
            }
        }
    }
    close($fh);

    if (%violated) {
        fail("$filename contains boilerplate text");
        diag "$_ appears on lines @{$violated{$_}}" for keys %violated;
    } else {
        pass("$filename contains no boilerplate text");
    }
} ## end sub not_in_file_ok




sub in_file_ok {
    my ($filename, %regex) = @_;

    if (not -e $filename) {
        $filename = '../' . $filename;
    }
    open(my $fh, '<', $filename)
        or die "couldn't open $filename for reading: $!";

    while (my $line = <$fh>) {
        while (my ($desc, $regex) = each %regex) {

            if ($line =~ $regex) {
                delete($regex{$desc});
                next;
            }
        }
    }
    close($fh);

    if (%regex) {
        fail("$filename does not contains boilerplate text");
        diag "'$_' missing text: " for keys %regex;
    } else {
        pass("$filename contains required boilerplate text");
    }
} ## end sub in_file_ok




sub module_boilerplate_ok {
    my ($module) = @_;
    not_in_file_ok(
        $module                    => 'the great new $MODULENAME' => qr/ - The great new /,
        'boilerplate description'  => qr/Quick summary of what the module/,
        'stub function definition' => qr/function[12]/,
        'wrong author name'        => qr/Super User \(/,
        'wrong copyright name'     => qr/by Super User\./,
        'wrong email name'         => qr/super\@domain\.tld/,
        'script version number'    => qr/^ our \s+ \$VERSION \s+ = \s+ '0\.0\.1';/x, # search txt: our $VERSION = '0.0.1';
        'comment script version' => qr/# \s+ \d{4}-\d{2}-\d{2} \s+ v0.0.1 \s+ H\. Klausing/,
    );
    in_file_ok(
        $module                 =>
        'script version number' => qr/^ our \s+ \$VERSION \s+ = \s+ '0\.001';/x, # search txt: our $VERSION = '0.001';
        'comment script version' => qr/# \s+ \d{4}-\d{2}-\d{2} \s+ v0.001 \s+ H\. Klausing/x,
    );
}
TODO: {
    local $TODO = "Need to replace/add the boilerplate text";
    not_in_file_ok(
        'README.md'                     => "The README.md is used..." => qr/The README.md is used/,
        "'version information here'" => qr/to provide version information/,
    );
    not_in_file_ok('Changes' => "placeholder date/time" => qr(Date/time));
    module_boilerplate_ok('script/openvpn-certgen.pl');
} ## end TODO:
