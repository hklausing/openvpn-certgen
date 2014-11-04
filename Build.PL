use 5.010;
use strict;
use warnings FATAL => 'all';
use Module::Build;
use Getopt::Long;
my $fake         = 0;
my $install      = 0;
my $dist         = 0;
my $help         = 0;
my $meta         = 0;
my $orgcondition = 0;
GetOptions(
    'h|help'             => \$help,
    'meta'               => \$meta,
    'dist'               => \$dist,
    'fake'               => \$fake,
    'install'            => \$install,
    'original-condition' => \$orgcondition,
);
my $builder = Module::Build->new(
    module_name    => 'openvpn-certgen',
    license        => 'GPL3',
    dist_author    => q{H. Klausing <h dot klausing at gmx dot de>},
    dist_abstract  => 'OpenVPN certificate Generator for Linux environment',
    dist_version   => '0.005',
    create_readme  => 0,                                                       # do not touch the existing README
    sign           => 0,                                                       # no signature is required
    release_status => 'stable',
    configure_requires => {    # Modules must be installed before running the Build.PL script.
        'Module::Build' => '0.40',
    },
    build_requires => {        # necessary to build and install, but not necessary for regular usage
        'Test::File'   => '1.35',
        'Test::More'   => '0.98',
        'Test::Output' => '1.02',
        'Test::Pod'    => '1.48',
        'Test::Warn'   => '0.24',
    },
    requires => {              # specifies any module prerequisites that the current module depends on.
        'Readonly'              => '1.04',
        'English'               => '1.04',
        'File::Basename'        => '2.82',
        'File::Copy'            => '2.21',
        'File::Copy::Recursive' => '0.38',
        'File::Path'            => '2.08_01',
        'Getopt::Long'          => '2.39',
        'Config::Tiny'          => '2.20',
        'Cwd'                   => '3.36',
        'Archive::Zip'          => '1.3',
        'Archive::Tar'          => '1.9',
        'File::Find'            => '1.19',
        'Pod::Usage'            => '1.36',
        'Carp'                  => '1.32',
    },
    script_files => [    # this requires install_path
        'script/openvpn-certgen.pl'
    ],
    install_path => {
        'script' => '/usr/local/sbin',
    },
    add_to_cleanup     => ['openvpn-certgen-*', 't/openvpn-certgen-html', 't/profile', 'test_results', '*.out', '*.log',],
    create_makefile_pl => 'traditional',
);

if ($help) {
    ## print help info
    print("\n");
    print("Usage: Build.PL [-h|--help][--meta][--dist][--fake][--install][--original-condition]\n");
    print("\n");
} elsif ($meta) {
    ## create meta files
    $builder->dispatch('manifest') if (not -f 'MANIFEST');
    $builder->dispatch('distmeta');
} elsif ($dist) {
    ## create a distrubution package of this project
    $builder->dispatch('manifest') if (not -f 'MANIFEST');
    $builder->dispatch('distmeta');
    $builder->dispatch('build');
    $builder->dispatch('test');
    $builder->dispatch('dist');
    $builder->create_build_script();
} elsif (($fake || $install) && -f 'MANIFEST') {
    ## fakeinstall or install of this project, requires --dist or --meta
    $builder->dispatch('build');
    $builder->dispatch('test', verbose => 1);
    $builder->dispatch($install ? 'install' : 'fakeinstall');
    $builder->create_build_script();
} elsif ($orgcondition) {
    ## put the project to HEAD of repository
    $builder->dispatch('distclean');
    system("rm -f MANIFEST META.* Makefile.PL");
} else {
    ## create build script
    $builder->create_build_script();
}
exit 0;
