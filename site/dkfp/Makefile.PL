use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'dkfp',
    AUTHOR              => q{Devon H. O'Dell <devon.odell@gmail.com>},
    VERSION_FROM        => 'lib/dkfp.pm',
    ABSTRACT            => 'DKIM Forensics Project website',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'BSD')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'YAML'       => 0,
        'Dancer'     => 1.3095,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'dkfp-*' },
);
