#!/usr/bin/perl -w -Iblib/lib -d:DProf

# This is usable for benchmarking bulk encryption.
# See "man dprofpp" regarding the output.

use strict;
use warnings;
use Crypt::Rijndael_PP_a::Cache;
my $long_key=pack("C*",
	0xa0, 0x88, 0x23, 0x2a,
	0xfa, 0x54, 0xa3, 0x6c,
	0x2b, 0x7e, 0x15, 0x16,
	0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88,
	0xfe, 0x2c, 0x39, 0x76,
	0x17, 0xb1, 0x39, 0x05,
	0x09, 0xcf, 0x4f, 0x3c,
);

my $long_iv=pack("C*",
		0x4a, 0x07, 0x0e, 0x92,
		0xdc, 0xc6, 0x97, 0xa5,
		0xea, 0xf5, 0xe3, 0x49,
		0xf2, 0x63, 0x05, 0xc5,
		0x2b, 0x81, 0x0a, 0xca,
		0x7f, 0xf9, 0x39, 0x49,
		0x8d, 0x4a, 0x14, 0x59,
		0x38, 0x09, 0x52, 0xf0
);

my %keys;
$keys{32}=$long_key;
$keys{24}=substr($long_key,0,24);
$keys{16}=substr($long_key,0,16);
my %ivs;
$ivs{32}=$long_iv;
$ivs{24}=substr($long_iv,0,24);
$ivs{16}=substr($long_iv,0,16);
{
	open(IFILE, "<", "test_data/bwulf10.txt") or die;
	local $/=undef;
	my $huge_ptext=<IFILE>;
	close IFILE;
	my $huge_ctext=Crypt::Rijndael_PP_a::block_encrypt_CBC($ivs{16}, $huge_ptext ,$keys{16});
	my $new_huge_ptext=Crypt::Rijndael_PP_a::block_decrypt_CBC($ivs{16}, $huge_ctext ,$keys{16});
	if($new_huge_ptext eq $huge_ptext) {
		warn "All seemed to work.\n"
	} else {
		warn "Argh! Something went pear-shaped!\n";
	}
}	
