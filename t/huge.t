use strict;
use warnings;
use Test::More tests => 2;

BEGIN { use_ok 'Crypt::Rijndael_PP_a::Cache';} # 1

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
	diag "Testing time-to-encrypt a big block of data (keeping it in core)...";
	open(IFILE, "<", "test_data/bwulf10.txt") or die;
	local $/=undef;
	my $huge_ptext=<IFILE>;
	close IFILE;
	my $before=time();
	my $huge_ctext=Crypt::Rijndael_PP_a::block_encrypt_CBC($ivs{16}, $huge_ptext ,$keys{16});
	my $after=time();
	my $diff=$after-$before + 1;
	my $size=length($huge_ptext)/1024;
	diag sprintf("$diff seconds to encrypt a %.1fKiB file (%.1fKiB/s).", $size, $size/$diff);
	$before=time();
	my $new_huge_ptext=Crypt::Rijndael_PP_a::block_decrypt_CBC($ivs{16}, $huge_ctext ,$keys{16});
	$after=time();
	$diff=$after-$before;
	diag sprintf("$diff seconds to decrypt (%.1fKiB/s).\n", $size/$diff);
	cmp_ok($new_huge_ptext, 'eq', $huge_ptext);

	diag "Here's (a snippet of) the result of the decryption:";
	diag "\n...".substr($new_huge_ptext, 40960, 256)."...";
}
