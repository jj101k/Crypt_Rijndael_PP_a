use strict;
use warnings;
use Test::More tests => 28;

BEGIN { use_ok 'Crypt::Rijndael_PP_a::Cache';} # 1

my ($input, $rkey)=map {pack("C*", @$_)} ([
	0x32, 0x88, 0x31, 0xe0,
	0x43, 0x5a, 0x31, 0x37,
	0xf6, 0x30, 0x98, 0x07,
	0xa8, 0x8d, 0xa2, 0x34
],[
	0x2b, 0x28, 0xab, 0x09,
	0x7e, 0xae, 0xf7, 0xcf,
	0x15, 0xd2, 0x15, 0x4f,
	0x16, 0xa6, 0x88, 0x3c
]);

$rkey=pack("C*", 
	0xa0, 0x88, 0x23, 0x2a,
	0xfa, 0x54, 0xa3, 0x6c,
	0xfe, 0x2c, 0x39, 0x76,
	0x17, 0xb1, 0x39, 0x05,
);

my $real_key=pack("C*", 
	0x2b, 0x7e, 0x15, 0x16 ,
	0x28, 0xae, 0xd2, 0xa6 ,
	0xab, 0xf7, 0x15, 0x88 ,
	0x09, 0xcf, 0x4f, 0x3c ,
);

my $test_string="test\n123456789ab"; # exactly 16 bytes
my $ctext=Crypt::Rijndael_PP_a::encrypt($test_string,$real_key);

cmp_ok(Crypt::Rijndael_PP_a::decrypt($ctext,$real_key), 'eq', $test_string, "Can I decrypt what I encrypt?"); # 2

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

my $long_ptext="0123456789abcdefABCDEFghijklmnop";

my %keys;
$keys{32}=$long_key;
$keys{24}=substr($long_key,0,24);
$keys{16}=substr($long_key,0,16);
my %ivs;
$ivs{32}=$long_iv;
$ivs{24}=substr($long_iv,0,24);
$ivs{16}=substr($long_iv,0,16);
my %pts;
$pts{32}=$long_ptext;
$pts{24}=substr($long_ptext,0,24);
$pts{16}=substr($long_ptext,0,16);

my %ctexts;

for my $keylen (qw/16 24 32/) { # 3 - 20
	for my $blocklen (qw/16 24 32/) {
			unless(ok(Crypt::Rijndael_PP_a::set_blocksize($blocklen), "Setting block length to ".($blocklen*8))) {
				diag "Uh-oh! I can't set a block size. Am I in AES mode?\n";
				next;
			}
			$ctexts{$keylen}{$blocklen}=Crypt::Rijndael_PP_a::encrypt($pts{$blocklen},$keys{$keylen});
			cmp_ok(Crypt::Rijndael_PP_a::decrypt($ctexts{$keylen}{$blocklen}, $keys{$keylen}), 'eq', $pts{$blocklen}, "Block length ".($blocklen*8).", key length ".($keylen*8));
	}	
}

# Resetting block size
Crypt::Rijndael_PP_a::set_blocksize(16);

my $got_rijndael;
if(eval {
	use Crypt::Rijndael;
	1;
}) {
	$got_rijndael = 1;
	# Excellent. My good friend Crypt::Rijndael exists. Let's try some stuff
}

SKIP: {

	skip "I've not yet got these to work...", 2;
	my $cipher=new Crypt::Rijndael(unpack("H*", $real_key), Crypt::Rijndael::MODE_ECB);
	cmp_ok($cipher->decrypt($ctext), 'eq', $test_string); # 21

	diag "Now, let's try the reverse.";
	
	cmp_ok($cipher->encrypt($test_string), 'eq', $ctext);
}

my $sample_long="This is some text that, well, basically exists only for the purpose of being long, thus forcing the usage of a block mode.\n";

my $ctext_cbc=Crypt::Rijndael_PP_a::block_encrypt_CBC($ivs{16}, $sample_long ,$keys{16});

SKIP: {
	skip "No Crypt::Rijndael to test against", 1 unless $got_rijndael;
	# standard openssl settings

	 use Crypt::CBC;
	 my $cipher = Crypt::CBC->new( {'key'             => $keys{16},
															 'cipher'          => 'Rijndael',
															 'iv'              => $ivs{16},
															 'regenerate_key'  => 0,   # default true
															 'prepend_iv'      => 0,
															 'pcbc'            => 0  #default 0
														});

	cmp_ok($ctext_cbc, 'eq', $cipher->encrypt($sample_long)); # 22
}
					 use Crypt::CBC;
					 my $cipher = Crypt::CBC->new( {'key'             => $keys{16},
																			 'cipher'          => 'Rijndael_PP_a',
																			 'iv'              => $ivs{16},
																			 'regenerate_key'  => 0,   # default true
																			 'prepend_iv'      => 0,
																			 'pcbc'            => 0  #default 0
																		});

	cmp_ok($ctext_cbc, 'eq', $cipher->encrypt($sample_long), "Native CBC vs Crypt::CBC"); # 23

SKIP: {
	skip "No Crypt::Rijndael", 4 unless $got_rijndael;

	# [this will fail if Crypt::Rijndael is, in fact, AES]...

	Crypt::Rijndael_PP_a::set_blocksize(32);
	my $longlblock_ctext=Crypt::Rijndael_PP_a::block_encrypt_CBC($ivs{32}, $sample_long ,$keys{32});

	TODO: {
		local $TODO="Crypt::Rijndael is AES!";
					 use Crypt::CBC;
					 $cipher = Crypt::CBC->new( {'key'             => $keys{32},
																			 'cipher'          => 'Rijndael',
																			 'iv'              => $ivs{32},
																			 'regenerate_key'  => 0,   # default true
																			 'prepend_iv'      => 0,
																			 'pcbc'            => 0  #default 0
																		});

					cmp_ok($cipher->decrypt($longlblock_ctext), 'eq', $sample_long,
						"Long block CBC, comparing with Crypt::CBC(Crypt::Rijndael)"); # 24
	}

	cmp_ok(Crypt::Rijndael_PP_a::block_decrypt_CBC($ivs{32}, $longlblock_ctext ,$keys{32}), 'eq', $sample_long); # 25


	Crypt::Rijndael_PP_a::set_blocksize(16);
	my $longkey_ctext=Crypt::Rijndael_PP_a::block_encrypt_CBC($ivs{16}, $sample_long ,$keys{32});

					 use Crypt::CBC;
					 $cipher = Crypt::CBC->new( {'key'             => $keys{32},
																			 'cipher'          => 'Rijndael',
																			 'iv'              => $ivs{16},
																			 'regenerate_key'  => 0,   # default true
																			 'prepend_iv'      => 0,
																			 'pcbc'            => 0  #default 0
																		});

					cmp_ok($cipher->decrypt($longkey_ctext), 'eq', $sample_long, "Long key CBC, comparing with Crypt::CBC(Crypt::Rijndael)"); # 26

	cmp_ok(Crypt::Rijndael_PP_a::block_decrypt_CBC($ivs{16}, $longkey_ctext ,$keys{32}), 'eq', $sample_long);

}
