#!/usr/bin/perl -w

# This is an openssl-style command-line encrypter. *Please* don't use it
# except for testing, as your key will be exposed.

use strict;
use warnings;

use Crypt::Rijndael_PP_a;
use MIME::Base64;

my ($iv, $key)=map {pack("H*", $_)} @ARGV;

$/=undef;
my $ctext=<STDIN>;

print Crypt::Rijndael_PP_a::block_decrypt_CBC($iv,decode_base64($ctext),$key);

