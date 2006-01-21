#!/usr/bin/perl -w

# This is an openssl-style command-line encrypter. *Please* don't use it
# except for testing, as your key will be exposed.

use strict;
use warnings;

use Crypt::Rijndael_PP_a;
use MIME::Base64;

my ($iv, $key)=map {pack("H*", $_)} @ARGV;

$/=undef;
my $ptext=<STDIN>;

print encode_base64 Crypt::Rijndael_PP_a::block_encrypt_CBC($iv,$ptext,$key);

