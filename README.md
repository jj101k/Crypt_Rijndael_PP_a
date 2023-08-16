NOTE

This has nothing whatever to do with Crypt::Rijndael nor with
Crypt::Rijndael_PP. I created this script just because the current version of
the latter was broken in some way (and, allegedly, slow, although I didn't get
far enough to check) and I didn't want to have to dig through the existing code
to find the problem.

Rijndael_PP_a in this case is supposed to mean "Rijndael Pure Perl (alternate)".

You need Crypt::CBC to test this, eg. `cpan install Crypt::CBC`

BUILDING

Although this is a pure-perl version of Rijndael, the cache data (for size
reasons) isn't included, so you need to build it. Quite probably you just want
to do:

make all test install

The fearless may also want to do:

make full-test

SPEED

This isn't a binary module, so expect it to be slow. But if you use this: USE
THE CACHE. It takes ten times as long to encrypt, and twenty times as long to
decrypt otherwise.

Also, big keys are slower in AES/Rijndael, by a factor of about 1.5 (ie, they take 150% of the amount of time). Use small (128-bit) keys, the default, unless
higher security is paramount or you don't have much data to encrypt.

The 'huge' test on my computer takes about 20 seconds to encrypt and 25 to
decrypt (making it about 7-8 kilobytes per second for encrypting, 6-7 for
decrypting). This isn't bad considering that it needs to go through 20,000
encryption or decryption rounds in that time, and actually this does mean that
for light load (eg, encrypting data of <=4KiB) this module should be reasonably
practical to use.

FILES

The files in utility/ will only work once Crypt::Rijndael_PP_a is installed:
they provide command-line encryption in a roughly comparable way to openssl.
Useful for testing ONLY. The following command:

utility/encrypt.pl <some iv> <some key>

...is equivalent (or should be) to:

openssl -aes-128-cbc -a -iv <some iv> -K <some key>

benchmark.pl is a less chatty version of the "huge" test, suitable for running
though Devel::Dprof (see that perldoc for details). It's just there for testing
convenience.

The test_data/ directory contains a sample large data file, in this case a
public domain etext: Beowulf. It's just there so that the test scripts have a
large data file to play with.

COPYING

All the files that make up this distribution are copyright 2004 Jim Driscoll.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
