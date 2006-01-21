.PHONY: test full-test clean

all:
	cp lib/Crypt/Rijndael_PP_a.pm blib/lib/Crypt/
	cp cache.pm blib/lib/Crypt/Rijndael_PP_a/Cache.pm
	perl -Ilib -MCrypt::Rijndael_PP_a -e'Crypt::Rijndael_PP_a::make_shiftrow_map();Crypt::Rijndael_PP_a::make_dot_cache();Crypt::Rijndael_PP_a::dump_fixed_arrays' >> blib/lib/Crypt/Rijndael_PP_a/Cache.pm 

test:
	perl -Iblib/lib -MTest::Harness -e'runtests(<t/all.t>)'

full-test:
	perl -Iblib/lib -MTest::Harness -e'runtests(<t/*.t>)'

clean:
	rm blib/lib/Crypt/Rijndael_PP_a.pm blib/lib/Crypt/Rijndael_PP_a/Cache.pm
