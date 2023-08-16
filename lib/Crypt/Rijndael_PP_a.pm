package Crypt::Rijndael_PP_a;
use strict;
use warnings;
use bytes;

=head1 NAME

Crypt::Rijndael_PP_a

=head1 DESCRIPTION

Another pure-perl implimentation of the Rijndael cipher (aka AES)

=head1 SYNOPSIS

# OO-style

$cipher=new Crypt::Rijndael_PP_a($key);

# Just one block

$ciphertext=$cipher->encrypt($plaintext);

$plaintext=$cipher->decrypt($ciphertext);

# Multiple blocks

$ciphertext=$cipher->block_encrypt_CBC($iv, $plaintext);

$plaintext=$cipher->block_decrypt_CBC($iv, $ciphertext);

# function-style

$ciphertext=Crypt::Rijndael_PP_a::encrypt($plaintext, $key);

$plaintext=Crypt::Rijndael_PP_a::decrypt($ciphertext, $key);

$ciphertext=Crypt::Rijndael_PP_a::block_encrypt_CBC($iv, $plaintext, $key);

$plaintext=Crypt::Rijndael_PP_a::block_decrypt_CBC($iv, $ciphertext, $key);

=head1 NOTICE

You very very probably want to use Crypt::Rijndael_PP_a::Cache if you use this
module. And if you already have Crypt::Rijndael, then why are you even looking
at this? Use that module instead, this one will never be able to compete on
speed.

You'll also want to use Crypt::CBC (if you have it) for CBC. The support built
in to this module works(the same as OpenSSL command-line CBC), but it doesn't give you any configuration options. Also, this module has some CBC-based optimisations, so using the built-in CBC functions rather than Crypt::CBC(with Crypt::Rijndael_PP_a as the cipher) may be slightly faster.

=head1 IMPORTING

The import function knows two keywords: ":AES" which switches into AES-only mode
and ":Rijndael" which forces full Rijndael mode. The default is full Rijndael mode.

i.e. if you want just AES block lengths available:

use Crypt::Rijndael_PP_a ":AES";

=head1 VARIABLES

=head2 $AES_MODE

You can twiddle this directly to enable/disable the alternate block sizes (AES
supports only 128bit; Rijndael supports 128bit, 192bit and 256bit).

=head1 FUNCTIONS

=cut

my $DEFAULT_KEYSIZE_BYTES=16;
my $DEFAULT_BLOCKSIZE_BYTES=16;
my $AES_BLOCKSIZE_BYTES=16;

our $AES_MODE=0;

my @valid_blocksizes_bytes=qw/16 24 32/;
my @valid_keysizes_bytes=qw/16 24 32/;

my $g_block_words=$DEFAULT_BLOCKSIZE_BYTES/4;


my @g_sbox;
my @g_inv_sbox;

my $g_all_cache;

sub import {
    my @args=@_;
    for(@args) {
        if($_ eq ":AES") {
            $AES_MODE=1;
        } elsif($_ eq ":Rijndael") {
            $AES_MODE=0;
        }
    }
}

=head2 set_blocksize($size_in_bytes)

Sets the block size to use. This is only relevant when encrypting or decrypting
single blocks. This is basically a no-op in AES mode.

The available block sizes are: AES: 16, Rijndael: 16, 24, 32

=cut

sub set_blocksize {
    my $isize=pop;
    if($AES_MODE) {
        return($isize==$AES_BLOCKSIZE_BYTES);
    }
    if(ref $_[0]) {
        my $self=shift;
        if(grep {$_==$isize} @valid_blocksizes_bytes) {
            $self->{block_words}=$isize/4;
            return $self;
        } else {
            return;
        }
    } else {
        if(grep {$_==$isize} @valid_blocksizes_bytes) {
            $g_block_words=$isize/4;
            return 1;
        } else {
            return;
        }
    }
}

#perl -MRijndael_PP_a -e'for(0 .. 0xf) {for (0 .. 0xf) {printf("%.2x ", sbox(mult_inverse($i++)))};print "\n"}'

#perl -MRijndael_PP_a -e'my @sbx=ret_sbox;for(0 .. 0xf) {for (0 .. 0xf) {printf("%.2x ", $sbx[$i++])};print "\n"}'

=head2 new($key)

This exists primarily as a Crypt::CBC hook. Note that the key is in binary (packed) form.

=cut

sub new {
    my ($class, $key)=@_;
    return bless({key=>$key, block_words=>$DEFAULT_BLOCKSIZE_BYTES/4});
}

=head2 keysize

Another Crypt::CBC hook. Returns the default key size in bytes, although IIRC Crypt::CBC will happily use any key size that new() above will accept.

=cut

sub keysize {
    return $DEFAULT_KEYSIZE_BYTES;
}

=head2 blocksize

Another Crypt::CBC hook. Returns the (global or object) chosen block size, in bytes.

=cut

sub blocksize {
    if(@_ and ref $_[0]) {
        my $self=shift;
        return $self->{block_words}*4;
    } else {
        return $g_block_words*4;
    }
}

# used by BEGIN to generate the s-box cache, if need be.

sub ret_sbox {
    return map {sbox(mult_inverse($_))} (0 .. 255);
}

# used by built-in CBC support

sub pad_pkcs5($$) {
    my ($string, $length)=@_;
    my $diff=$length-(length($string)%$length);
    #warn "Padding $diff";
    #warn length($string);
    return $string.(pack("C", $diff) x $diff);
}

# inverse of the above. Doesn't do careful checks, so invalid input
# will be *extra* invalid on the way out.

sub unpad_pkcs5($) {
    my ($string)=@_;
		return "" unless length $string;
    my $pad_len=unpack("C", substr($string, -1, 1));
    #warn $pad_len;
    #warn length($string);
    substr($string, -$pad_len, $pad_len)="";
    return $string;
}

# The multiplicative inverse of a number in the finite GF(2**8) polynomial space.
# Don't ask.

sub mult_inverse {
	my $polyn=0x11b;
	my $num=shift;
	return 0 unless $num;
	my @remainder=($polyn,$num);
	my @auxiliary=(0,1);

	my $i=1;
	while($remainder[$i]!=1) {
		$i++;
		my $quotient=div($remainder[$i-2],$remainder[$i-1]);
		my $multiplied=mul($remainder[$i-1], $quotient);
		#warn unpack("B*", pack("N",$multiplied));
		$remainder[$i]=$remainder[$i-2]^$multiplied;
		$auxiliary[$i]=mul($quotient , $auxiliary[$i-1]) ^ $auxiliary[$i-2];
		#warn "$i:= $remainder[$i] $quotient $auxiliary[$i]";
		if ($i>10) {
			warn "Break!";
			last;
		}
	}
	return $auxiliary[$i];
}

# s-box function. Not used directly, as it obviously makes sense to cache it.

sub sbox($) {
	my $c=0x63;
	my $b=shift;
	my @shifted;
	my $b_t=$b;
	my $result=$b;
	for(1 .. 4) {
		my $b_t=(($b<<$_)&0xff)|($b>>(8-$_));
		$result=$result^$b_t;
	}
	return $result^$c;
}

# Not the same as dot() below, as it doesn't truncate results.

sub mul($$) {
	my ($l, $r)=@_;
	my $result=0;
	my $tv=$l;
	for(0 .. 7) {
		if($r&(1<<$_)) {
			$result^=$tv;
			#warn "Setting bit $_ with ".unpack("B*", pack("N", $tv));
		}
		$tv=$tv<<1;
	}
	return $result;
}

=head2 make_dot_cache

Pardon? Yeah, this caches the map of 8-bit polynomial multiplications in the
GF(256) space.

Basically, this cache speeds things up a lot, but it'll use at least 64KiB of
memory.

You don't need to run this if you're using Crypt::Rijndael_PP_a::Cache.

=cut

my @g_dot_cache;
sub make_dot_cache {
    my @t_dot_cache;
    for my $l (0 .. 0xff) {
        for my $r (0 .. 0xff) {
            if($l>$r) {
                # We've already done this.
                $t_dot_cache[$l][$r]=$t_dot_cache[$r][$l];
            } else {
                $t_dot_cache[$l][$r]=dot($l,$r);
            }
        }
    }
    @g_dot_cache=@t_dot_cache;
};

# Does the dot-multiplying alluded to above. It's not horrendously inefficient,
# but you probably want the cache instead.

sub dot($$) {
	my ($l, $r)=@_;

    return 0 unless($l and $r);

    if(@g_dot_cache) {
        return $g_dot_cache[$l][$r];
    }

	my $result=0;
	my $tv=$l;
	for(0 .. 7) {
		if($r&(1<<$_)) {
			$result^=$tv;
			#warn "Setting bit $_ with ".unpack("B*", pack("N", $tv));
		}
		$tv=xtime($tv);
	}
	return $result;
}

# The inverse of dot() above. Or, more strictly, the inverse of mul().

sub div {
	my ($l, $r)=@_;
	my $acc=$l;
	my $tv=$r;
	my $result=0;
	my @xtm=($r, map{$tv=xtime($tv)} (0 .. 6));
	for(reverse 0 .. 7) {
		$tv=$r<<$_;
		if( ( ($tv&~$acc) < $acc )  or ($acc^$tv)<=(1<<$_)) {
			$result|=(1<<$_);
			$acc^=$tv;
		}
	}
	return $result;
}

# One of the building blocks of all this polynomial finite-space logic.
# Used by dot().

sub xtime($) {
	my ($inhex)=shift;
	$inhex*=2;
	if($inhex&0x100) {
		$inhex^=0x1b;
	}
	$inhex&=0xff;
	return $inhex;
}

# One of the core Rijndael functions. This mixes a single column, by putting
# it through a matrix (remembering to use dot() for multiplies and XOR for +/-)
# Uses the dot() cache directly if it exists.

sub mix_col {
    my (@col)=@_;
    if($g_all_cache) {
        return (
            ($g_dot_cache[02][$col[0]] ^
                $g_dot_cache[03][$col[1]] ^
                    $col[2] ^
                        $col[3] ),
            ( $col[0] ^
                $g_dot_cache[02][$col[1]] ^
                    $g_dot_cache[03][$col[2]] ^
                        $col[3] ),
            ( $col[0] ^
                $col[1] ^
                    $g_dot_cache[02][$col[2]] ^
                        $g_dot_cache[03][$col[3]]),
            ($g_dot_cache[03][$col[0]] ^
                $col[1] ^
                    $col[2] ^
                        $g_dot_cache[02][$col[3]])
        )
    } else {
        return (
            (dot(02,$col[0]) ^ dot(03,$col[1]) ^        $col[2]  ^        $col[3] ),
            (       $col[0]  ^ dot(02,$col[1]) ^ dot(03,$col[2]) ^        $col[3] ),
            (       $col[0]  ^        $col[1]  ^ dot(02,$col[2]) ^ dot(03,$col[3])),
            (dot(03,$col[0]) ^        $col[1]  ^        $col[2]  ^ dot(02,$col[3]))
        )
    }
}

# One of the scarier-looking optimisations. This mixes all the columns in the
# block at once, which saves a little bit of time by not forcing you to array-
# slice

sub mix_col_b {
    my ($block_words, @col)=@_;
    if($g_all_cache) {
        return (map {
            ($g_dot_cache[02][$col[($_*4)+0]] ^
                $g_dot_cache[03][$col[($_*4)+1]] ^
                    $col[($_*4)+2] ^
                        $col[($_*4)+3] ),
            ( $col[($_*4)+0] ^
                $g_dot_cache[02][$col[($_*4)+1]] ^
                    $g_dot_cache[03][$col[($_*4)+2]] ^
                        $col[($_*4)+3] ),
            ( $col[($_*4)+0] ^
                $col[($_*4)+1] ^
                    $g_dot_cache[02][$col[($_*4)+2]] ^
                        $g_dot_cache[03][$col[($_*4)+3]]),
            ($g_dot_cache[03][$col[($_*4)+0]] ^
                $col[($_*4)+1] ^
                    $col[($_*4)+2] ^
                        $g_dot_cache[02][$col[($_*4)+3]])
        } (0 .. ($block_words-1)));
    } else {
        return (map {
            (dot(02,$col[($_*4)+0]) ^ dot(03,$col[($_*4)+1]) ^        $col[($_*4)+2]  ^        $col[($_*4)+3] ),
            (       $col[($_*4)+0]  ^ dot(02,$col[($_*4)+1]) ^ dot(03,$col[($_*4)+2]) ^        $col[($_*4)+3] ),
            (       $col[($_*4)+0]  ^        $col[($_*4)+1]  ^ dot(02,$col[($_*4)+2]) ^ dot(03,$col[($_*4)+3])),
            (dot(03,$col[($_*4)+0]) ^        $col[($_*4)+1]  ^        $col[($_*4)+2]  ^ dot(02,$col[($_*4)+3]))
        } (0 .. ($block_words-1)))
    }
}

# The inverse of mix_col, using an inverted matrix. Otherwise, it's the same.
# This is used for decryption, while mix_col is used for encryption.

sub inv_mix_col {
    my (@col)=@_;
    if($g_all_cache) {
    return (
        ($g_dot_cache[0x0e][$col[0]] ^
            $g_dot_cache[0x0b][$col[1]] ^
                $g_dot_cache[0x0d][$col[2]] ^
                    $g_dot_cache[0x09][$col[3]]),
        ($g_dot_cache[0x09][$col[0]] ^
            $g_dot_cache[0x0e][$col[1]] ^
                $g_dot_cache[0x0b][$col[2]] ^
                    $g_dot_cache[0x0d][$col[3]]),
        ($g_dot_cache[0x0d][$col[0]] ^
            $g_dot_cache[0x09][$col[1]] ^
                $g_dot_cache[0x0e][$col[2]] ^
                    $g_dot_cache[0x0b][$col[3]]),
        ($g_dot_cache[0x0b][$col[0]] ^
            $g_dot_cache[0x0d][$col[1]] ^
                $g_dot_cache[0x09][$col[2]] ^
                    $g_dot_cache[0x0e][$col[3]])
    )
    } else {
    return (
        (dot(0x0e,$col[0]) ^ dot(0x0b,$col[1]) ^ dot(0x0d,$col[2]) ^ dot(0x09,$col[3])),
        (dot(0x09,$col[0]) ^ dot(0x0e,$col[1]) ^ dot(0x0b,$col[2]) ^ dot(0x0d,$col[3])),
        (dot(0x0d,$col[0]) ^ dot(0x09,$col[1]) ^ dot(0x0e,$col[2]) ^ dot(0x0b,$col[3])),
        (dot(0x0b,$col[0]) ^ dot(0x0d,$col[1]) ^ dot(0x09,$col[2]) ^ dot(0x0e,$col[3]))
    )
    }
}

# The inverse of mix_col_b, or inv_mix_col set to operate on a block at once.
# Whichever you prefer.

sub inv_mix_col_b {
    my ($block_words, @col)=@_;
    if($g_all_cache) {
    return (map {
        ($g_dot_cache[0x0e][$col[($_*4)+0]] ^
            $g_dot_cache[0x0b][$col[($_*4)+1]] ^
                $g_dot_cache[0x0d][$col[($_*4)+2]] ^
                    $g_dot_cache[0x09][$col[($_*4)+3]]),
        ($g_dot_cache[0x09][$col[($_*4)+0]] ^
            $g_dot_cache[0x0e][$col[($_*4)+1]] ^
                $g_dot_cache[0x0b][$col[($_*4)+2]] ^
                    $g_dot_cache[0x0d][$col[($_*4)+3]]),
        ($g_dot_cache[0x0d][$col[($_*4)+0]] ^
            $g_dot_cache[0x09][$col[($_*4)+1]] ^
                $g_dot_cache[0x0e][$col[($_*4)+2]] ^
                    $g_dot_cache[0x0b][$col[($_*4)+3]]),
        ($g_dot_cache[0x0b][$col[($_*4)+0]] ^
            $g_dot_cache[0x0d][$col[($_*4)+1]] ^
                $g_dot_cache[0x09][$col[($_*4)+2]] ^
                    $g_dot_cache[0x0e][$col[($_*4)+3]])
    } (0 .. ($block_words-1)))
    } else {
    return (map {
        (dot(0x0e,$col[($_*4)+0]) ^ dot(0x0b,$col[($_*4)+1]) ^ dot(0x0d,$col[($_*4)+2]) ^ dot(0x09,$col[($_*4)+3])),
        (dot(0x09,$col[($_*4)+0]) ^ dot(0x0e,$col[($_*4)+1]) ^ dot(0x0b,$col[($_*4)+2]) ^ dot(0x0d,$col[($_*4)+3])),
        (dot(0x0d,$col[($_*4)+0]) ^ dot(0x09,$col[($_*4)+1]) ^ dot(0x0e,$col[($_*4)+2]) ^ dot(0x0b,$col[($_*4)+3])),
        (dot(0x0b,$col[($_*4)+0]) ^ dot(0x0d,$col[($_*4)+1]) ^ dot(0x09,$col[($_*4)+2]) ^ dot(0x0e,$col[($_*4)+3]))
    } (0 .. ($block_words-1)))
    }
}

# A core part of Rijndael. round0 is the start of every encryption and the
# end of every decryption. It very simply XORs its args.

sub round0($$) {
    my ($input, $round_key)=@_;
    return "$input"^"$round_key";
}

my %shift_for_block_len=(
  4=>[0,1,2,3],
  6=>[0,1,2,3],
  8=>[0,1,3,4],
);

my %g_shiftrow_map;
my %g_inv_shiftrow_map;

=head2 make_shiftrow_map

Another cache creator. The shift_rows() operation and its inverse are straightforward byte-moving operations, so it can be expressed as arrays and used in map {}.

This is low-overhead (should be less than 2KiB) and provides a fair speedup, so
you may want to run it.

Like the other cache functions, this is redundant if you're using Crypt::Rijndael_PP_a::Cache.

=cut

sub make_shiftrow_map {
    for my $block_len (keys %shift_for_block_len) {
        my $row_len=$block_len;
        my @state_b=(0 .. ($row_len*4)-1);
        my $col_len=4;
        my @c=@{$shift_for_block_len{$block_len}};
        for my $row_n (0 .. $#c) {
            # Grab the lossage first
            next unless $c[$row_n];

            my (@d1)=@state_b[
                map {$row_n+$col_len*$_} ($row_len-$c[$row_n] .. $row_len-1)
            ];
            my (@d2)=@state_b[
                map {$row_n+$col_len*$_} (0 .. $row_len-$c[$row_n]-1)
            ];

            @state_b[map {$row_n+$col_len*$_} (0 .. $row_len-1)] = (@d1,@d2);
        }
        $g_inv_shiftrow_map{$block_len}=\@state_b;
        for(0 .. $#state_b) {
            $g_shiftrow_map{$block_len}[$state_b[$_]]=$_;
        }
    }
}

# The shift_rows() function, a core part of Rijndael. This shifts data about -
# cyclically - in a way determined by the block length.
# Note that a row in this sense is *perpendicular* to the data stream, while
# a column is parallel.

sub shift_rows {
  my (@state_b)=@_;
  my $col_len=4;
  my $row_len=scalar(@state_b)/4;

  if(%g_shiftrow_map) {
    return @state_b[@{$g_shiftrow_map{$row_len}}];
  }

  my @c=@{$shift_for_block_len{scalar(@state_b)/4}};
  for my $row_n (0 .. $#c) {
    # Grab the lossage first
    next unless $c[$row_n];

    my (@d1)=@state_b[
        map {$row_n+$col_len*$_} (0 .. $c[$row_n]-1)
    ];
    my (@d2)=@state_b[
        map {$row_n+$col_len*$_} ($c[$row_n] .. $row_len-1)
    ];

    @state_b[map {$row_n+$col_len*$_} (0 .. $row_len-1)] = (@d2,@d1);

  }
  return @state_b;
}

# identical to the above, only backwards. Separate for speed efficiency reasons.
# Used for decryption only.

sub inv_shift_rows {
  my (@state_b)=@_;
  my $col_len=4;
  my $row_len=scalar(@state_b)/4;

  if(%g_inv_shiftrow_map) {
    return @state_b[@{$g_inv_shiftrow_map{$row_len}}];
  }

  my @c=@{$shift_for_block_len{scalar(@state_b)/4}};
  for my $row_n (0 .. $#c) {
    # Grab the lossage first
    next unless $c[$row_n];

    my (@d1)=@state_b[
        map {$row_n+$col_len*$_} ($row_len-$c[$row_n] .. $row_len-1)
    ];
    my (@d2)=@state_b[
        map {$row_n+$col_len*$_} (0 .. $row_len-$c[$row_n]-1)
    ];

    @state_b[map {$row_n+$col_len*$_} (0 .. $row_len-1)] = (@d1,@d2);

  }
  return @state_b;
}

# roundn() handles all of the middle rounds of Rijndael. It mixes columns,
# shifts rows, s-boxes, and XORs, not in that order.

sub roundn($$;$) {
    my ($input, $round_key, $block_words)=@_;
    # convert to use tr for the s-box

    $block_words||=length($input)/4;
    my $row_len=$block_words;

    my @bytes_n=map {$g_sbox[$_]} unpack("C*", $input);
    if($g_all_cache) {
        @bytes_n=@bytes_n[@{$g_shiftrow_map{$block_words}}];
    } else {
        @bytes_n=shift_rows(@bytes_n);
    }

    # Tune this - jim
    my @bytes_n_t=mix_col_b($block_words, @bytes_n);
    $input=pack("C*", @bytes_n_t);

    return "$input"^"$round_key";
}

# The inverse of the above, used for decryption. Most of the stuff is done
# in reverse order.

sub inv_roundn($$;$) {
    my ($input, $round_key, $block_words)=@_;

    $input="$input"^"$round_key";
    my @bytes_n=unpack("C*", $input);

    $block_words||=length($input)/4;
    my $row_len=$block_words;

    my @bytes_n_t=inv_mix_col_b($block_words, @bytes_n);

    @bytes_n=@bytes_n_t;

    if($g_all_cache) {
        @bytes_n=@bytes_n[@{$g_inv_shiftrow_map{$block_words}}];
    } else {
        @bytes_n=inv_shift_rows(@bytes_n);
    }

    # convert to use tr for the s-box ?
    $input=pack("C*", map {$g_inv_sbox[$_]} @bytes_n);

    return $input;
}

# roundl() is the last round of encryption. It's the same as roundn() except for
# the lack of mixing columns. Separate for speed efficiency.

sub roundl($$;$) {
    my ($input, $round_key, $block_words)=@_;

    $block_words||=length($input)/4;

    # convert to use tr for the s-box
    my @bytes_n=map {$g_sbox[$_]} unpack("C*", $input);
    if($g_all_cache) {
        @bytes_n=@bytes_n[@{$g_shiftrow_map{$block_words}}];
    } else {
        @bytes_n=shift_rows(@bytes_n);
    }

    $input=pack("C*", @bytes_n);

    return "$input"^"$round_key";
}

# inv_roundl() is, perversely, the first round of decryption (round0 is the
# last). This is the inverse of the above function.

sub inv_roundl($$;$) {
    my ($input, $round_key, $block_words)=@_;
    # convert to use tr for the s-box

    $block_words||=length($input)/4;

    $input="$input"^"$round_key";

    my @bytes_n=map {$g_inv_sbox[$_]} unpack("C*", $input);

    if($g_all_cache) {
        @bytes_n=@bytes_n[@{$g_inv_shiftrow_map{$block_words}}];
    } else {
        @bytes_n=inv_shift_rows(@bytes_n);
    }
    $input=pack("C*", @bytes_n);

    return $input;
}

# _round_count is used by encrypt() and decrypt() to tell how many rounds to
# use, based on the key size or block size, whichever is bigger.
#
# This is a good reason (in Rijndael mode) to use a bigger block size with
# bigger keys (if you're encrypting a stream) because that way you end up
# doing fewer total rounds.

my %r_count_map=qw/4 10 6 12 8 14/;

sub _round_count($$) {
  my($block_words, $key_words)=@_;
  my $biggest_words=($block_words>$key_words)?$block_words:$key_words;
  return $r_count_map{$biggest_words};
}

# Ah, key expansion. Rijndael uses a predictable algorithm to squeeze a key
# out to be as long as needed (from $keylen to $blocklen*($rounds+1)).
# For the biggest key size, a slightly different algorithm is used, so this
# is just a proxy function...

sub expand_key($$) {
    my ($key, $block_words)=@_;
    my $key_words=length($key)/4;
    return(($key_words>6)?expand_key_gt6($key, $block_words):
        expand_key_le6($key, $block_words));
}

# This expands keys of <=6 words in size (<=192-bit).

sub expand_key_le6($$) { # expand to blocklen*(rounds+1) bits
    my($key, $block_words)=@_;
    my $expanded_key;
    $expanded_key=$key;
    my @ek_words=map {pack("N", $_)} unpack("N*", $expanded_key);

    my $key_words=length($key)/4;
    my $rounds=_round_count($block_words, $key_words);

# cache this FIXME

    my $temp_v=1;
    my @p_round_constant=(
    (map {pack("C*", $_, 0, 0, 0)} (0,1)),
    map {
        #0x1000000<<($_-1)
        pack("C*", $temp_v=dot(02,$temp_v) ,0,0,0)
    } (2 .. int($block_words * ($rounds + 1)/$key_words))

    );

    for(my $i=$key_words; $i< $block_words * ($rounds + 1); $i++) {
        my $p_temp=$ek_words[$i-1];
        if($i%$key_words == 0) {
            {
                my $t_byte=substr($p_temp,0,1);
                substr($p_temp,0,3)=substr($p_temp,1,3);
                substr($p_temp,3,1)=$t_byte;
            }
            # tr would be great here again.
            $p_temp=
                pack("C*", map {$g_sbox[$_]} unpack("C*",
                  $p_temp
                ));
            $p_temp= "$p_temp"^"$p_round_constant[$i/$key_words]";
        }

        $ek_words[$i]="$ek_words[$i-$key_words]"^"$p_temp";
    }
    return join("", @ek_words);
}

# Expands keys of > 6 words size (256bit)

sub expand_key_gt6 { # expand to blocklen*(rounds+1) bits
    my($key, $block_words)=@_;
    my $expanded_key;
    $expanded_key=$key;
    my @ek_words=map {pack("N", $_)} unpack("N*", $expanded_key);

    my $key_words=length($key)/4;
    my $rounds=_round_count($block_words, $key_words);

# cache this FIXME

    my $temp_v=1;
    my @p_round_constant=(
    (map {pack("C*", $_, 0, 0, 0)} (0,1)),
    map {
        #0x1000000<<($_-1)
        pack("C*", $temp_v=dot(02,$temp_v) ,0,0,0)
    } (2 .. int($block_words * ($rounds + 1)/$key_words))

    );

    for(my $i=$key_words; $i< $block_words * ($rounds + 1); $i++) {
        my $p_temp=$ek_words[$i-1];
        if($i%$key_words == 0) {
            {
                my $t_byte=substr($p_temp,0,1);
                substr($p_temp,0,3)=substr($p_temp,1,3);
                substr($p_temp,3,1)=$t_byte;
            }
            # tr would be great here again.
            $p_temp=
                pack("C*", map {$g_sbox[$_]} unpack("C*",
                  $p_temp
                ));

            $p_temp= "$p_temp"^"$p_round_constant[$i/$key_words]";

        } elsif($i%$key_words == 4) {
            $p_temp=pack("C*", map {$g_sbox[$_]} unpack("C*",
                  $p_temp
                )
            );
        }

        $ek_words[$i]="$ek_words[$i-$key_words]"^"$p_temp";
    }
    return join("", @ek_words);
}

=head2 encrypt($plaintext, $key)

=head2 encrypt($plaintext) [OO only]

Encrypts a single block. The key length is worked out from, well, the length
of the key, so you don't need to set it explicitly.

This should return undef only if you provide an invalid-length key. While in
theory wrong-size blocks should be rejected, they aren't: short ones effectively
get nulls appended, and long ones will get the end chopped off.

If there's any question that you might not be using exactly the right length
of data, use CBC instead.

=cut

sub encrypt($$;$$) {
    my ($plaintext, $key, $block_words, $expanded_key);
    if(ref($_[0])) {
        my $self=shift;
        $plaintext=shift;
        $expanded_key=shift;
        $key=$self->{key};
        $block_words=$self->{block_words};
    } else {
       ($plaintext, $key, $expanded_key)=@_;
        $block_words=$g_block_words;
    }
    return unless grep {$_ == length($key)} @valid_keysizes_bytes;

    my $rounds=_round_count($block_words, length($key)/4);
    $expanded_key||=expand_key($key, $block_words);
    my $state=$plaintext;

    my $blockl_b=$block_words*4;
    $state=round0($state, substr($expanded_key,0,$blockl_b));
    for(1 .. $rounds-1) {
        $state=roundn($state, substr($expanded_key,$blockl_b*$_,$blockl_b), $block_words);
    }
    return roundl($state, substr($expanded_key,$blockl_b*$rounds,$blockl_b), $block_words);
}

=head2 decrypt($ciphertext, $key)

=head2 decrypt($ciphertext) [OO only]

The opposite of encrypt() above.

=cut

sub decrypt($$;$$) {
    my ($ciphertext, $key, $block_words, $expanded_key);
    if(ref($_[0])) {
        my $self=shift;
        $ciphertext=shift;
        $expanded_key=shift;
        $key=$self->{key};
        $block_words=$self->{block_words};
    } else {
       ($ciphertext, $key, $expanded_key)=@_;
        $block_words=$g_block_words;
    }
    return unless grep {$_ == length($key)} @valid_keysizes_bytes;

    my $rounds=_round_count($block_words, length($key)/4);
    $expanded_key||=expand_key($key, $block_words);
    my $state=$ciphertext;

    my $blockl_b=$block_words*4;
    $state=inv_roundl($state, substr($expanded_key,$blockl_b*$rounds,$blockl_b), $block_words);
    for(reverse 1 .. $rounds-1) {
        $state=inv_roundn($state, substr($expanded_key,$blockl_b*$_,$blockl_b), $block_words);
    }
    return round0($state, substr($expanded_key,0,$blockl_b));
}

=head2 block_encrypt_CBC($iv, $plaintext, $key)

=head2 block_encrypt_CBC($iv, $plaintext) [OO only]

Encrypts a stream of data. $iv is a packed binary Initial Value. Read some crypto books if you want to know what this is. For now, just know that it should
be an unpredicatable, preferably random value, of the same length as the block
size, and that you will need it for decryption. The block size is derived from
the length of $iv. If it's an invalid block size, then undef will be returned.

Undef will also be returned if $key is of an invalid length.

$plaintext will be padded up to a multiple of the block length using PKCS#5. This is the standard way of doing it, so you shouldn't need to know this.

Other than that, it's pretty much just plaintext-in, ciphertext-out. Use Crypt::CBC instead if you want to set more options.

=cut

sub block_encrypt_CBC($$$) {
    my ($self, $iv, $plaintext, $key, $block_words);
    if(ref $_[0]) {
        ($self, $iv, $plaintext)=@_;
        $key=$self->{key};
        return unless $self->set_blocksize(length $iv);
        $block_words=$self->{block_words};
    } else {
        ($iv, $plaintext, $key)=@_;
        return unless set_blocksize(length $iv);
        $block_words=$g_block_words;
    }

    return unless grep {$_ == length($key)} @valid_keysizes_bytes;

    my $current_block;
    my $last_block_e=$iv;

    my $blockl_b=$block_words*4;

    my $r_data="";
    $plaintext=pad_pkcs5($plaintext, $blockl_b);

    my $expanded_key=expand_key($key, $block_words);

    my $pt_l=length($plaintext);
    for(my $i=0;$blockl_b*$i<$pt_l;$i++) {
        $current_block=substr(
            $plaintext,
            $i*$blockl_b,
            $blockl_b
        );
        #warn "Working on \"$current_block\"";
        my $to_encrypt="$last_block_e"^"$current_block";
        $last_block_e=encrypt($to_encrypt, $key, $expanded_key, length($key));
        $r_data.=$last_block_e;
    }
    return $r_data;
}

=head2 block_decrypt_CBC($iv, $ciphertext, $key)

=head2 block_decrypt_CBC($iv, $ciphertext) [OO only]

The reverse of the above. ciphertext in, plaintext out.

This will also return undef if an invalid-length ciphertext is given, and it assumes PKCS#5 padding.

=cut

sub block_decrypt_CBC($$$) {
    my ($self, $iv, $ciphertext, $key, $block_words);
    if(ref $_[0]) {
        ($self, $iv, $ciphertext)=@_;
        $key=$self->{key};
        return unless $self->set_blocksize(length $iv);
        $block_words=$self->{block_words};
    } else {
        ($iv, $ciphertext, $key)=@_;
        return unless set_blocksize(length $iv);
        $block_words=$g_block_words;
    }
    return unless grep {$_ == length($key)} @valid_keysizes_bytes;


    my $current_block;
    my $last_block_e=$iv;

    my $blockl_b=$block_words*4;

		return unless length($ciphertext)%$blockl_b==0;

    my $expanded_key=expand_key($key, $block_words);

    my $ct_l=length($ciphertext);

    my $r_data="";
    for(my $i=0;$blockl_b*$i<$ct_l;$i++) {
        $current_block=substr(
            $ciphertext,
            $i*$blockl_b,
            $blockl_b
        );
        my $pt_block=decrypt($current_block, $key, $expanded_key, length($key));
        my $decrypted="$last_block_e"^"$pt_block";
        $last_block_e=$current_block;
        $r_data.=$decrypted;
    }
    # We assume PKCS5 padding.
    $r_data=unpad_pkcs5($r_data);
    return $r_data;
}

=head2 dump_fixed_arrays

This is how Crypt::Rijndael_PP_a::Cache was made: it prints to STDOUT a Data::Dumper -like block of perl code to make the cache data. You'll want to run make_dot_cache() and make_shiftrow_map() before running this, if you ever do.

=cut

sub dump_fixed_arrays {
		my %arrays=(g_sbox=>\@g_sbox, g_inv_sbox=>\@g_inv_sbox);
		for my $aname (keys %arrays) {
			print 'our @'.$aname."=(\n\t";
			for my $y (0 .. 0xf) {
				for my $x (0 .. 0xf) {
					print '0x'.unpack("H*", pack("C", ${$arrays{$aname}}[($y*0x10) + $x])).", ";
				}
				print "\n\t";
			}

			print ");\n";
		}
		my %hashes=(g_shiftrow_map=>\%g_shiftrow_map, g_inv_shiftrow_map=>\%g_inv_shiftrow_map);
		for my $hname (keys %hashes) {
			print 'our %'.$hname."=(\n\t";
			for my $key (keys %{$hashes{$hname}}) {
                print "$key => [\n\t\t";
                for my $y (0 .. ($key-1)) {
                    for my $x (0 .. 3) {
                        printf("0x%.2x, ",
                            ${$hashes{$hname}{$key}}[($y*4) + $x]);
                    }
                    print "\n\t\t";
                }
                print "],\n\t";
			}
			print ");\n";
		}
		my %darrays=(g_dot_cache=>\@g_dot_cache);
		for my $aname (keys %darrays) {
			print 'our @'.$aname."=(\n\t";
			for my $left (0 .. $#{$darrays{$aname}}) {
                print "[\n\t\t";
                for my $right (0 .. $#{$darrays{$aname}[$left]}) {
                    printf("0x%.2x, ", $darrays{$aname}[$left][$right]);
                }
                print "],\n\t";
			}
			print ");\n";
		}
}

BEGIN {
		if(@Crypt::Rijndael_PP_a::Cache::g_sbox) {
			@g_sbox=@Crypt::Rijndael_PP_a::Cache::g_sbox;
			@g_inv_sbox=@Crypt::Rijndael_PP_a::Cache::g_inv_sbox;

			@g_dot_cache=@Crypt::Rijndael_PP_a::Cache::g_dot_cache;

			%g_shiftrow_map=%Crypt::Rijndael_PP_a::Cache::g_shiftrow_map;
			%g_inv_shiftrow_map=%Crypt::Rijndael_PP_a::Cache::g_inv_shiftrow_map;
			$g_all_cache=1;
		} else {
			@g_sbox=ret_sbox();
			for(0 .. $#g_sbox) {
					$g_inv_sbox[$g_sbox[$_]]=$_;
			}
		}
}

=head1 NOTES

Use Crypt::Rijndael instead, if it's available. Seriously.

=head1 BUGS

Some extra input checking is needed, and block_decrypt_CBC() should barf if it
makes some obviously broken (ie, badly padded) plaintext.

Oh, and the POD needs reorganising.

=head1 COPYRIGHT

This program is copyright (c) 2004, Jim Driscoll <jim[at]shellprompt.org>.

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

=head1 SEE ALSO

Crypt::Rijndael_PP_a::Cache

=cut

1;
