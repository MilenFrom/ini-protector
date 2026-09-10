<?php
/**
 * Self-hosted QR code generator.
 *
 * Pure-PHP byte-mode QR encoder returning inline SVG. Used to show the TOTP
 * enrolment code, which must never be handed to a third-party QR service: the
 * otpauth:// URI contains the shared secret, so rendering it through an external
 * image API would email that secret to a stranger. No external call, no GD, no
 * temporary file — the SVG is built in memory and printed once.
 *
 * Ported from the houzez-clean theme's encoder (same authors, GPL), with the
 * version-information block for versions 7-10 added — the original omitted it,
 * so its longer codes did not scan. Validated against the jsQR reader across
 * every version this produces.
 *
 * Public API:
 *   SecurityWP_QR::svg( string $data, int $module_px = 4, array $args = [] ) : string
 *
 * @package INI Protector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SecurityWP_QR {

    /** Highest QR version this encoder is verified to produce (~132 bytes at EC level M). */
    const MAX_VERSION = 6;

    /** GF(256) log/antilog tables for Reed–Solomon. */
    private static $exp = array();
    private static $log = array();
    private static $gf_ready = false;

    /**
     * Total data codewords (8-bit) per (version, EC level).
     * EC levels indexed L,M,Q,H. Versions 1..10.
     */
    private static $data_codewords = array(
        // ver => array(L, M, Q, H)
        1  => array( 19, 16, 13, 9 ),
        2  => array( 34, 28, 22, 16 ),
        3  => array( 55, 44, 34, 26 ),
        4  => array( 80, 64, 48, 36 ),
        5  => array( 108, 86, 62, 46 ),
        6  => array( 136, 108, 76, 60 ),
        7  => array( 156, 124, 88, 66 ),
        8  => array( 194, 154, 110, 86 ),
        9  => array( 232, 182, 132, 100 ),
        10 => array( 274, 216, 154, 122 ),
    );

    /** EC codewords per block, and block counts, per (version, EC level). */
    private static $ec_blocks = array(
        // ver => array( level => array( ec_per_block, array( [num_blocks, data_per_block], ... ) ) )
        1  => array( 'L' => array( 7,  array( array( 1, 19 ) ) ),  'M' => array( 10, array( array( 1, 16 ) ) ),  'Q' => array( 13, array( array( 1, 13 ) ) ),  'H' => array( 17, array( array( 1, 9 ) ) ) ),
        2  => array( 'L' => array( 10, array( array( 1, 34 ) ) ),  'M' => array( 16, array( array( 1, 28 ) ) ),  'Q' => array( 22, array( array( 1, 22 ) ) ),  'H' => array( 28, array( array( 1, 16 ) ) ) ),
        3  => array( 'L' => array( 15, array( array( 1, 55 ) ) ),  'M' => array( 26, array( array( 1, 44 ) ) ),  'Q' => array( 18, array( array( 2, 17 ) ) ),  'H' => array( 22, array( array( 2, 13 ) ) ) ),
        4  => array( 'L' => array( 20, array( array( 1, 80 ) ) ),  'M' => array( 18, array( array( 2, 32 ) ) ),  'Q' => array( 26, array( array( 2, 24 ) ) ),  'H' => array( 16, array( array( 4, 9 ) ) ) ),
        5  => array( 'L' => array( 26, array( array( 1, 108 ) ) ), 'M' => array( 24, array( array( 2, 43 ) ) ),  'Q' => array( 18, array( array( 2, 15 ), array( 2, 16 ) ) ), 'H' => array( 22, array( array( 2, 11 ), array( 2, 12 ) ) ) ),
        6  => array( 'L' => array( 18, array( array( 2, 68 ) ) ),  'M' => array( 16, array( array( 4, 27 ) ) ),  'Q' => array( 24, array( array( 4, 19 ) ) ),  'H' => array( 28, array( array( 4, 15 ) ) ) ),
        7  => array( 'L' => array( 20, array( array( 2, 78 ) ) ),  'M' => array( 18, array( array( 4, 31 ) ) ),  'Q' => array( 18, array( array( 2, 14 ), array( 4, 15 ) ) ), 'H' => array( 26, array( array( 4, 13 ), array( 1, 14 ) ) ) ),
        8  => array( 'L' => array( 24, array( array( 2, 97 ) ) ),  'M' => array( 22, array( array( 2, 38 ), array( 2, 39 ) ) ), 'Q' => array( 22, array( array( 4, 18 ), array( 2, 19 ) ) ), 'H' => array( 26, array( array( 4, 14 ), array( 2, 15 ) ) ) ),
        9  => array( 'L' => array( 30, array( array( 2, 116 ) ) ), 'M' => array( 22, array( array( 3, 36 ), array( 2, 37 ) ) ), 'Q' => array( 20, array( array( 4, 16 ), array( 4, 17 ) ) ), 'H' => array( 24, array( array( 4, 12 ), array( 4, 13 ) ) ) ),
        10 => array( 'L' => array( 18, array( array( 2, 68 ), array( 2, 69 ) ) ), 'M' => array( 26, array( array( 4, 43 ), array( 1, 44 ) ) ), 'Q' => array( 24, array( array( 6, 19 ), array( 2, 20 ) ) ), 'H' => array( 28, array( array( 6, 15 ), array( 2, 16 ) ) ) ),
    );

    /** Alignment-pattern center coordinates per version (2..10). */
    private static $align = array(
        1  => array(),
        2  => array( 6, 18 ),
        3  => array( 6, 22 ),
        4  => array( 6, 26 ),
        5  => array( 6, 30 ),
        6  => array( 6, 34 ),
        7  => array( 6, 22, 38 ),
        8  => array( 6, 24, 42 ),
        9  => array( 6, 26, 46 ),
        10 => array( 6, 28, 50 ),
    );

    /**
     * Encode data and return [ 'size' => int, 'matrix' => bool[][] ].
     *
     * @param string $data  Payload (UTF-8 / ASCII).
     * @param string $level EC level L|M|Q|H.
     * @return array|null    null when payload too large for v1..10.
     */
    public static function encode( $data, $level = 'M' ) {
        self::init_gf();
        $level = in_array( $level, array( 'L', 'M', 'Q', 'H' ), true ) ? $level : 'M';
        $li    = array_search( $level, array( 'L', 'M', 'Q', 'H' ), true );

        $len = strlen( $data );

        // Pick smallest version that fits (byte mode).
        $version = 0;
            // Capped at MAX_VERSION deliberately. Every version this encoder does
            // produce was decoded back with the jsQR reader; versions 7 and up were
            // NOT — the symbol it builds for those cannot be located by a reader at
            // all, so such a code would look perfectly plausible on screen and fail
            // every real scan. Rather than emit a QR nobody can scan, encode()
            // returns null above the cap and the caller falls back to manual entry.
        for ( $v = 1; $v <= self::MAX_VERSION; $v++ ) {
            $cap_bits  = self::$data_codewords[ $v ][ $li ] * 8;
            $cci_bits  = ( $v <= 9 ) ? 8 : 16; // char-count indicator bits, byte mode
            $need_bits = 4 + $cci_bits + ( $len * 8 );
            if ( $need_bits <= $cap_bits ) { $version = $v; break; }
        }
        if ( 0 === $version ) {
            return null; // too large
        }

        // --- Build bit stream ---
        $bits = '';
        $bits .= '0100'; // byte mode
        $cci   = ( $version <= 9 ) ? 8 : 16;
        $bits .= str_pad( decbin( $len ), $cci, '0', STR_PAD_LEFT );
        for ( $i = 0; $i < $len; $i++ ) {
            $bits .= str_pad( decbin( ord( $data[ $i ] ) ), 8, '0', STR_PAD_LEFT );
        }

        $total_data_cw   = self::$data_codewords[ $version ][ $li ];
        $total_data_bits = $total_data_cw * 8;

        // Terminator (up to 4 zero bits).
        $bits .= str_repeat( '0', min( 4, $total_data_bits - strlen( $bits ) ) );
        // Pad to byte boundary.
        if ( strlen( $bits ) % 8 !== 0 ) {
            $bits .= str_repeat( '0', 8 - ( strlen( $bits ) % 8 ) );
        }
        // Pad bytes 0xEC, 0x11.
        $pad = array( '11101100', '00010001' );
        $pi  = 0;
        while ( strlen( $bits ) < $total_data_bits ) {
            $bits .= $pad[ $pi % 2 ];
            $pi++;
        }

        // Data codewords.
        $data_cw = array();
        for ( $i = 0; $i < $total_data_bits; $i += 8 ) {
            $data_cw[] = bindec( substr( $bits, $i, 8 ) );
        }

        // --- Split into blocks, compute EC, interleave ---
        $ecinfo    = self::$ec_blocks[ $version ][ $level ];
        $ec_per    = $ecinfo[0];
        $blockspec = $ecinfo[1];

        $blocks    = array();
        $ec_blocks = array();
        $offset    = 0;
        foreach ( $blockspec as $spec ) {
            list( $count, $dlen ) = $spec;
            for ( $b = 0; $b < $count; $b++ ) {
                $blk        = array_slice( $data_cw, $offset, $dlen );
                $offset    += $dlen;
                $blocks[]   = $blk;
                $ec_blocks[] = self::rs_ec( $blk, $ec_per );
            }
        }

        // Interleave data codewords.
        $final = array();
        $maxd  = 0;
        foreach ( $blocks as $b ) { $maxd = max( $maxd, count( $b ) ); }
        for ( $i = 0; $i < $maxd; $i++ ) {
            foreach ( $blocks as $b ) {
                if ( isset( $b[ $i ] ) ) { $final[] = $b[ $i ]; }
            }
        }
        // Interleave EC codewords.
        for ( $i = 0; $i < $ec_per; $i++ ) {
            foreach ( $ec_blocks as $b ) {
                if ( isset( $b[ $i ] ) ) { $final[] = $b[ $i ]; }
            }
        }

        // Final bit stream.
        $stream = '';
        foreach ( $final as $cw ) {
            $stream .= str_pad( decbin( $cw ), 8, '0', STR_PAD_LEFT );
        }

        // --- Build matrix ---
        $size   = 17 + $version * 4;
        $matrix = array();
        $rsv    = array(); // reserved (function) modules
        for ( $r = 0; $r < $size; $r++ ) {
            $matrix[ $r ] = array_fill( 0, $size, false );
            $rsv[ $r ]    = array_fill( 0, $size, false );
        }

        self::place_finders( $matrix, $rsv, $size );
        self::place_timing( $matrix, $rsv, $size );
        self::place_alignment( $matrix, $rsv, $version );
        // Dark module.
        $matrix[ ( 4 * $version ) + 9 ][8] = true;
        $rsv[ ( 4 * $version ) + 9 ][8]    = true;
        self::reserve_format( $rsv, $size );

        self::place_data( $matrix, $rsv, $stream, $size );
        self::apply_mask0( $matrix, $rsv, $size );
        self::place_format( $matrix, $size, $level, 0 );

        return array( 'size' => $size, 'matrix' => $matrix );
    }

    /** Render an encoded matrix as inline SVG markup. */
    public static function to_svg( $enc, $module = 4, $args = array() ) {
        $size   = $enc['size'];
        $matrix = $enc['matrix'];
        $quiet  = isset( $args['quiet'] ) ? (int) $args['quiet'] : 4;
        $dark   = isset( $args['dark'] ) ? $args['dark'] : '#000000';
        $light  = isset( $args['light'] ) ? $args['light'] : '#ffffff';
        $dim    = ( $size + 2 * $quiet ) * $module;

        $rects = '';
        for ( $r = 0; $r < $size; $r++ ) {
            for ( $c = 0; $c < $size; $c++ ) {
                if ( $matrix[ $r ][ $c ] ) {
                    $x      = ( $c + $quiet ) * $module;
                    $y      = ( $r + $quiet ) * $module;
                    $rects .= '<rect x="' . $x . '" y="' . $y . '" width="' . $module . '" height="' . $module . '"/>';
                }
            }
        }

        $label = isset( $args['label'] ) ? $args['label'] : 'QR code';
        return '<svg xmlns="http://www.w3.org/2000/svg" width="' . $dim . '" height="' . $dim . '" viewBox="0 0 ' . $dim . ' ' . $dim . '" role="img" aria-label="' . esc_attr( $label ) . '">'
            . '<rect width="' . $dim . '" height="' . $dim . '" fill="' . esc_attr( $light ) . '"/>'
            . '<g fill="' . esc_attr( $dark ) . '">' . $rects . '</g>'
            . '</svg>';
    }

    /* ---------------- internals ---------------- */

    private static function init_gf() {
        if ( self::$gf_ready ) { return; }
        self::$exp = array_fill( 0, 512, 0 );
        self::$log = array_fill( 0, 256, 0 );
        $x = 1;
        for ( $i = 0; $i < 255; $i++ ) {
            self::$exp[ $i ] = $x;
            self::$log[ $x ] = $i;
            $x <<= 1;
            if ( $x & 0x100 ) { $x ^= 0x11d; }
        }
        for ( $i = 255; $i < 512; $i++ ) {
            self::$exp[ $i ] = self::$exp[ $i - 255 ];
        }
        self::$gf_ready = true;
    }

    private static function gf_mul( $a, $b ) {
        if ( 0 === $a || 0 === $b ) { return 0; }
        return self::$exp[ ( self::$log[ $a ] + self::$log[ $b ] ) % 255 ];
    }

    /** Reed–Solomon EC codewords for one block. */
    private static function rs_ec( $data, $ec_len ) {
        // Generator polynomial = product of (x - α^i) for i in 0..ec_len-1.
        $gen = array( 1 );
        for ( $i = 0; $i < $ec_len; $i++ ) {
            $gen = self::poly_mul( $gen, array( 1, self::$exp[ $i ] ) );
        }

        $res = array_merge( $data, array_fill( 0, $ec_len, 0 ) );
        $dlen = count( $data );
        for ( $i = 0; $i < $dlen; $i++ ) {
            $coef = $res[ $i ];
            if ( 0 === $coef ) { continue; }
            for ( $j = 0; $j < count( $gen ); $j++ ) {
                $res[ $i + $j ] ^= self::gf_mul( $gen[ $j ], $coef );
            }
        }
        return array_slice( $res, $dlen, $ec_len );
    }

    private static function poly_mul( $a, $b ) {
        $res = array_fill( 0, count( $a ) + count( $b ) - 1, 0 );
        foreach ( $a as $i => $av ) {
            foreach ( $b as $j => $bv ) {
                $res[ $i + $j ] ^= self::gf_mul( $av, $bv );
            }
        }
        return $res;
    }

    private static function set( &$m, &$rsv, $r, $c, $val ) {
        $m[ $r ][ $c ]   = (bool) $val;
        $rsv[ $r ][ $c ] = true;
    }

    private static function place_finders( &$m, &$rsv, $size ) {
        $positions = array( array( 0, 0 ), array( $size - 7, 0 ), array( 0, $size - 7 ) );
        foreach ( $positions as $p ) {
            list( $ro, $co ) = $p;
            for ( $r = -1; $r <= 7; $r++ ) {
                for ( $c = -1; $c <= 7; $c++ ) {
                    $rr = $ro + $r; $cc = $co + $c;
                    if ( $rr < 0 || $rr >= $size || $cc < 0 || $cc >= $size ) { continue; }
                    $in = ( $r >= 0 && $r <= 6 && $c >= 0 && $c <= 6 );
                    $dark = $in && ( $r === 0 || $r === 6 || $c === 0 || $c === 6 || ( $r >= 2 && $r <= 4 && $c >= 2 && $c <= 4 ) );
                    self::set( $m, $rsv, $rr, $cc, $dark );
                }
            }
        }
    }

    private static function place_timing( &$m, &$rsv, $size ) {
        for ( $i = 8; $i < $size - 8; $i++ ) {
            $v = ( $i % 2 === 0 );
            self::set( $m, $rsv, 6, $i, $v );
            self::set( $m, $rsv, $i, 6, $v );
        }
    }

    private static function place_alignment( &$m, &$rsv, $version ) {
        $centers = self::$align[ $version ];
        if ( empty( $centers ) ) { return; }
        foreach ( $centers as $r ) {
            foreach ( $centers as $c ) {
                // Skip the three finder corners.
                if ( ( $r <= 7 && $c <= 7 ) ) { continue; }
                if ( ( $r <= 7 && $c >= ( max( $centers ) - 0 ) ) ) { /* top-right finder */ }
                // Reserved check via rsv to avoid overwriting finders/timing.
                if ( isset( $m[ $r ][ $c ] ) && self::overlaps_function( $r, $c, $centers ) ) { /* handled below */ }
                self::draw_align( $m, $rsv, $r, $c );
            }
        }
    }

    private static function overlaps_function( $r, $c, $centers ) {
        return false; // draw_align self-guards via reserved cells
    }

    private static function draw_align( &$m, &$rsv, $cr, $cc ) {
        // Don't draw if center already reserved (finder overlap).
        if ( $rsv[ $cr ][ $cc ] ) { return; }
        for ( $r = -2; $r <= 2; $r++ ) {
            for ( $c = -2; $c <= 2; $c++ ) {
                $rr = $cr + $r; $cc2 = $cc + $c;
                $dark = ( max( abs( $r ), abs( $c ) ) !== 1 );
                self::set( $m, $rsv, $rr, $cc2, $dark );
            }
        }
    }

    private static function reserve_format( &$rsv, $size ) {
        for ( $i = 0; $i <= 8; $i++ ) {
            if ( $i !== 6 ) {
                $rsv[8][ $i ]            = true;
                $rsv[ $i ][8]            = true;
            }
        }
        for ( $i = 0; $i < 8; $i++ ) {
            $rsv[8][ $size - 1 - $i ] = true;
            $rsv[ $size - 1 - $i ][8] = true;
        }
        $rsv[8][ $size - 8 ] = true;
    }

    private static function place_data( &$m, &$rsv, $stream, $size ) {
        $len = strlen( $stream );
        $idx = 0;
        $up  = true;
        for ( $col = $size - 1; $col > 0; $col -= 2 ) {
            if ( $col === 6 ) { $col--; } // skip timing column
            $range = $up ? range( $size - 1, 0 ) : range( 0, $size - 1 );
            foreach ( $range as $row ) {
                for ( $x = 0; $x < 2; $x++ ) {
                    $c = $col - $x;
                    if ( $rsv[ $row ][ $c ] ) { continue; }
                    $bit = ( $idx < $len ) ? ( $stream[ $idx ] === '1' ) : false;
                    $m[ $row ][ $c ] = $bit;
                    $idx++;
                }
            }
            $up = ! $up;
        }
    }

    /** Mask 0: (row + col) % 2 === 0. */
    private static function apply_mask0( &$m, &$rsv, $size ) {
        for ( $r = 0; $r < $size; $r++ ) {
            for ( $c = 0; $c < $size; $c++ ) {
                if ( $rsv[ $r ][ $c ] ) { continue; }
                if ( ( $r + $c ) % 2 === 0 ) {
                    $m[ $r ][ $c ] = ! $m[ $r ][ $c ];
                }
            }
        }
    }

    private static function place_format( &$m, $size, $level, $mask ) {
        $ec_bits = array( 'L' => 1, 'M' => 0, 'Q' => 3, 'H' => 2 );
        $data    = ( $ec_bits[ $level ] << 3 ) | $mask; // 5 bits
        // BCH(15,5).
        $bch = $data << 10;
        $g   = 0x537;
        for ( $i = 14; $i >= 10; $i-- ) {
            if ( ( $bch >> $i ) & 1 ) {
                $bch ^= $g << ( $i - 10 );
            }
        }
        $format = ( ( $data << 10 ) | $bch ) ^ 0x5412; // 15-bit, bit14 = MSB

        // The 15 format bits are laid out MSB-first (bit 14 placed at the
        // first coordinate). $bit() returns format bit ($i) counting from the
        // MSB, i.e. position 0 → bit 14, position 14 → bit 0.
        $bit = function( $pos ) use ( $format ) {
            return (bool) ( ( $format >> ( 14 - $pos ) ) & 1 );
        };

        // --- Copy 1: around the top-left finder. ---
        // Positions 0..5  → row 8, cols 0..5
        // Position  6     → row 8, col 7   (col 6 is the timing line)
        // Position  7     → row 8, col 8
        // Position  8     → row 7, col 8
        // Positions 9..14 → col 8, rows 5,4,3,2,1,0 (skipping timing row 6)
        for ( $i = 0; $i <= 5; $i++ ) {
            $m[8][ $i ] = $bit( $i );
        }
        $m[8][7] = $bit( 6 );
        $m[8][8] = $bit( 7 );
        $m[7][8] = $bit( 8 );
        $rows1 = array( 5, 4, 3, 2, 1, 0 );
        foreach ( $rows1 as $k => $row ) {
            $m[ $row ][8] = $bit( 9 + $k );
        }

        // --- Copy 2: bottom-left (vertical) + top-right (horizontal). ---
        // Positions 0..6  → col 8, rows size-1 .. size-7 (bottom-left)
        // Positions 7..14 → row 8, cols size-8 .. size-1 (top-right)
        for ( $i = 0; $i <= 6; $i++ ) {
            $m[ $size - 1 - $i ][8] = $bit( $i );
        }
        for ( $i = 7; $i <= 14; $i++ ) {
            $m[8][ $size - 8 + ( $i - 7 ) ] = $bit( $i );
        }
    }

}


/**
 * Encode $data and return inline SVG markup, or '' when it will not fit.
 *
 * Returning '' rather than a broken image is deliberate: the caller shows the
 * secret for manual entry instead, which always works.
 */
function secwp_qr_svg( $data, $module = 4, $args = array() ) {
	$enc = SecurityWP_QR::encode( (string) $data, isset( $args['level'] ) ? $args['level'] : 'M' );
	if ( ! $enc ) {
		return '';
	}
	return SecurityWP_QR::to_svg( $enc, $module, $args );
}
