<?php
/**
 * Email address protection. Scrambles every email address and mailto: link in the rendered
 * content so spam-bot harvesters scraping the raw HTML get unusable garbage, while real visitors
 * see and click the address normally — a tiny script decodes it on load.
 *
 * Encoding: each address is XORed byte-by-byte with a random 1-byte key, hex-encoded, and the
 * key is prepended as the first hex pair (the same reversible scheme Cloudflare's email
 * obfuscation uses). The address never appears in plain text anywhere in the source.
 *
 * Applies automatically to the_content, the_excerpt, widget_text, and comment_text, and also
 * provides the [inipr_obfuscate email="…"] shortcode for explicit use.
 *
 * @package SecurityWP_Connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SecurityWP_Email_Protect {

	const CLASS_NAME = 'secwp-eml';

	/** True once a protected address has been emitted on this request (so we only enqueue the JS then). */
	private $used = false;

	public function register(): void {
		add_shortcode( 'inipr_obfuscate', array( $this, 'shortcode' ) );

		// Automatic, site-wide protection over the common content areas.
		add_filter( 'the_content', array( $this, 'filter_html' ), 20 );
		add_filter( 'the_excerpt', array( $this, 'filter_html' ), 20 );
		add_filter( 'widget_text', array( $this, 'filter_html' ), 20 );
		add_filter( 'comment_text', array( $this, 'filter_html' ), 20 );

		// Register the decoder; it's only enqueued once an address has actually been protected.
		add_action( 'wp_enqueue_scripts', array( $this, 'register_script' ) );
		add_action( 'wp_footer', array( $this, 'maybe_enqueue' ), 1 );
	}

	// ── encoding ────────────────────────────────────────────────────────────────

	/** Reversibly encode an email: random key byte, then each char XOR key, all hex. */
	public static function encode( string $email ): string {
		// A deterministic-per-call key is fine; randomness only needs to vary the ciphertext.
		$key = function_exists( 'random_int' ) ? random_int( 1, 255 ) : ( ord( substr( md5( $email ), 0, 1 ) ) | 1 );
		$out = sprintf( '%02x', $key );
		$len = strlen( $email );
		for ( $i = 0; $i < $len; $i++ ) {
			$out .= sprintf( '%02x', ord( $email[ $i ] ) ^ $key );
		}
		return $out;
	}

	/** Attributes of an existing link worth keeping on its protected replacement. */
	const KEEP_ATTRS = array( 'id', 'title', 'target', 'rel', 'aria-label', 'style' );

	/**
	 * Build the placeholder markup for a protected address (decoded by the JS into a mailto link).
	 *
	 * @param string $email  The address.
	 * @param string $label  Visible label; '' means "show the address" (data-eml-fill).
	 * @param string $query  Any '?subject=…' part of the original mailto, kept with the address.
	 * @param array  $attrs  Kept attributes of the original link (name => raw value).
	 * @param string $tag    'a', or 'span' where a link is not allowed (inside another link).
	 */
	private function protected_link( string $email, string $label = '', string $query = '', array $attrs = array(), string $tag = 'a' ): string {
		$this->used = true;
		// The query is encoded with the address: a cc= in it is an address too.
		$enc   = self::encode( $email . $query );
		$fill  = '' === $label;
		// A non-JS visitor sees the neutral "[email protected]"; the script fills in the address.
		$shown = $fill ? '[email&nbsp;protected]' : wp_kses_post( $label );
		$class = trim( self::CLASS_NAME . ' ' . (string) ( $attrs['class'] ?? '' ) );
		$extra = '';
		foreach ( self::KEEP_ATTRS as $name ) {
			if ( isset( $attrs[ $name ] ) ) {
				$extra .= ' ' . $name . '="' . esc_attr( $attrs[ $name ] ) . '"';
			}
		}
		return '<' . $tag . ( 'a' === $tag ? ' href="#"' : '' ) . ' class="' . esc_attr( $class ) . '" data-eml="' . esc_attr( $enc ) . '"'
			. ( $fill ? ' data-eml-fill="1"' : '' ) . $extra . '>' . $shown . '</' . $tag . '>';
	}

	/** Parse the attributes of an opening tag into name => decoded value. */
	private static function parse_attrs( string $tag ): array {
		$out = array();
		if ( preg_match_all( '#([a-zA-Z][a-zA-Z0-9_:\-]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'>]+))#', $tag, $m, PREG_SET_ORDER ) ) {
			foreach ( $m as $a ) {
				$out[ strtolower( $a[1] ) ] = html_entity_decode( $a[2] . ( $a[3] ?? '' ) . ( $a[4] ?? '' ), ENT_QUOTES );
			}
		}
		return $out;
	}

	/** Replace bare addresses in a text node with protected markup of the given tag. */
	private function protect_text( string $text, string $tag ): string {
		if ( false === strpos( $text, '@' ) ) {
			return $text;
		}
		return (string) preg_replace_callback(
			'#[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}#',
			function ( $m ) use ( $tag ) {
				$email = sanitize_email( $m[0] );
				return '' === $email ? $m[0] : $this->protected_link( $email, '', '', array(), $tag );
			},
			$text
		);
	}

	/** Run protect_text() over the text nodes of an HTML fragment, leaving tags alone. */
	private function protect_fragment( string $html, string $tag ): string {
		$parts = preg_split( '#(<[^>]+>)#s', $html, -1, PREG_SPLIT_DELIM_CAPTURE );
		if ( ! is_array( $parts ) ) {
			return $html;
		}
		foreach ( $parts as $i => $chunk ) {
			if ( 0 === ( $i % 2 ) ) {
				$parts[ $i ] = $this->protect_text( $chunk, $tag );
			}
		}
		return implode( '', $parts );
	}

	// ── automatic filtering ─────────────────────────────────────────────────────

	/**
	 * Protect emails in a chunk of HTML: first existing <a href="mailto:…"> links, then bare
	 * addresses in text nodes. We avoid <script>/<style>/<textarea> and anything already protected.
	 */
	public function filter_html( $html ) {
		if ( ! is_string( $html ) || '' === $html || is_admin() || is_feed() ) {
			return $html;
		}
		if ( false === strpos( $html, '@' ) ) {
			return $html; // Nothing to do.
		}

		// 1) Existing mailto links → protected link, keeping the label, the ?subject= and the
		//    link's own attributes (class, target, rel, …).
		$html = preg_replace_callback(
			'#<a\b([^>]*\bhref\s*=\s*(["\'])\s*mailto:([^"\'?]+)(\?[^"\']*)?\2[^>]*)>(.*?)</a>#is',
			function ( $m ) {
				$email = sanitize_email( html_entity_decode( $m[3] ) );
				if ( '' === $email ) {
					return $m[0];
				}
				$query = isset( $m[4] ) ? html_entity_decode( $m[4], ENT_QUOTES ) : '';
				$label = trim( $m[5] );
				// If the label is itself the email (the common case), let the script show the address.
				$label = ( '' === $label || strtolower( wp_strip_all_tags( $label ) ) === strtolower( $email ) ) ? '' : $label;
				return $this->protected_link( $email, $label, $query, self::parse_attrs( $m[1] ) );
			},
			$html
		);

		// 2) Bare addresses in text nodes. Scripts, styles and textareas are left alone (a
		//    textarea's content is text, not markup). Inside another link — ours from step 1
		//    included — an address becomes a <span>: a link nested in a link is invalid HTML.
		$parts = preg_split( '#(<script\b.*?</script>|<style\b.*?</style>|<textarea\b.*?</textarea>|<a\b[^>]*>.*?</a>|<[^>]+>)#is', $html, -1, PREG_SPLIT_DELIM_CAPTURE );
		if ( is_array( $parts ) ) {
			foreach ( $parts as $i => $chunk ) {
				if ( false === strpos( $chunk, '@' ) ) {
					continue;
				}
				if ( 0 === ( $i % 2 ) ) {
					$parts[ $i ] = $this->protect_text( $chunk, 'a' );
				} elseif ( preg_match( '#^(<a\b[^>]*>)(.*)(</a>)$#is', $chunk, $a ) && false === strpos( $a[1], 'data-eml' ) ) {
					$parts[ $i ] = $a[1] . $this->protect_fragment( $a[2], 'span' ) . $a[3];
				}
			}
			$html = implode( '', $parts );
		}

		return $html;
	}

	// ── shortcode ───────────────────────────────────────────────────────────────

	/** [inipr_obfuscate email="x@y.com" link="yes|no|mailto" subject="…" class="…" text="…" display="inline|block"] */
	public function shortcode( $atts ): string {
		$a = shortcode_atts(
			array(
				'email'   => '',
				'display' => 'block',
				'link'    => 'no',
				'subject' => '',
				'class'   => '',
				'text'    => '',
			),
			$atts,
			'inipr_obfuscate'
		);

		$email = sanitize_email( $a['email'] );
		if ( '' === $email ) {
			return '';
		}

		$this->used = true;
		$enc        = self::encode( $email );

		// 'mailto' mode: emit an encoded data string for use in an href attribute context. The
		// script also upgrades any href="#secwp-eml:<enc>" it finds, so this stays bot-safe.
		if ( 'mailto' === $a['link'] ) {
			return esc_attr( '#secwp-eml:' . $enc );
		}

		$classes = trim( self::CLASS_NAME . ' ' . $a['class'] );
		$style   = ( 'inline' === $a['display'] ) ? ' style="display:inline"' : '';
		$label   = '' !== $a['text'] ? esc_html( $a['text'] ) : '[email&nbsp;protected]';
		$data    = ' data-eml="' . esc_attr( $enc ) . '"' . ( '' === $a['text'] ? ' data-eml-fill="1"' : '' );
		if ( '' !== $a['subject'] ) {
			$data .= ' data-subject="' . esc_attr( $a['subject'] ) . '"';
		}

		// 'yes' → clickable mailto (default after decode); 'no' → plain text span, no link.
		if ( 'yes' === $a['link'] ) {
			return '<a href="#" class="' . esc_attr( $classes ) . '"' . $data . $style . '>' . $label . '</a>';
		}
		return '<span class="' . esc_attr( $classes ) . '"' . $data . $style . '>' . $label . '</span>';
	}

	// ── decoder script ──────────────────────────────────────────────────────────

	public function register_script(): void {
		wp_register_script( 'secwp-email-protect', SECWP_PLUGIN_URL . 'assets/email-protect.js', array(), SECWP_VERSION, true );
	}

	public function maybe_enqueue(): void {
		if ( $this->used ) {
			wp_enqueue_script( 'secwp-email-protect' );
		}
	}

}
