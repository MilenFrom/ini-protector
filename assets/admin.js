/* SecurityWP admin — AJAX toggle switches (no page reload) + toast notifications. */
( function () {
	'use strict';

	var cfg = window.secwpAdmin || {};

	/* ------------------------------------------------------------------ */
	/* Toasts                                                              */
	/* ------------------------------------------------------------------ */

	var ICONS = {
		success: 'dashicons-yes-alt',
		error: 'dashicons-warning',
		info: 'dashicons-info'
	};

	function toastHost() {
		var host = document.querySelector( '.secwp-toasts' );
		if ( ! host ) {
			host = document.createElement( 'div' );
			host.className = 'secwp-toasts';
			document.body.appendChild( host );
		}
		return host;
	}

	/**
	 * Show a toast.
	 * @param {string} message
	 * @param {string} [type] success | error | info (default info)
	 * @param {number} [duration] ms before auto-dismiss; 0 = sticky. Errors default sticky.
	 */
	function toast( message, type, duration ) {
		if ( ! message ) {
			return;
		}
		type = type || 'info';
		if ( typeof duration !== 'number' ) {
			duration = ( type === 'error' ) ? 0 : 3000;
		}

		var host = toastHost();
		var el = document.createElement( 'div' );
		el.className = 'secwp-toast ' + type;
		el.setAttribute( 'role', type === 'error' ? 'alert' : 'status' );

		var icon = document.createElement( 'span' );
		icon.className = 'dashicons ' + ( ICONS[ type ] || ICONS.info );
		el.appendChild( icon );

		var msg = document.createElement( 'span' );
		msg.className = 'secwp-toast-msg';
		msg.textContent = message;
		el.appendChild( msg );

		var close = document.createElement( 'button' );
		close.type = 'button';
		close.className = 'secwp-toast-close';
		close.setAttribute( 'aria-label', 'Dismiss' );
		close.innerHTML = '&times;';
		el.appendChild( close );

		host.appendChild( el );
		// Force reflow so the entrance transition runs.
		void el.offsetWidth;
		el.classList.add( 'in' );

		var timer = null;
		function dismiss() {
			if ( timer ) {
				window.clearTimeout( timer );
				timer = null;
			}
			el.classList.remove( 'in' );
			el.classList.add( 'out' );
			window.setTimeout( function () {
				if ( el.parentNode ) {
					el.parentNode.removeChild( el );
				}
			}, 220 );
		}

		close.addEventListener( 'click', dismiss );
		if ( duration > 0 ) {
			timer = window.setTimeout( dismiss, duration );
		}
		return dismiss;
	}

	// Expose for reuse elsewhere (e.g. future panels).
	window.secwpToast = toast;

	/* ------------------------------------------------------------------ */
	/* AJAX toggle                                                         */
	/* ------------------------------------------------------------------ */

	/* Reflect the new state in the switch button, the hidden field, and the
	   "Configure ▾" link visibility — without reloading. */
	function applyState( form, on ) {
		var btn = form.querySelector( '.secwp-switch' );
		var hidden = form.querySelector( 'input[name="on"]' );
		if ( btn ) {
			btn.classList.toggle( 'on', on );
			btn.setAttribute( 'aria-pressed', on ? 'true' : 'false' );
		}
		if ( hidden ) {
			hidden.value = on ? '0' : '1'; // next click sends the opposite.
		}

		var feature = form.closest( '.secwp-feature' );
		if ( feature ) {
			var configToggle = feature.querySelector( '.secwp-config-toggle' );
			if ( configToggle ) {
				configToggle.style.display = on ? 'inline-block' : 'none';
			}
		}
		// When turning a tweak off, collapse any open config panel for it.
		if ( ! on ) {
			var key = form.getAttribute( 'data-key' );
			var panel = key ? document.getElementById( 'cfg-' + key ) : null;
			if ( panel ) {
				panel.style.display = 'none';
			}
		}
	}

	function errorMsg() {
		return ( cfg.i18n && cfg.i18n.error ) || 'Could not save the change. Please try again.';
	}

	function submitToggle( form ) {
		if ( form.dataset.busy === '1' ) {
			return;
		}
		var hidden = form.querySelector( 'input[name="on"]' );
		var key = form.getAttribute( 'data-key' );
		if ( ! hidden || ! key || ! cfg.ajaxUrl ) {
			form.submit(); // fallback: behave as before.
			return;
		}
		var desired = hidden.value === '1'; // the value to set.

		form.dataset.busy = '1';
		var btn = form.querySelector( '.secwp-switch' );
		if ( btn ) {
			btn.disabled = true;
		}

		var body = new URLSearchParams();
		body.append( 'action', 'secwp_toggle' );
		body.append( 'key', key );
		body.append( 'on', desired ? '1' : '0' );
		body.append( '_wpnonce', cfg.nonce || '' );

		fetch( cfg.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
			body: body.toString()
		} )
			.then( function ( res ) {
				return res.json();
			} )
			.then( function ( json ) {
				if ( json && json.success && json.data ) {
					var on = !! json.data.on;
					applyState( form, on );
					toast(
						on ? ( cfg.i18n && cfg.i18n.enabled ) : ( cfg.i18n && cfg.i18n.disabled ),
						'success'
					);
				} else {
					var msg = ( json && json.data && json.data.message ) ? json.data.message : errorMsg();
					toast( msg, 'error' );
				}
			} )
			.catch( function () {
				toast( errorMsg(), 'error' );
			} )
			.finally( function () {
				form.dataset.busy = '';
				if ( btn ) {
					btn.disabled = false;
				}
			} );
	}

	/* ------------------------------------------------------------------ */
	/* Init                                                                */
	/* ------------------------------------------------------------------ */

	document.addEventListener( 'DOMContentLoaded', function () {
		// Toast queued by a redirect (config save, or a no-JS toggle fallback).
		if ( cfg.flash && cfg.flash.message ) {
			toast( cfg.flash.message, cfg.flash.type || 'info' );
			// Drop secwp_msg from the URL so a manual refresh won't replay it.
			if ( window.history && window.history.replaceState ) {
				try {
					var url = new URL( window.location.href );
					url.searchParams.delete( 'secwp_msg' );
					window.history.replaceState( {}, '', url.toString() );
				} catch ( e ) {}
			}
		}

		document.querySelectorAll( '.secwp-toggle-form' ).forEach( function ( form ) {
			form.addEventListener( 'submit', function ( e ) {
				e.preventDefault();
				submitToggle( form );
			} );
		} );
	} );
}() );
