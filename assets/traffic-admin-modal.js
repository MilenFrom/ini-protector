( function () {
	var modal = document.getElementById( 'secwp-retention-modal' );
	if ( ! modal || typeof modal.showModal !== 'function' ) {
		return; // No <dialog> support: the settings-page link in the footer still works.
	}
	document.addEventListener( 'click', function ( e ) {
		if ( e.target.closest( '.secwp-retention-open' ) ) {
			e.preventDefault();
			modal.showModal();
			return;
		}
		if ( e.target.closest( '.secwp-retention-close' ) ) {
			e.preventDefault();
			modal.close();
			return;
		}
		// Click on the backdrop (the dialog element itself, outside the form) closes it.
		if ( e.target === modal ) {
			modal.close();
		}
	} );
} )();
