document.querySelectorAll('.secwp-config-toggle').forEach(function(a){
	a.addEventListener('click', function(e){ e.preventDefault();
		var el = document.getElementById(a.dataset.target);
		if (el) el.style.display = (el.style.display === 'block') ? 'none' : 'block';
	});
});
