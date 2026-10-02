(function(){
	function decode(enc){
		try{
			var key=parseInt(enc.substr(0,2),16),out='';
			for(var i=2;i<enc.length;i+=2){out+=String.fromCharCode(parseInt(enc.substr(i,2),16)^key);}
			return out;
		}catch(e){return '';}
	}
	function run(){
		document.querySelectorAll('.secwp-eml[data-eml]').forEach(function(el){
			// The encoded value may carry the original link's ?subject=… after the address.
			var full=decode(el.getAttribute('data-eml'));
			if(!full){return;}
			var email=full.split('?')[0];
			var href='mailto:'+full;
			var subj=el.getAttribute('data-subject');
			if(subj&&full.indexOf('?')===-1){href+='?subject='+encodeURIComponent(subj);}
			// Replace the text only where it is our placeholder; a custom label or an image
			// inside the link stays as the author wrote it. (The text test covers pages cached
			// before data-eml-fill existed.)
			var placeholder=/^\[email\s*protected\]$/.test(el.textContent.replace(/\u00a0/g,' ').trim());
			if(el.hasAttribute('data-eml-fill')||placeholder){el.textContent=email;}
			if(el.tagName==='A'){el.setAttribute('href',href);}
			el.classList.remove('secwp-eml');
			el.removeAttribute('data-eml');
			el.removeAttribute('data-eml-fill');
		});
		// Upgrade any href="#secwp-eml:<enc>" produced by the shortcode mailto mode.
		document.querySelectorAll('a[href^="#secwp-eml:"]').forEach(function(a){
			var email=decode(a.getAttribute('href').slice(11));
			if(email){a.setAttribute('href','mailto:'+email);}
		});
	}
	if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',run);}else{run();}
})();
