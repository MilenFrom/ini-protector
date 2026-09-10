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
			var email=decode(el.getAttribute('data-eml'));
			if(!email){return;}
			var href='mailto:'+email;
			var subj=el.getAttribute('data-subject');
			if(subj){href+='?subject='+encodeURIComponent(subj);}
			// Only show the address as text if the node has none of its own (the placeholder).
			if(el.textContent.indexOf('@')===-1){el.textContent=email;}
			if(el.tagName==='A'){el.setAttribute('href',href);}
			el.classList.remove('secwp-eml');
			el.removeAttribute('data-eml');
		});
		// Upgrade any href="#secwp-eml:<enc>" produced by the shortcode mailto mode.
		document.querySelectorAll('a[href^="#secwp-eml:"]').forEach(function(a){
			var email=decode(a.getAttribute('href').slice(11));
			if(email){a.setAttribute('href','mailto:'+email);}
		});
	}
	if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',run);}else{run();}
})();
