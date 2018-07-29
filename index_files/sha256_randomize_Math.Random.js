/*
rand() function in PHP have repeats and patterns in PRNG.
See more here: https://www.random.org/analysis/#visual

I think, Math.random() have any patterns too.
https://www.google.com/search?q=math+random+bitmap&tbm=isch
Math.random () maybe has a regularity in generation, therefore this is not have crypto strength.
https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator
see more here: https://stackoverflow.com/questions/16884631/better-random-function-in-javascript/

I did not test this using "pattern-detection tests"
https://en.wikipedia.org/wiki/Pseudorandom_number_generator#Potential_problems_with_deterministic_generators
But here I have any ideas for randomize Math.random() function...

In this code you can find the dymamic salt, as enchancement for Math.random()
This salt is regenerate for each call of Math.random() function or when mouse moving.

	Salt is depending from sha256-hash of previous salt,
	if this was been privided as string in function get_rand_salt(X, Y, string);
	when Math.random() called again and again.
	Or this salt will be regenerated for each time when mouse moving, using X, and Y coordinates,
	and another enchancements to get random values.
	For example, there is using this value:
	document.write(window.performance.now()); //value seems, like this: 28.999999980442226
	//and this is time, including nanoseconds.
	
This salt is dependent from next values:
	- time including nanoseconds. console.log(window.performance.now());
	- seconds from UNIX Epoch. console.log((new Date).getTime());
	- x and y coordinate when mouse moving.
	- previous generated salt as string
	- sha256 hash from this all.
*/

/*
including:
	1. 
<!-- visualization randomization-->
	<img id="cursor" src="./index_files/spin.gif"
	style="display: none; position: absolute; top: 50%; left: 50%"
	title="EventListener onmousemove indication
When salt changed, display this gif for mouse cursor with random coordinates">
	</img>

	<font title="See more info in the source code sha256_randomize_Math.Random.js">
		Partial value of salt for modified Math.random() function:
		<div id="partial_salt_value" style="display: inline; "
		title="Display partial salt value."></div>
	</font>
<!-- end visualization-->

	2.
var function_as_string = 'function_name()'; //function to run when mouse moving or when salt is updated by rand timeout value.

	2.
<script src="./index_files/sha256_randomize_Math.Random.js"></script>

*/

//add salt to Math.random() function
//to get more strength for random values

//maximum interval for update salt, if mouse not moving
var interval = 5;					//seconds
var milliseconds = interval*1000;	//milliseconds


//sha-256 function
function SHA256(s){ //s - string, unicode supporting.
 var chrsz  = 8;
 var hexcase = 0;
 function safe_add (x, y) {
 var lsw = (x & 0xFFFF) + (y & 0xFFFF);
 var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
 return (msw << 16) | (lsw & 0xFFFF);
 }
 function S (X, n) { return ( X >>> n ) | (X << (32 - n)); }
 function R (X, n) { return ( X >>> n ); }
 function Ch(x, y, z) { return ((x & y) ^ ((~x) & z)); }
 function Maj(x, y, z) { return ((x & y) ^ (x & z) ^ (y & z)); }
 function Sigma0256(x) { return (S(x, 2) ^ S(x, 13) ^ S(x, 22)); }
 function Sigma1256(x) { return (S(x, 6) ^ S(x, 11) ^ S(x, 25)); }
 function Gamma0256(x) { return (S(x, 7) ^ S(x, 18) ^ R(x, 3)); }
 function Gamma1256(x) { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }
 function core_sha256 (m, l) {
 var K = new Array(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2);
 var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
 var W = new Array(64);
 var a, b, c, d, e, f, g, h, i, j;
 var T1, T2;
 m[l >> 5] |= 0x80 << (24 - l % 32);
 m[((l + 64 >> 9) << 4) + 15] = l;
 for ( var i = 0; i<m.length; i+=16 ) {
 a = HASH[0];
 b = HASH[1];
 c = HASH[2];
 d = HASH[3];
 e = HASH[4];
 f = HASH[5];
 g = HASH[6];
 h = HASH[7];
 for ( var j = 0; j<64; j++) {
 if (j < 16) W[j] = m[j + i];
 else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
 T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
 T2 = safe_add(Sigma0256(a), Maj(a, b, c));
 h = g;
 g = f;
 f = e;
 e = safe_add(d, T1);
 d = c;
 c = b;
 b = a;
 a = safe_add(T1, T2);
 }
 HASH[0] = safe_add(a, HASH[0]);
 HASH[1] = safe_add(b, HASH[1]);
 HASH[2] = safe_add(c, HASH[2]);
 HASH[3] = safe_add(d, HASH[3]);
 HASH[4] = safe_add(e, HASH[4]);
 HASH[5] = safe_add(f, HASH[5]);
 HASH[6] = safe_add(g, HASH[6]);
 HASH[7] = safe_add(h, HASH[7]);
 }
 return HASH;
 }
 function str2binb (str) {
 var bin = Array();
 var mask = (1 << chrsz) - 1;
 for(var i = 0; i < str.length * chrsz; i += chrsz) {
 bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i%32);
 }
 return bin;
 }
 function Utf8Encode(string) {
 string = string.replace(/\r\n/g,"\n");
 var utftext = "";
 for (var n = 0; n < string.length; n++) {
 var c = string.charCodeAt(n);
 if (c < 128) {
 utftext += String.fromCharCode(c);
 }
 else if((c > 127) && (c < 2048)) {
 utftext += String.fromCharCode((c >> 6) | 192);
 utftext += String.fromCharCode((c & 63) | 128);
 }
 else {
 utftext += String.fromCharCode((c >> 12) | 224);
 utftext += String.fromCharCode(((c >> 6) & 63) | 128);
 utftext += String.fromCharCode((c & 63) | 128);
 }
 }
 return utftext;
 }
 function binb2hex (binarray) {
 var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
 var str = "";
 for(var i = 0; i < binarray.length * 4; i++) {
 str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
 hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8 )) & 0xF);
 }
 return str;
 }
 s = Utf8Encode(s);
 return binb2hex(core_sha256(str2binb(s), s.length * chrsz));
}
//test sha256 from specified 'string'
//document.write(SHA256('test_string_with_text. Unicode: 守护村子')); //show sha256 hash


var salt;	//define salt variable
//generate salt from mouse coordinates or string
function get_rand_salt(X, Y, string){ //X, Y - mouse coordinate must be specified (integers or 0), string - is a string.
	//function to derive salt.
		
	//console.log(salt);				//previous value of the salt is 'undefined' for first call;
	
	//generate this...

/*
	//using integers
	salt=
	(
		(
			(
				window.performance.now()	//time, including nanoseconds.
											//console.log(window.performance.now()); //give the number like -> 1836.0000000102445
				*1000000000000000			//1836.0000000102445 * 1000000000000000 = 18360000000102444 - give a whole integer
			)
			+(new Date).getTime()			//1532438760335 - whole integer of timestamp. Seconds after Unix Epoch.				
		)									//sum - is whole integer
		+(
			X*Y								//multiply x and y coordinates - whole integer
			*10000000000000					//whole greater integer
		)									//summary integer
		//if previous salt is undefined - add value using DEFAULT, not modified Math.random(),
		//else if salt was been defined - add previous salt value.
		+ ((typeof salt === 'undefined') ? z = Math.random() : salt)
	)
	%	Number.MAX_SAFE_INTEGER;			//do mod for get the whole integer, lesser than Number.MAX_SAFE_INTEGER

	//console.log(Number.MAX_SAFE_INTEGER); //2^53 - 1 = 9007199254740991
*/
	/*
		ParseInt working with numbers in range -2,147,483,648 to 2,147,483,647;
		Maximum number is 2,147,483,647. And this is prime number.
		Previous prime number of this number is 2147483629;
		So you can using % 2147483629 to get primes lesser than 2147483629
	*/
/*
	mod by Number.MAX_SAFE_INTEGER, can working bad, if dividend have value - over this limit.
	So I'll try to concatenate base36 strings, using value.toString(36);
*/
	
	//using strings
	salt=
		(
			(
				window.performance.now()	//time, including nanoseconds.
											//console.log(window.performance.now()); //give the number like -> 1836.0000000102445
				*1000000000000000			//1836.0000000102445 * 1000000000000000 = 18360000000102444 - give a whole integer
			).toString(36)
			+(new Date).getTime().toString(36) //1532438760335 - whole integer of timestamp. Seconds after Unix Epoch.				
		)									//sum - is whole integer
		+(
			X*Y								//multiply x and y coordinates - whole integer
			*10000000000000					//whole greater integer
		).toString(36)									//summary integer
		//if previous salt is undefined - add value using DEFAULT, not modified Math.random(),
		//else if salt was been defined - add previous salt value.
		+ ((typeof salt === 'undefined') ? z = Math.random() : salt).toString(36)
	;
	//console.log(salt);
	/*
	give strings, like this:
		43p20ul4zyajk1m2tn000.siaixh3k0z52ke29 - first call
		797b8vd9qt4wjk1m2ud4rf1e7767rnk4z90fhpb7p - mouse moving
		7aap4m09yco4jk1m2ud80q7mgwarmd - update by timer
	*/
	
	
	//console.log('z = ', z); //display z value, generated using default Math.random()
	//uncomment any console.log() in modified Math.random, in the bottom, to see responses from modified Math.random() function.
	
	//console.log(salt);				//now first salt is defined in console, when page reloaded.
	salt = salt.toString();			//to string this number. Now this as string.

	//derive this using string, if this is specified.
	if(typeof string !== 'undefined'){ //if string was been specified, then generate add this to previous salt...
		salt = salt+X.toString(36)+Y.toString(36)+string;
		//console.log(salt);
	}
	
	//console.log(salt);
	//give a strings, it containins the sha256-hash

	//get last 48 bit integer from hash of string. Not a first.
	var salt_hash = SHA256(salt);

	//console.log(Number.MAX_SAFE_INTEGER); //2^53 - 1 (~53 bits).
	//53 bits / 8 [bit/byte]= 6,625 bytes. Floor this result. 6 bytes * 8 bit/byte = 48 bits)
	//So 48 bit value is max correct integer bitlength.
	//salt = salt%Number.MAX_SAFE_INTEGER; //limit value by Number.MAX_SAFE_INTEGER (can be bad calculations)
	//no need this, and value for salt integer can be limited as 48 bits.
	var bytes = 6; //6*8 = 48 bits
	var hex_symbols = bytes*2; //two hex symbols for each 8 bit value: FF for 11111111 value;
	//parse hex from hash to int (12 symbols from end, 6 bytes, 48 bits)
	salt = parseInt(salt_hash.substring(salt_hash.length-hex_symbols, salt_hash.length), 16);

	//console.log('salt =', salt, ', (1/(1+salt)) = ', (100000000000000/(1+salt))%1); //(100000000000000/(1+salt)) - this value can be over 1, so using %1
	/*
	give values:
	salt = 233183339618152 , (1/(1+salt)) =  0.42884710444474283
	salt = 176286980583455 , (1/(1+salt)) =  0.5672568653058245
	salt = 222020706665591 , (1/(1+salt)) =  0.45040843938317965
	salt = 174389028459945 , (1/(1+salt)) =  0.573430570048552
	salt = 102161792492734 , (1/(1+salt)) =  0.9788395207250428
	salt = 107176912820529 , (1/(1+salt)) =  0.9330367648063544
	*/

	return salt; //after this all - return salt as JS integer.
}

//another first start
var randomize_string = 'Unicode string: 守护村子';	//start string value
salt = get_rand_salt(0, 0, Math.random().toString(36)+randomize_string);	//first call with ransom_num string + randomize_string, without coordinates

//test after first call
//console.log('first salt', salt);

//get elements cursor, and partial salt, if this was been included.

var cursor = document.getElementById('cursor');
var partial_salt = document.getElementById('partial_salt_value');

//variables to append this elements, if this was not been included.
var append_cursor = true; //or false
var append_div_for_display_partial_salt = true;	//or false

//append gif-image
if(		(typeof cursor === 'undefined' || cursor===null)
	&& 	(append_cursor===true)
	){
	
	//base64 encoded gif in src attribute here;
	//symbol '\' in the end of string make this HTML-code - multistringify
	//No any hacks here. You can delete this symbol and decode image from base64, yourself.
	var created_cursor = '<img id="cursor"\
src="data:image/gif;base64,\
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\
wVgDD+0V17+6Y6BwaNfBwy9YY2YBcMAPnStTY1B9YMdNiyZOngCFGuIBxDZAiRY1eoTvE6UoDEIAGrNSUoNBUuzAaYlljxo2M+HIeXiJpRsRNMaq+JSFCpsRJEqYOPH\
2JQgAIfkECQoAAAAsAAAAAB8AHwAABv9AgHBIFAwIBQPAUCAMBMSodHhAJK5XAPaKOEynCsIWqx0nCIrvcMEwZ90JxkINaMATZXfjywjlzX9jdXNEHiAVFX8ODwoQAB\
AKDw5bZQxpQh8YiIhaERJqEhF4WwRDDpubAJdqaWZeAByoFR0edEMTolsIAA+yFUq2QxJmAgmyGhvBRJNbA5qoGcpED2MEFrIX0kMKYwUUslDaj2PA4soGY47iEOQFY\
6vS3FtNYw/m1KQDYw7mzFhPZj5JGzYGipUtESYowzVmF4ADgOCBCZTgFQAxZBJ4AiXqT6ltbUZhWdToUSR/Ii1FWbDnDkUyDQhJsQPn5ZU9atjUhCPHVhgTNy/RSKsi\
qKFFbUaQKGHiJNyXIAAh+QQJCgAAACwAAAAAHwAfAAAG/0CAcEh8JDAWCsBQIAwExKhU+HFwKlgsIMHlIg7TqQeTLW+7XYIiPGSAymY0mrFgA0LwuLzbCC/6eVlnewk\
ADXVECgxcAGUaGRdQEAoPDmhnDGtDBJcVHQYbYRIRhWgEQwd7AB52AGt7YAAIchETrUITpGgIAAJ7ErdDEnsCA3IOwUSWaAOcaA/JQ0amBXKa0QpyBQZyENFCEHIG39\
HcaN7f4WhM1uTZaE1y0N/TacZoyN/LXU+/0cNyoMxCUytYLjm8AKSS46rVKzmxADhjlCACMFGkBiU4NUQRxS4OHijwNqnSJS6ZovzRyJAQo0NhGrgs5bIPmwWLCLHsQ\
sfhxBWTe9QkOzCwC8sv5Ho127akyRM7QQAAOwAAAAAAAAAAADxiciAvPgo8Yj5XYXJuaW5nPC9iPjogIG15c3FsX3F1ZXJ5KCkgWzxhIGhyZWY9J2Z1bmN0aW9uLm15\
c3FsLXF1ZXJ5Jz5mdW5jdGlvbi5teXNxbC1xdWVyeTwvYT5dOiBDYW4ndCBjb25uZWN0IHRvIGxvY2FsIE15U1FMIHNlcnZlciB0aHJvdWdoIHNvY2tldCAnL3Zhci9\
ydW4vbXlzcWxkL215c3FsZC5zb2NrJyAoMikgaW4gPGI+L2hvbWUvYWpheGxvYWQvd3d3L2xpYnJhaXJpZXMvY2xhc3MubXlzcWwucGhwPC9iPiBvbiBsaW5lIDxiPj\
Y4PC9iPjxiciAvPgo8YnIgLz4KPGI+V2FybmluZzwvYj46ICBteXNxbF9xdWVyeSgpIFs8YSBocmVmPSdmdW5jdGlvbi5teXNxbC1xdWVyeSc+ZnVuY3Rpb24ubXlzc\
WwtcXVlcnk8L2E+XTogQSBsaW5rIHRvIHRoZSBzZXJ2ZXIgY291bGQgbm90IGJlIGVzdGFibGlzaGVkIGluIDxiPi9ob21lL2FqYXhsb2FkL3d3dy9saWJyYWlyaWVz\
L2NsYXNzLm15c3FsLnBocDwvYj4gb24gbGluZSA8Yj42ODwvYj48YnIgLz4KPGJyIC8+CjxiPldhcm5pbmc8L2I+OiAgbXlzcWxfcXVlcnkoKSBbPGEgaHJlZj0nZnV\
uY3Rpb24ubXlzcWwtcXVlcnknPmZ1bmN0aW9uLm15c3FsLXF1ZXJ5PC9hPl06IENhbid0IGNvbm5lY3QgdG8gbG9jYWwgTXlTUUwgc2VydmVyIHRocm91Z2ggc29ja2\
V0ICcvdmFyL3J1bi9teXNxbGQvbXlzcWxkLnNvY2snICgyKSBpbiA8Yj4vaG9tZS9hamF4bG9hZC93d3cvbGlicmFpcmllcy9jbGFzcy5teXNxbC5waHA8L2I+IG9uI\
GxpbmUgPGI+Njg8L2I+PGJyIC8+CjxiciAvPgo8Yj5XYXJuaW5nPC9iPjogIG15c3FsX3F1ZXJ5KCkgWzxhIGhyZWY9J2Z1bmN0aW9uLm15c3FsLXF1ZXJ5Jz5mdW5j\
dGlvbi5teXNxbC1xdWVyeTwvYT5dOiBBIGxpbmsgdG8gdGhlIHNlcnZlciBjb3VsZCBub3QgYmUgZXN0YWJsaXNoZWQgaW4gPGI+L2hvbWUvYWpheGxvYWQvd3d3L2x\
pYnJhaXJpZXMvY2xhc3MubXlzcWwucGhwPC9iPiBvbiBsaW5lIDxiPjY4PC9iPjxiciAvPgo8YnIgLz4KPGI+V2FybmluZzwvYj46ICBteXNxbF9xdWVyeSgpIFs8YS\
BocmVmPSdmdW5jdGlvbi5teXNxbC1xdWVyeSc+ZnVuY3Rpb24ubXlzcWwtcXVlcnk8L2E+XTogQ2FuJ3QgY29ubmVjdCB0byBsb2NhbCBNeVNRTCBzZXJ2ZXIgdGhyb\
3VnaCBzb2NrZXQgJy92YXIvcnVuL215c3FsZC9teXNxbGQuc29jaycgKDIpIGluIDxiPi9ob21lL2FqYXhsb2FkL3d3dy9saWJyYWlyaWVzL2NsYXNzLm15c3FsLnBo\
cDwvYj4gb24gbGluZSA8Yj42ODwvYj48YnIgLz4KPGJyIC8+CjxiPldhcm5pbmc8L2I+OiAgbXlzcWxfcXVlcnkoKSBbPGEgaHJlZj0nZnVuY3Rpb24ubXlzcWwtcXV\
lcnknPmZ1bmN0aW9uLm15c3FsLXF1ZXJ5PC9hPl06IEEgbGluayB0byB0aGUgc2VydmVyIGNvdWxkIG5vdCBiZSBlc3RhYmxpc2hlZCBpbiA8Yj4vaG9tZS9hamF4bG\
9hZC93d3cvbGlicmFpcmllcy9jbGFzcy5teXNxbC5waHA8L2I+IG9uIGxpbmUgPGI+Njg8L2I+PGJyIC8+Cg=="\
style="display: none; position: absolute; top: 50%; left: 50%"\
title="EventListener onmousemove indication\
When salt changed, display this gif for mouse cursor with random coordinates"></img>';
	document.documentElement.innerHTML += created_cursor;
}

//append partial_salt div
if(
		(typeof partial_salt === 'undefined' || partial_salt===null)
	&& 	append_div_for_display_partial_salt
	){
	
	var partial_salt_element = '<font title="See more info in the source code sha256_randomize_Math.Random.js">\
		Partial value of salt for modified Math.random() function:\
		<div id="partial_salt_value" style="display: inline; "\
		title="Display partial salt value."></div>\
	</font>';
	document.documentElement.innerHTML += partial_salt_element;
}

//get this element again, after appending.
cursor = document.getElementById('cursor');
partial_salt = document.getElementById('partial_salt_value');
//this using in visualization functions.

//update salt when mouse moving
document.addEventListener('mousemove',function(event) {
	//console.log('function_as_string', function_as_string);
	//salt=get_rand_salt(event.pageX, event.pageY); 							//no string specified, coordinates only
	salt=get_rand_salt(event.pageX, event.pageY, SHA256(salt.toString(36))); 	//hash from previous salt string as seed for hash random value.
	
	if(cursor!==null){//image for cursor found
		onMouseMove(event);		//do this
	}
	if(partial_salt!==null){	//if salt div is found
		update_partial_salt_in_div(); //do this
	}
	//console.log('mousemove: ', function_as_string);
	if(	typeof function_as_string !== 'undefined' 	//if function_as_string was been specified
	&&	typeof function_as_string === 'string'		//and if this is a string
	){
		setTimeout(function_as_string, 0);			//run this without add second EventListener
	}

	//test after update (move your mouse on page)

	//console.log(salt);	//test salt changing using mouse moving
});

//update salt when mouse moving
document.addEventListener('touchmove',function(event) {
	//salt=get_rand_salt(event.pageX, event.pageY); 							//no string specified, coordinates only
	salt=get_rand_salt(event.pageX, event.pageY, SHA256(salt.toString(36))); 	//hash from previous salt string as seed for hash random value.
	
	if(cursor!==null){//image for cursor found
		onTouch(event);		//run this
	}
	if(partial_salt!==null){	//if salt div is found
		update_partial_salt_in_div(); //do this
	}
	if(	typeof function_as_string !== 'undefined' 	//if function_as_string was been specified
	&&	typeof function_as_string === 'string'		//and if this is a string
	){
		setTimeout(function_as_string, 0);			//run this without add second EventListener
	}

	//test after update (move your mouse on page)
	
	//console.log(salt);	//test salt changing using touchmove

}, true);


var salt2;	//define second variable to compare previous salt

//using salt for modified Math.random() function
Math.random=(function(rand){
	return function() {
		//console.log('prev salt: ', salt, 'salt2', salt2);
		//salt2 is undefined for first call;
		
		if(typeof salt2 === 'undefined'){
			//console.log('salt2 is undefined, ', salt2);
			salt2 = salt;
			//console.log('salt2 defined now', salt2);
		}
		if(salt===salt2){			//if this salt is previous salt this will be regenerated for each call this function.
			salt = get_rand_salt(
				0,
				0,
				SHA256(
					(salt+1).toString(36)+
					(salt+1).toString(36)+
					(salt+1).toString(36)//triple repeat short string with different modification, to get randomized hash.
				)
			);
			//console.log('"salt===salt2", previous salt:', salt2, 'salt after changed: ', salt);
		}
		
		//console.log('changed salt: ', salt, '(rand()+(1/(1+salt)))%1', ((rand()+(1/(1+salt)))%1));
		salt2 = salt;
		return ((rand()+(1/(1+salt)))%1); //for each call
	};
})(Math.random);
//Now this can be called as default Math.random()



	//visualization randomization.
//update partial salt in div
function update_partial_salt_in_div(){
	//console.log(document.getElementById('salt').innerHTML);
	//if(typeof salt==='undefined'){var salt = 1};
	var partial_salt_element = document.getElementById('partial_salt_value');
	if(partial_salt_element==null){return false;}
	else{
		document.getElementById('partial_salt_value').innerHTML = '<font title="Not a full number.">'+"**********"+salt.toString().slice(10)+'</font>';
	}
}

function getRandInt(min, max){//get random integer from min to max (including both)
	return Math.floor(Math.random() * (max+1 - min)) + min;	//using Math.random(). Salt regenerated for each call.
}

var timeout; //random timeout for regenerate salt, if mouse not moving...

//function for update salt with recall this using setTimeout and random intervals.
function generate(milliseconds){
	//generate additional random timeout interval
	//from half timeout up to timeout
	
	clearTimeout(timeout);
	timeout = getRandInt(milliseconds/2, milliseconds);
					//this get value from function getRandInt()
					//and that function is using Math.random()
					//so there, in modified function, salt will be changed by each call.
	
	//display random intervals
	//document.write('<br>default milliseconds: ', milliseconds, ', generated timeout: ', timeout, ', wait '+timeout+' milliseconds...');
	if(cursor!==null){
		cursor.style.display = 'block';
		timeout2 = setTimeout(stopped , 500);
	}
	update_partial_salt_in_div();
	//console.log(document.getElementById('salt').innerHTML);
	
	if(	typeof function_as_string !== 'undefined' 	//if function_as_string was been specified
	&&	typeof function_as_string === 'string'		//and if this is a string
	){
		//console.log('generate ', timeout);
		eval(function_as_string);					//run this here without add second timeout there
	}

	setTimeout('generate(milliseconds)', timeout); //every time calls after rand milliseconds up to "milliseconds" value.
	//but getRandInt call to mod Math.random(), and recalculate nonce.
	//and often calls recalculate hashes... 

	//console.log(salt); //test salt changing by timeout.
}
generate(milliseconds);
//setInterval('console.log(timeout);', 100);

//show gif near cursor with random coordinates, when mouse moving,
//and hide this if moving is stopped

//document.addEventListener('mousemove', onMouseMove, false);
//document.addEventListener('mousemove', onMouseStop, false);
//document.addEventListener("touchmove", onTouch, true);
//document.addEventListener('touchmove', onMouseStop, false);

var hasStopped = false,
    hasChanged = false;
	
var timeout2, //for hide cursor
	x, y;
function getRandomInt_window_crypto(min, max){       
    // Create byte array and fill with 1 random number, using window.crypto.getRandomValues(byteArray);
	// Salt will not regenerate in this case.
	// Using just for fluctuations image coordinates 
    var byteArray = new Uint8Array(1); 			//numbers
    window.crypto.getRandomValues(byteArray); 	//fill random value

    // Convert to decimal
    var randomNum = '0.' + byteArray[0].toString();	

    // Get number in range
    randomNum = Math.floor(randomNum * (max - min + 1)) + min;

    return randomNum;
}
//console.log(getRandomInt_window_crypto(0, 2)); //test

//check mouse movement
function onMouseMove(e) {
  hasStopped = false;
  hasChanged = true;  
  x = e.pageX;
  y = e.pageY;
  
	cursor.style.transition = "";
	cursor.style.display = "block";

	cursor.style.left = x + 0 + "px"; //align pixels right from cursor
	cursor.style.top = y + 20 + "px"; //and bottom after cursor

	//randomize cursor coordinates, using window.Crypto.getRandomValues(bytearray);
	//cursor.style.left = x + getRandomInt_window_crypto(0, 50) + "px";		//using random values in square 50x50
	//cursor.style.top = y + getRandomInt_window_crypto(0, 50)+20 + "px";		//using random values

	if(partial_salt!==null){
		update_partial_salt_in_div();
	}
	
  onMouseStop();
};

function onTouch(e) {
  hasStopped = false;
  hasChanged = true; 
  e.preventDefault();
  x = e.targetTouches[0].pageX;
  y = e.targetTouches[0].pageY;
  
  //generate salt, using coordinates.
  salt=get_rand_salt(x, y, SHA256(salt.toString(36))); 	//hash from previous salt string as seed for hash random value.
  
  onMouseStop();
};

var moving;
var timeout3,	//to say stop moving
	timeout4;	//to return image back
function move_to_right_top(){ //for first page loading page
	//variable first_ran = true;
	
	if(
		cursor.style.display.top !== window.innerWidth-32 + "px"
	&&	cursor.style.top !== 0 + "px"
	)
	{
		//make image visible.
		cursor.style.display = "block";
		//move image in the end and bottom of page
		//cursor.style.left = window.innerWidth-32 + "px";		//right current window width
		//cursor.style.top = window.innerHeight-32 + "px";		//bottom current window Height
	
		//move image in the end and top of page (resizing available)
		cursor.style.left = window.innerWidth-32 + "px";		//right current window width
		cursor.style.top = 0 + "px";							//top, current window Height = 0;
	
		//do this slowly.
		cursor.style.transition = "all 1.5s ease-in-out";

		moving = true;	//say about moving
		clearTimeout(timeout3);
		timeout3 = setTimeout('moving = false; onMouseStop();', 1500); //and wait +1 second. Then image can be hidden.
		
		first_run = false; //don't run this function within 10 seconds
		
		//clearTimeout(timeout2);
		clearTimeout(timeout4);
		timeout4 = setTimeout("first_run = true;", 10000); //turn back this after 5 seconds
		//console.log(timeout3, timeout4);
				
	}
	//else, do nothing...
}

var stopped = function() { //when mouse stop moving
  hasChanged = false;
  hasStopped = true;
  if(typeof cursor === 'undefined'){return false;}
  
  if(moving===false){
	cursor.style.transition = "";
	cursor.style.display = "none";
  }

  if(first_run===true){
	move_to_right_top();
  }
};

function onMouseStop() {
  clearTimeout(timeout2);
  timeout2 = setTimeout( stopped , 1000);
  //console.log(timeout2);
};


var first_run; //move or no move cursor, just define this.

//display cursor by first loading page
if(cursor!==null){ //if this element was geen founded
	first_run = true; //move by first run
	
	cursor.style.display = "block"; //display this
	
	//set rand coordinates
	//randomize cursor coordinates, using window.Crypto.getRandomValues(bytearray);
	cursor.style.left = getRandomInt_window_crypto(0, window.innerWidth-32) + "px";		//using random width in currend window size (without picture size)
	cursor.style.top = getRandomInt_window_crypto(0, window.innerHeight-32) + "px";		//using random height values (window resising available)
	
	timeout2 = setTimeout( stopped , 500); //timeout to hide div when page reloaded, without moving cursor
}