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
	if this was been privided as string in function get_rand_prime_salt(X, Y, string);
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

//add salt to Math.random() function
//to get more strength for random values

function getRandInt(min, max){//get random integer from min to max (including both)
	return Math.floor(Math.random() * (max+1 - min)) + min;
}

//maximum interval for update salt
var interval = 5;					//seconds
var milliseconds = interval*1000;	//milliseconds

//function for update salt with recall this using setTimeout and random intervals.
function generate(milliseconds){
	//generate additional random timeout interval
	//from half timeout up to timeout
	var timeout = getRandInt(milliseconds/2, milliseconds);
					//this get value from function getRandInt()
					//and that function is using Math.random()
					//so there, in modified function, salt will be changed by each call.
	
	//display random intervals
	//document.write('<br>default milliseconds: ', milliseconds, ', generated timeout: ', timeout, ', wait '+timeout+' milliseconds...');
	
	setTimeout('generate(milliseconds)', timeout); //every time calls after rand milliseconds up to "milliseconds" value.
	//but getRandInt call to mod Math.random(), and recalculate nonce.
	//and often calls recalculate hashes... 
}
generate(milliseconds);

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
function get_rand_prime_salt(X, Y, string){ //X, Y - mouse coordinate must be specified (integers or 0), string - is a string.
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
	*/
	//console.log(Number.MAX_SAFE_INTEGER); //2^53 - 1 = 9007199254740991
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

	//console.log(Number.MAX_SAFE_INTEGER); //2^53 - 1 (~53 bits)
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

	/*
	//search next prime from this number
	var salt =
		parseInt(//parseInt from string
			bigInt2str(//return as string
				next_prime(//find next prime
					str2bigInt(salt,10,salt.length * 4, 0) 		//bigInt from string number
				) //whole prime numbers when mouse move...
				,10
			)
		); //this is random JS prime number
	
	*/

	return salt; //after this all - return salt as JS integer.
}

//another first start
var randomize_string = 'Unicode string: 守护村子';	//start string value
salt = get_rand_prime_salt(0, 0, Math.random().toString(36)+randomize_string);	//first call with ransom_num string + randomize_string, without coordinates

//test after first call
//console.log('first salt', salt);



//update salt when mouse moving
document.addEventListener('mousemove',function(event) {
	//salt=get_rand_prime_salt(event.pageX, event.pageY); 							//no string specified, coordinates only
	salt=get_rand_prime_salt(event.pageX, event.pageY, SHA256(salt.toString(36))); 	//hash from previous salt string as seed for hash random value.

	//test after update (move your mouse on page)
	//console.log(salt);
});

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
			salt = get_rand_prime_salt(
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