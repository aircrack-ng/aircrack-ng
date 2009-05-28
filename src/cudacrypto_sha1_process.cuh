{
	#pragma unroll
	for(t = 16; t < 80; t++)
	{
		W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
	}

	    
	A = h0;
	B = h1;
	C = h2;
	D = h3;
	E = h4;

  	#pragma unroll
	for(t = 0; t < 20; t++)
	{
		temp =  SHA1CircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + D_K0;
		E = D;
		D = C;
		C = SHA1CircularShift(30,B);
		B = A;
		A = temp;
	}

	#pragma unroll
	for(t = 20; t < 40; t++)
	{
		temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + D_K1;
		E = D;
		D = C;
		C = SHA1CircularShift(30,B);
		B = A;
		A = temp;
	}

	#pragma unroll
	for(t = 40; t < 60; t++)
	{
		temp = SHA1CircularShift(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + D_K2;
		E = D;
		D = C;
		C = SHA1CircularShift(30,B);
		B = A;
		A = temp;
	}

	#pragma unroll
	for(t = 60; t < 80; t++)
	{
		temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + D_K3;
		E = D;
		D = C;
		C = SHA1CircularShift(30,B);
		B = A;
		A = temp;
	}

	h0 = (h0 + A);
	h1 = (h1 + B);
	h2 = (h2 + C);
	h3 = (h3 + D);
	h4 = (h4 + E);
}
