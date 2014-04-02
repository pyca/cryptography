Example test files for FIPS 186-2 ECDSA

1. The files with extension '.rsp' are response files in the proper format for
CAVS validation.

2. The file SigGen.txt contains values for ECDSA signature generation with the
following additional values needed to calculate r and s as in X9.62:
	a. 'd' -- The private key.
	
	b. 'k' -- The random value used in calculating signature (r, s).
	See ANS X9.62.