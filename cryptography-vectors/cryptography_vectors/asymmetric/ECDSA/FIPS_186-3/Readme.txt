Example test files for FIPS 186-3 ECDSA

1. The files with extension '.rsp' are response files in the proper format for
CAVS validation.

2. The file SigGen.txt contains values for ECDSA signature generation with the
following additional values needed to calculate r and s as in Section 6.4:
	a. 'd' -- The private key.
	
	b. 'k' -- The Per-message secret number (PMSN) used to compute (r, s).
	See Section 6.3 and Appendix B.5 for more information on the PMSN.