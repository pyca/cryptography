Example test files for FIPS 186-3 DSA

1. The files with extension '.rsp' are response files in the proper format for
CAVS validation.

2. The file PQGGen.txt contains values for DSA domain parameter generation with
intermediate results for the following:

    a. For 'A.1.1.2 Generation of the Probable Primes p and q Using an Approved
	Hash Function', the value of the prime 'p' after step 11.5 for the first
	five values of counter (i.e., 0 to 4) is printed out.
	
	b. For 'A.1.2.1 Construction of the Primes p and q Using the Shawe-Taylor
	Algorithm', three sets of intermediate values are provided:
	    1. All values of 'q' and 'qgen_counter' computed with 'C.6 Shawe-Taylor'
		are printed.
		
		2. All values of 'p0' with corresponding value of 'pgen_counter'
		computed with Shawe-Taylor are printed.
		
		3. The first five intermediate values of the prime 'p' at Step 13 of
		A.1.2.1.2, with corresponding value of 'pgen_counter', are printed.

3. The file SigGen.txt contains values for DSA signature generation with the
following additional values needed to calculate r and s as in Section 4.6:
	a. 'x' -- The private key.
	
	b. 'k' -- The Per-message secret number (PMSN) used to compute R and S.
	See Section 4.5 and Appendix B.2 for more information on the PMSN.