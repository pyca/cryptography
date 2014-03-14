Example test files for FIPS 186-2 DSA

1. The files with extension '.rsp' are response files in the proper format for CAVS validation.

2. The file PQGGen.txt contains values for DSA domain parameter generation with intermediate results for generating the
prime p according to Appendix 2, section 2.2 "Generation of Primes."

3. The file SigGen.txt contains values for DSA signature generation with the
following additional values needed to calculate r and s as in Section 5:
	a. 'x' -- The private key.
	
	b. 'k' -- A randomly-generated parameter, unique for each message, used to
	compute r and s.  See Section 4 and Appendix 3 for more information on k.