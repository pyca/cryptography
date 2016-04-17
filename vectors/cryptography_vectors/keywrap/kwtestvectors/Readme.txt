This zip file contains sample test vectors (values) for the following functions defined in
NIST SP 800-38F:

1. AES Key Wrap Authenticated Encryption (KW-AE) and Authenticated Decryption (KW-AD)
 - file names indicate direction (KW_AE or KW_AD), AES key length (128, 192 or 256).
   e.g., KW_AE_128 mean AES Key Wrap Authenticated Encryption using AES-128.
 - for KW-AE, 'inv' at end of file name indicates AES inverse cipher transformation used
 - for KW-AD, 'inv' at end of file name indicates AES forward cipher transformation used (i.e.,
   authenticated decryption of ciphertext that has been *encrypted using AES inverse cipher function*)
 - 5 plaintext lengths with 100 trials per plaintext length
 - For each trial in KW-AE files, two inputs: key (K) and plaintext (P) and one output: resulting ciphertext (C)
 - for each trial in KW-AD files, two inputs: key (K) and ciphertext (C) and one output: either the resulting
   plaintext (P) or FAIL if ciphertext fails to authenticate.  Should FAIL 20 times per 100 trials.

2. AES Key Wrap with Padding Authenticated Encryption (KWP-AE) and Authenticated Decryption (KWP-AD)
  - file names indicate same things as in (1.), just replace KW_ with KWP_
  - trials same as in (1.)

3. TDEA Key Wrap Authenticated Encryption (TKW-AE) and Authenticated Decryption (TKW-AD)
  - file names indicate same things as in (1.), just replace KW_ with TKW_, except for...
  - only one key size, so no 128/192/256 in file name
  - trials same as in (1.)


Refer to NIST SP 800-38F (December 2012) for more on these functions:

http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf