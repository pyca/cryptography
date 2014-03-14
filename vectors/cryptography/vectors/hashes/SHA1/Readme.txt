There are two sets of SHA example files:

1. The response (.rsp) files contain properly formatted CAVS response files.

2. The intermediate value (.txt) files for the Monte Carlo tests contain
   values for the inner loop as shown in the pseudocode in Figure 1 on page 9
   of the SHA Validation System.  The inner loop variable 'i' ranges in value
   from 3 to 1002.  The intermediate values for the first five iterations of
   the inner loop therefore correspond to 'i' values of 3 to 7. The message (M)
   and the message digest (MDi) for each of these i are printed out, indented
   by one tab space.  The final message digest (MD), not indented, is the last
   value printed for each count.

   
The SHA Validation System document can be found at:

http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf.