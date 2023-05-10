# Avalanche_Effect_on_AES-128

Avalanche effect is a desirable property in cryptographic algorithms, where a slight change in the input text or they key, leads to a significant change in the cipher-text.
This project uses the bit independence criterion which states that output bits $j$ and $k$ should change independently when  any input bit $i$ is inverted, for all $i$, $j$ and $k$.
The idea is to create at least 30 pairs of messages (here we create 50), where the first is the original message and the second is a message that differs in one bit. Then, we calculate the rate of the bits that changed in both EBC and CBC modes for all the pairs. If the rate is equal or greater than $50\%$, then the cryptosystem satisfies the strict avalanche effect. The messages we randomly generate are $256$ $bits$. So AES-128 will break each message in two block and will encrypt each block independetly.


## AES-128

In this project i created my own AES-128 cryptosystem.

The overall structure is:
* $Substitute$ $bytes$
* $Shift$ $rows$
* $Mix$ $Columns$
* $Add$ $Round$ $Key$


## Results
The EBC mode does NOT satisfies the strict avalanche effect since only the block that contains the different bit changes, so half of the cipher-text stays the same. The rate in EBC is around $25\%$.
In CBC mode we get a rate around $50\%$, so it satisfies the avalanche effect. That is because it uses and random initial vector with which we $XOR$ the cipher-text. So even if only one bit changes, the initial vector when we encrypt both messages will be different and as a result bits are going to change in both blocks.
