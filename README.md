# veriable-outsoure-computation
We implemented a verifiable outsourcing computing model based on three building blocks: BCP variant encryption, proxy re-encryption, and LHE
## paper scheme
![image](https://user-images.githubusercontent.com/59734213/192187109-405b919c-4e69-4469-be78-7077f85283a8.png)
## implementation details
* Our bcp variant is implemented based on the blog **https://www.jianshu.com/p/5ba561c01c22**, and the LHE scheme is from **https://github.com/acmert/bfv-python**
* The operations of Elmement type in the pbc library will do mod operations by default, so when you want to customize the order of mod operations, you can consider using the charm-crypto library
* The charm-crypto library allows addition, subtraction, multiplication, division, and exponentiation operations between elements of the same type. When the types of the two elements are inconsistent, the impact of type coercion on subsequent operations needs to be considered
* g^(a^-1*a) != (g^a)^(a^-1)
## library dependencies
* [charm](https://github.com/JHUISI/charm)
* [pypbc](https://github.com/debatem1/pypbc)
