#ifndef CKB_MISCELLANEOUS_SCRIPTS_RSA_SIGHASH_ALL_H
#define CKB_MISCELLANEOUS_SCRIPTS_RSA_SIGHASH_ALL_H

#include <stddef.h>
/**
 * This structure contains the following information:
 * 1) RSA Key Size
 * 2) RSA Public Key
 * 3) Real Signature data
 *
 * Because we need to use the same interfaces (see validate_signature) as
 * secp256k1, store 1) and 2) information alone with signature.
 */
typedef struct RsaInfo {
  // RSA Key Size, in bits. For example, 1024, 2048.
  // Normally we use 1024; Choose 2048 for safety.
  uint32_t key_size;

  // RSA public key, part E. It's normally very small, OK to use uint32_to hold
  // it. https://eprint.iacr.org/2008/510.pdf The choice e = 65537 = 2^16 + 1 is
  // especially widespread. Of the certificates observed in the UCSD TLS Corpus
  // [23] (which was obtained by surveying frequently-used TLS servers), 99.5%
  // had e = 65537, and all had e at most 32 bits.
  uint32_t E;

  // RSA public key, part N.
  // The public key is the combination of E and N.
  // But N is a very large number and need to use array to represent it.
  // The total length in byte is key_size/8 (The key_size is in bits).
  // The memory layout is the same as the field "p" of mbedtls_mpi type.
  uint8_t *N;

  // length of signature, in bytes.
  uint32_t sig_length;
  // pointer to signature
  uint8_t *sig;
} RsaInfo;

/**
 * This structure contains the following information:
 * 1) RSA Key Size
 * 2) RSA modulus N
 * 3) A random integer g
 * 4) Proof Data: integers a and d
 */
typedef struct NonmembershipInfo {
  // RSA Key Size, in bits. For example, 1024, 2048.
  // Normally we use 1024; Choose 2048 for safety.
  uint32_t key_size;

  // The message size that this accumulator deals with
  // Much smaller than key_size. Take l = 256 should be sufficient
  uint32_t l;

  // RSA modulus N. Note that in RSA accumulator the exponent E is not needed
  // N is a very large number and should be stored in a byte array of size key_size/8
  uint8_t *N;

  // g is a random value in QR[n] which is the group of quadratic residues modulo n
  // i.e. g = x^2 mod n for some 0 <= x < n
  // g generates a group G_n = {g^k mod n | for 0 <= k < order(g)}
  // g should be of size key_size/8, i.e. same as n
  uint8_t *g;

  // The nonmembership proof contains two integers: a and d
  // where a is an integer less than 2^l
  // and d is in the group G_n
  // a is stored in array of size l/8
  // d is stored in array of size key_size/8
  uint8_t *a;
  uint8_t *d;

  // The accumulator is an integer 0 <= c < n of size key_size/8
  uint8_t *c;
} NonmembershipInfo;
#endif  // CKB_MISCELLANEOUS_SCRIPTS_RSA_SIGHASH_ALL_H
