// # rsa_sighash_all
// same as secp256k1_blake2b_sighash_all_dual but with RSA (mbedtls)
#include "rsa_sighash_all.h"

#include <string.h>

#include "mbedtls/md.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ctr_drbg.h"

#define CKB_SUCCESS 0
#define ERROR_ARGUMENTS_LEN (-1)
#define ERROR_ENCODING (-2)
#define ERROR_SYSCALL (-3)
#define ERROR_RSA_INVALID_PARAM1 (-40)
#define ERROR_RSA_INVALID_PARAM2 (-41)
#define ERROR_RSA_MDSTRING_FAILED (-42)
#define ERROR_RSA_VERIFY_FAILED (-43)
#define ERROR_RSA_ONLY_INIT (-44)
#define ERROR_RSA_INVALID_KEY_SIZE (-45)

#define ERROR_NONMEMBERSHIP_INVALID_PARAM1 (-1040)
#define ERROR_NONMEMBERSHIP_INVALID_PARAM2 (-1041)
#define ERROR_NONMEMBERSHIP_INVALID_MESSAGE_SIZE (-1042)
#define ERROR_NONMEMBERSHIP_HASH_SIZE_TOO_LARGE (-1043)
#define ERROR_NONMEMBERSHIP_HASH_TO_PRIME_FAILED (-1044)
#define ERROR_NONMEMBERSHIP_POWER_MOD_FAILED (-1045)
#define ERROR_NONMEMBERSHIP_MUL_FAILED (-1046)
#define ERROR_NONMEMBERSHIP_MOD_FAILED (-1047)
#define ERROR_NONMEMBERSHIP_VERIFY_FAILED (-1048)

#define RSA_VALID_KEY_SIZE1 1024
#define RSA_VALID_KEY_SIZE2 2048
#define RSA_VALID_KEY_SIZE3 4096

#define NONMEMBERSHIP_VALID_MESSAGE_SIZE 256

#define CHECK_PARAM(cond, code) \
  do {                          \
    if (!(cond)) {              \
      exit_code = code;         \
      goto exit;                \
    }                           \
  } while (0)

#if defined(USE_SIM)
#include <stdio.h>
#define mbedtls_printf printf
#else
#define mbedtls_printf(x, ...) (void)0
#endif

/**
 * Hashes a string using the given hash algorithm
 * @param md_info The info structure of the hash algorithm
 * @param buf the string to hash
 * @param n the size of the string to hash
 * @param output the buffer to store the hash value
 */
int md_string(const mbedtls_md_info_t *md_info, const unsigned char *buf,
              size_t n, unsigned char *output);

/**
 * Hash a string using the given hash algorithm, then increase the hash value
 * until it represents a prime number
 * @param md_info The info structure of the hash algorithm
 * @param buf the string to hash
 * @param n the size of the string to hash
 * @param output the resulting prime number
 * @return if succeed, return 0, else return nonzero value
 * Warning: Succeed or not, this function may modify output!!!
 */
int hash_to_prime(const mbedtls_md_info_t *md_info, const unsigned char *buf,
              size_t n, mbedtls_mpi *output);

/**
 * Note: there is no prefilled data for RSA, it's only be used in secp256k1.
 * Always succeed.
 * @param data
 * @param len
 * @return
 */
__attribute__((visibility("default"))) int load_prefilled_data(void *data,
                                                               size_t *len) {
  (void)data;
  *len = 0;
  return CKB_SUCCESS;
}

/**
 *
 * @param prefilled_data ignore. Not used.
 * @param signature_buffer pointer to signature buffer. It is casted to type
 * "RsaInfo*"
 * @param signature_size size of signature_buffer. it should be exactly the same
 * as size of "RsaInfo".
 * @param message_buffer pointer to message buffer.
 * @param message_size size of message_buffer.
 * @param output ignore. Not used
 * @param output_len ignore. Not used.
 * @return
 */
__attribute__((visibility("default"))) int validate_signature(
    void *prefilled_data, const uint8_t *signature_buffer,
    size_t signature_size, const uint8_t *message_buffer, size_t message_size,
    uint8_t *output, size_t *output_len) {
  (void)prefilled_data;
  (void)output;
  (void)output_len;
  int ret;
  int exit_code = ERROR_RSA_ONLY_INIT;
  mbedtls_rsa_context rsa;
  unsigned char hash[32];
  RsaInfo *input_info = (RsaInfo *)signature_buffer;

  // for key size with 1024 bits, it uses 3444 bytes at most.
  // for key size with 4096 bits, it uses 6316 bytes at most.
  const int alloc_buff_size = 1024 * 7;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  CHECK_PARAM(input_info->key_size == RSA_VALID_KEY_SIZE1 ||
                  input_info->key_size == RSA_VALID_KEY_SIZE2 ||
                  input_info->key_size == RSA_VALID_KEY_SIZE3,
              ERROR_RSA_INVALID_KEY_SIZE);
  CHECK_PARAM(signature_buffer != NULL, ERROR_RSA_INVALID_PARAM1);
  CHECK_PARAM(message_buffer != NULL, ERROR_RSA_INVALID_PARAM1);
  CHECK_PARAM(signature_size == sizeof(RsaInfo), ERROR_RSA_INVALID_PARAM2);

  mbedtls_mpi_read_binary_le(&rsa.E, (const unsigned char *)&input_info->E,
                             sizeof(uint32_t));
  mbedtls_mpi_read_binary_le(&rsa.N, (const unsigned char *)input_info->N,
                             input_info->key_size / 8);
  rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;

  ret = md_string(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), message_buffer,
                  message_size, hash);
  if (ret != 0) {
    mbedtls_printf("md_string failed: %d", ret);
    exit_code = ERROR_RSA_MDSTRING_FAILED;
    goto exit;
  }
  // note: hashlen = 20 is used for MD5, we can ignore it here for SHA256.
  ret = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC,
                                 MBEDTLS_MD_SHA256, 20, hash, input_info->sig);
  if (ret != 0) {
    mbedtls_printf("mbedtls_rsa_pkcs1_verify returned -0x%0x\n",
                   (unsigned int)-ret);
    exit_code = ERROR_RSA_VERIFY_FAILED;
    goto exit;
  }
  mbedtls_printf("\nOK (the signature is valid)\n");
  exit_code = CKB_SUCCESS;

exit:
  mbedtls_rsa_free(&rsa);
  return exit_code;
}


/**
 *
 * @param prefilled_data ignore. Not used.
 * @param proof_buffer pointer to proof buffer. It is casted to type
 * "NonmembershipInfo*"
 * @param proof_size size of proof_buffer. it should be exactly the same
 * as size of "NonmembershipInfo".
 * @param message_buffer pointer to message buffer.
 * @param message_size size of message_buffer.
 * @param output ignore. Not used
 * @param output_len ignore. Not used.
 * @return
 */
__attribute__((visibility("default"))) int verify_nonmembership(
    void *prefilled_data, const uint8_t *proof_buffer,
    size_t proof_size, const uint8_t *message_buffer, size_t message_size,
    uint8_t *output, size_t *output_len) {
  (void)prefilled_data;
  (void)output;
  (void)output_len;
  int ret;
  int exit_code = ERROR_RSA_ONLY_INIT;
  // mbedtls_rsa_context rsa;
  mbedtls_mpi N,g,a,d,c;
  unsigned char hash[32];
  NonmembershipInfo *input_info = (NonmembershipInfo *)proof_buffer;

  // Allocate memory in this buffer instead of from the heap
  // Should be sufficient to
  // TODO: give a precise estimate of the memory usage
  const int alloc_buff_size = 1024 * 100;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  // mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&g);
  mbedtls_mpi_init(&a);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&c);
  CHECK_PARAM(input_info->key_size == RSA_VALID_KEY_SIZE1 ||
                  input_info->key_size == RSA_VALID_KEY_SIZE2 ||
                  input_info->key_size == RSA_VALID_KEY_SIZE3,
              ERROR_RSA_INVALID_KEY_SIZE);
  CHECK_PARAM(input_info->l == NONMEMBERSHIP_VALID_MESSAGE_SIZE, ERROR_NONMEMBERSHIP_INVALID_MESSAGE_SIZE);
  CHECK_PARAM(proof_buffer != NULL, ERROR_NONMEMBERSHIP_INVALID_PARAM1);
  CHECK_PARAM(message_buffer != NULL, ERROR_NONMEMBERSHIP_INVALID_PARAM1);
  CHECK_PARAM(proof_size == sizeof(NonmembershipInfo), ERROR_NONMEMBERSHIP_INVALID_PARAM2);

  // Load all the integers from input
  mbedtls_mpi_read_binary_le(&rsa.N, (const unsigned char *)input_info->N,
                             input_info->key_size / 8);
  mbedtls_mpi_read_binary_le(&rsa.g, (const unsigned char *)input_info->g,
                             input_info->key_size / 8);
  mbedtls_mpi_read_binary_le(&rsa.a, (const unsigned char *)input_info->a,
                             input_info->l / 8);
  mbedtls_mpi_read_binary_le(&rsa.d, (const unsigned char *)input_info->d,
                             input_info->key_size / 8);
  mbedtls_mpi_read_binary_le(&rsa.c, (const unsigned char *)input_info->d,
                             input_info->key_size / 8);
  // rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;

  ret = hash_to_prime(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), message_buffer,
                  message_size, hash);
  if (ret != 0) {
    mbedtls_printf("\nhash_to_prime failed: %d\n", ret);
    exit_code = ERROR_NONMEMBERSHIP_HASH_TO_PRIME_FAILED;
    goto exit;
  }

  // check c^a = d^x g mod n, where x = hash(m)
  ret = mbedtls_mpi_power(c,c,a,n);
  if(ret != 0) {
    exit_code = ERROR_NONMEMBERSHIP_POWER_MOD_FAILED;
    goto exit;
  }

  ret = mbedtls_mpi_power(d,d,x,n);
  if(ret != 0) {
    exit_code = ERROR_NONMEMBERSHIP_POWER_MOD_FAILED;
    goto exit;
  }

  ret = mbedtls_mpi_mul_mpi(d,d,g);
  if(ret != 0) {
    exit_code = ERROR_NONMEMBERSHIP_MUL_FAILED;
    goto exit;
  }

  ret = mbedtls_mpi_mod_mpi(d,d,n);
  if(ret != 0) {
    exit_code = ERROR_NONMEMBERSHIP_MUL_FAILED;
    goto exit;
  }

  // Compare, if not zero, then the integers are not equal
  if(mbedtls_mpi_cmp_mpi(c,d) != 0) {
    mbedtls_printf("\nthe accumulator nonmembership verification fails\n");
    exit_code = ERROR_NONMEMBERSHIP_VERIFY_FAILED;
    goto exit;
  }

  mbedtls_printf("\nOK (the membersship proof is valid)\n");
  exit_code = CKB_SUCCESS;

exit:
  mbedtls_mpi_free(&N);
  mbedtls_mpi_free(&g);
  mbedtls_mpi_free(&a);
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&c);
  return exit_code;
}

int md_string(const mbedtls_md_info_t *md_info, const unsigned char *buf,
              size_t n, unsigned char *output) {
  int ret = -1;
  mbedtls_md_context_t ctx;

  if (md_info == NULL) return (MBEDTLS_ERR_MD_BAD_INPUT_DATA);

  mbedtls_md_init(&ctx);

  if ((ret = mbedtls_md_setup(&ctx, md_info, 0)) != 0) goto cleanup;

  if ((ret = mbedtls_md_starts(&ctx)) != 0) goto cleanup;

  if ((ret = mbedtls_md_update(&ctx, buf, n)) != 0) goto cleanup;

  ret = mbedtls_md_finish(&ctx, output);

cleanup:
  mbedtls_md_free(&ctx);
  return ret;
}

int hash_to_prime(const mbedtls_md_info_t *md_info, const unsigned char *buf,
                  size_t n, mbedtls_mpi *output) {
  int ret = -1;
  int size = md_info->size;
  mbedtls_mpi p;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;

  // The hash function we use should not be larger than the message size
  if(size <= NONMEMBERSHIP_VALID_MESSAGE_SIZE) {
    goto cleanup;
  }

  unsigned char hash_value[NONMEMBERSHIP_VALID_MESSAGE_SIZE];
  if((ret = md_string(md_info, buf, n, hash_value)) != 0) goto cleanup;

  // Directly use the output as the buffer for the prime
  if((ret = mbedtls_mpi_read_binary_le(output, hash_value, size)) != 0) goto cleanup;

  // The primality test requires some random number generator
  mbedtls_ctr_drbg_init( &ctr_drbg );
  mbedtls_entropy_init( &entropy );

  if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    goto cleanup;

  // This function returns 0 when the given integer IS PRIME
  // Returns MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if the integer is not prime
  // If any error, it returns other nonzero value
  // TODO: investigate the security issues that may brought by small round number
  // in the primality test
  // TODO: first increment to odd integer, then increment by two each time, to save time
  // TODO: investigate how to implement next_prime() more efficiently (refer to the gmp implementation)
  while((ret = mbedtls_mpi_is_prime_ext(output, 50, mbedtls_ctr_drbg_random, &ctr_drbg)) ==
    MBEDTLS_ERR_MPI_NOT_ACCEPTABLE) {
    if((ret = mbedtls_mpi_add_int(output, output, 1)) != 0) goto cleanup;
  }

cleanup:
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );
  return ret;
}