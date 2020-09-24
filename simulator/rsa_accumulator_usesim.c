#include "../c/rsa_sighash_all.c"

static unsigned char get_hex(unsigned char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  else if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  else
    return 0;
}

static int scan_hex(const char *s, unsigned char *value) {
  if (s[0] == '\0' || s[1] == '\0') return 0;

  unsigned char high_part = get_hex(s[0]);
  unsigned char low_part = get_hex(s[1]);

  *value = (high_part << 4) + low_part;
  return 1;
}

static int bytes_from_hex(const char *s, unsigned char *value, int n) {
  for(int i = 0; i < n; i++) {
    if(scan_hex(s + 2 * i, value + i) == 0)
      return 0;
  }
  return 1;
}

void mbedtls_mpi_dump(const char *prefix, const mbedtls_mpi *X) {
  size_t n;
  char s[1024];
  memset(s, 0, sizeof(s));

  mbedtls_mpi_write_string(X, 16, s, sizeof(s) - 2, &n);
  mbedtls_printf("%s%s\n", prefix, s);
}

void dup_buffer(const unsigned char *src, int src_len, unsigned char *dest,
                int dup_count) {
  for (int i = 0; i < dup_count; i++) {
    for (int j = 0; j < src_len; j++) {
      dest[i * src_len + j] = src[j];
    }
  }
}

int main(int argc, const char *argv[]) {
  (void)argc;
  (void)argv;
  int exit_code = ERROR_RSA_ONLY_INIT;
  mbedtls_printf("Entering main()\n");

  // TODO: use real data instead of fake ones
  const char *N =
      "A1D46FBA2318F8DCEF16C280948B1CF27966B9B47225ED2989F8D74B45BD36049C0AAB5A"
      "D0FF003553BA843C8E12782FC5873BB89A3DC84B883D25666CD22BF3ACD5B675969F8BEB"
      "FBCAC93FDD927C7442B178B10D1DFF9398E52316AAE0AF74E594650BDC3C670241D41868"
      "4593CDA1A7B9DC4F20D2FDC6F66344074003E211"; // 1024 bits
  const char *g =
      "5AC84DEA32E756A5A1C287C5F4F1446F0606ACF8202D419570B2082EB8C439FB2157DF48"
      "2546487B89FD6A8E00452431E57AD264C9D0B7F71182D250219CFCBA74D61AC01ACE4820"
      "6DA7D124BE2E1DA77A9E1F4CF34F64CC4085DA79AE406A96C4F15467086839A79EAB691C"
      "73D1EE248819479574028389376BD7F9FB4F5C9B"; // 1024 bits
  const char *a =
      "5AC84DEA32E756A5A1C287C5F4F1446F0606ACF8202D419570B2082EB8C439FB"; // 256 bits
  const char *d =
      "5AC84DEA32E756A5A1C287C5F4F1446F0606ACF8202D419570B2082EB8C439FB2157DF48"
      "2546487B89FD6A8E00452431E57AD264C9D0B7F71182D250219CFCBA74D61AC01ACE4820"
      "6DA7D124BE2E1DA77A9E1F4CF34F64CC4085DA79AE406A96C4F15467086839A79EAB691C"
      "73D1EE248819479574028389376BD7F9FB4F5C9B"; // 1024 bits
  const char *c =
      "5AC84DEA32E756A5A1C287C5F4F1446F0606ACF8202D419570B2082EB8C439FB2157DF48"
      "2546487B89FD6A8E00452431E57AD264C9D0B7F71182D250219CFCBA74D61AC01ACE4820"
      "6DA7D124BE2E1DA77A9E1F4CF34F64CC4085DA79AE406A96C4F15467086839A79EAB691C"
      "73D1EE248819479574028389376BD7F9FB4F5C9B"; // 1024 bits

  const char *msg = "hello,CKB!";

  unsigned char N_buf[1024/8];
  unsigned char g_buf[1024/8];
  unsigned char a_buf[256/8];
  unsigned char d_buf[1024/8];
  unsigned char c_buf[1024/8];

  bytes_from_hex(N, N_buf, 1024/8);
  bytes_from_hex(g, g_buf, 1024/8);
  bytes_from_hex(a, a_buf, 256/8);
  bytes_from_hex(d, d_buf, 1024/8);
  bytes_from_hex(c, c_buf, 1024/8);

  NonmembershipInfo info;
  info.key_size = 1024;
  info.l = 256;
  info.N = N_buf;
  info.g = g_buf;
  info.a = a_buf;
  info.d = d_buf;
  info.c = c_buf;

  int result = verify_nonmembership(NULL, (const uint8_t *)&info, sizeof(info),
                                  (const uint8_t *)msg, strlen(msg), NULL, NULL);
  if (result == 0) {
    mbedtls_printf("verify nonmembership passed\n");
  } else {
    mbedtls_printf("verify nonmembership failed: %d\n", result);
    exit_code = ERROR_NONMEMBERSHIP_VERIFY_FAILED;
    goto exit;
  }

exit:
  if (exit_code != CKB_SUCCESS) {
    mbedtls_printf("Failed, check log!");
  }
  return exit_code;
}
