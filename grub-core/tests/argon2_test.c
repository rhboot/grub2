static void
check_argon2 (void)
{
  gcry_error_t err;
  static struct {
    int subalgo;
    unsigned long param[4];
    size_t passlen;
    const char *pass;
    size_t saltlen;
    const char *salt;
    size_t keylen;
    const char *key;
    size_t adlen;
    const char *ad;
    size_t dklen;
    const char *dk;
  } tv[] = {
    {
      GCRY_KDF_ARGON2D,
      { 32, 3, 32, 4 },
      32,
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
      16,
      "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02",
      8,
      "\x03\x03\x03\x03\x03\x03\x03\x03",
      12,
      "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04",
      32,
      "\x51\x2b\x39\x1b\x6f\x11\x62\x97\x53\x71\xd3\x09\x19\x73\x42\x94"
      "\xf8\x68\xe3\xbe\x39\x84\xf3\xc1\xa1\x3a\x4d\xb9\xfa\xbe\x4a\xcb"
    },
    {
      GCRY_KDF_ARGON2I,
      { 32, 3, 32, 4 },
      32,
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
      16,
      "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02",
      8,
      "\x03\x03\x03\x03\x03\x03\x03\x03",
      12,
      "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04",
      32,
      "\xc8\x14\xd9\xd1\xdc\x7f\x37\xaa\x13\xf0\xd7\x7f\x24\x94\xbd\xa1"
      "\xc8\xde\x6b\x01\x6d\xd3\x88\xd2\x99\x52\xa4\xc4\x67\x2b\x6c\xe8"
    },
    {
      GCRY_KDF_ARGON2ID,
      { 32, 3, 32, 4 },
      32,
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
      16,
      "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02",
      8,
      "\x03\x03\x03\x03\x03\x03\x03\x03",
      12,
      "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04",
      32,
      "\x0d\x64\x0d\xf5\x8d\x78\x76\x6c\x08\xc0\x37\xa3\x4a\x8b\x53\xc9"
      "\xd0\x1e\xf0\x45\x2d\x75\xb6\x5e\xb5\x25\x20\xe9\x6b\x01\xe6\x59"
    },
    {
      /* empty password */
      GCRY_KDF_ARGON2I,
      { 32, 3, 128, 1 },
      0, NULL,
      16,
      "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
      0, NULL,
      0, NULL,
      32,
      "\xbb\x1f\xf2\xb9\x9f\xd4\x4a\xd9\xdf\x7f\xb9\x54\x55\x9e\xb8\xeb"
      "\xb5\x9d\xab\xce\x2e\x62\x9f\x9b\x89\x09\xfe\xde\x57\xcc\x63\x86"
    },
    {
      /* empty password */
      GCRY_KDF_ARGON2ID,
      { 32, 3, 128, 1 },
      0, NULL,
      16,
      "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
      0, NULL,
      0, NULL,
      32,
      "\x09\x2f\x38\x35\xac\xb2\x43\x92\x93\xeb\xcd\xe8\x04\x16\x6a\x31"
      "\xce\x14\xd4\x55\xdb\xd8\xf7\xe6\xb4\xf5\x9d\x64\x8e\xd0\x3a\xdb"
    },
  };
  unsigned char out[32];
  int i;
  int count;

  for (count = 0; count < DIM(tv); count++)
    {
      if (verbose)
        fprintf (stderr, "checking ARGON2 test vector %d\n", count);

      err = my_kdf_derive (0, GCRY_KDF_ARGON2,
                           tv[count].subalgo, tv[count].param, 4,
                           tv[count].pass, tv[count].passlen,
                           tv[count].salt, tv[count].saltlen,
                           tv[count].key, tv[count].keylen,
                           tv[count].ad, tv[count].adlen,
                           tv[count].dklen, out);
      if (err)
        fail ("argon2 test %d failed: %s\n", count*2+0, gpg_strerror (err));
      else if (memcmp (out, tv[count].dk, tv[count].dklen))
        {
          fail ("argon2 test %d failed: mismatch\n", count*2+0);
          fputs ("got:", stderr);
          for (i=0; i < tv[count].dklen; i++)
            fprintf (stderr, " %02x", out[i]);
          putc ('\n', stderr);
        }

#ifdef HAVE_PTHREAD
      err = my_kdf_derive (1, GCRY_KDF_ARGON2,
                           tv[count].subalgo, tv[count].param, 4,
                           tv[count].pass, tv[count].passlen,
                           tv[count].salt, tv[count].saltlen,
                           tv[count].key, tv[count].keylen,
                           tv[count].ad, tv[count].adlen,
                           tv[count].dklen, out);
      if (err)
        fail ("argon2 test %d failed: %s\n", count*2+1, gpg_strerror (err));
      else if (memcmp (out, tv[count].dk, tv[count].dklen))
        {
          fail ("argon2 test %d failed: mismatch\n", count*2+1);
          fputs ("got:", stderr);
          for (i=0; i < tv[count].dklen; i++)
            fprintf (stderr, " %02x", out[i]);
          putc ('\n', stderr);
        }
#endif
    }
}
