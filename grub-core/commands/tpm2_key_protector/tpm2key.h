/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2023 SUSE LLC
 *  Copyright (C) 2024 Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_TPM2_TPM2KEY_HEADER
#define GRUB_TPM2_TPM2KEY_HEADER 1

#include <grub/types.h>
#include <libtasn1.h>

/*
 * TPMPolicy ::= SEQUENCE {
 *   CommandCode   [0] EXPLICIT INTEGER,
 *   CommandPolicy [1] EXPLICIT OCTET STRING
 * }
 */
struct tpm2key_policy {
  struct tpm2key_policy *next;
  struct tpm2key_policy **prev;
  grub_uint32_t cmd_code;
  void *cmd_policy;
  grub_uint16_t cmd_policy_len;
};
typedef struct tpm2key_policy *tpm2key_policy_t;

/*
 * TPMAuthPolicy ::= SEQUENCE {
 *   Name    [0] EXPLICIT UTF8String OPTIONAL,
 *   Policy  [1] EXPLICIT SEQUENCE OF TPMPolicy
 * }
 *
 * Name is not a necessary part to unseal the key. Ignore it.
 */
struct tpm2key_authpolicy {
  struct tpm2key_authpolicy *next;
  struct tpm2key_authpolicy **prev;
  /* char *name; */
  tpm2key_policy_t policy_seq;
};
typedef struct tpm2key_authpolicy *tpm2key_authpolicy_t;

extern grub_err_t
grub_tpm2key_start_parsing (asn1_node *parsed_tpm2key, void *data, grub_size_t size);

extern void
grub_tpm2key_end_parsing (asn1_node tpm2key);

extern grub_err_t
grub_tpm2key_get_rsaparent (asn1_node tpm2key, grub_uint8_t *rsaparent);

extern grub_err_t
grub_tpm2key_get_parent (asn1_node tpm2key, grub_uint32_t *parent);

extern grub_err_t
grub_tpm2key_get_pubkey (asn1_node tpm2key, void **data, grub_size_t *size);

extern grub_err_t
grub_tpm2key_get_privkey (asn1_node tpm2key, void **data, grub_size_t *size);

extern grub_err_t
grub_tpm2key_get_policy_seq (asn1_node tpm2key, tpm2key_policy_t *policy_seq);

extern void
grub_tpm2key_free_policy_seq (tpm2key_policy_t policy_seq);

extern grub_err_t
grub_tpm2key_get_authpolicy_seq (asn1_node tpm2key, tpm2key_authpolicy_t *authpol_seq);

extern void
grub_tpm2key_free_authpolicy_seq (tpm2key_authpolicy_t authpol_seq);

#endif /* GRUB_TPM2_TPM2KEY_HEADER */
