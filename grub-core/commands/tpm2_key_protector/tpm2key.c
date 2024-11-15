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

#include <grub/list.h>
#include <grub/misc.h>
#include <grub/mm.h>

#include <tss2_buffer.h>

#include "tpm2key.h"

extern asn1_static_node tpm2key_asn1_tab[];
const char *sealed_key_oid = "2.23.133.10.1.5";

static int
asn1_allocate_and_read (asn1_node node, const char *name, void **content, grub_size_t *content_size)
{
  grub_uint8_t *tmpstr = NULL;
  int tmpstr_size = 0;
  int ret;

  if (content == NULL)
    return ASN1_MEM_ERROR;

  ret = asn1_read_value (node, name, NULL, &tmpstr_size);
  if (ret != ASN1_MEM_ERROR)
    return ret;

  tmpstr = grub_malloc (tmpstr_size);
  if (tmpstr == NULL)
    return ASN1_MEM_ERROR;

  ret = asn1_read_value (node, name, tmpstr, &tmpstr_size);
  if (ret != ASN1_SUCCESS)
    return ret;

  *content = tmpstr;
  *content_size = tmpstr_size;

  return ASN1_SUCCESS;
}

static int
asn1_read_uint32 (asn1_node node, const char *name, grub_uint32_t *out)
{
  grub_uint32_t tmp = 0;
  grub_uint8_t *ptr;
  void *data = NULL;
  grub_size_t data_size;
  int ret;

  ret = asn1_allocate_and_read (node, name, &data, &data_size);
  if (ret != ASN1_SUCCESS)
    return ret;

  /*
   * ASN.1 INTEGER is encoded in the following format:
   *
   * TAG LENGTH OCTECTS
   *
   * The integer TAG is 02 and LENGTH is the number of followed OCTECTS in
   * big endian. For example:
   *
   *    0x1: 02 01 01
   * 0xabcd: 02 02 ab cd
   *
   * To decribe 0x1, it only takes 1 octect, so LENGTH is 0x01 and the
   * octect is 0x01. On the other hand, 0xabcd requires 2 octects: 'ab" and
   * 'cd', so LENGTH is 0x02.
   *
   * This function only expects a uint32 integer, so it rejects any integer
   * containing more than 4 octects.
   */
  if (data_size > 4)
    {
      ret = ASN1_MEM_ERROR;
      goto error;
    }

  /* Copy the octects into 'tmp' to make it a big-endian uint32 */
  ptr = (grub_uint8_t *) &tmp + (4 - data_size);
  grub_memcpy (ptr, data, data_size);

  /* Convert the big-endian integer to host uint32 */
  tmp = grub_be_to_cpu32 (tmp);

  *out = tmp;
 error:
  if (data)
    grub_free (data);
  return ret;
}

grub_err_t
grub_tpm2key_start_parsing (asn1_node *parsed_tpm2key, void *data, grub_size_t size)
{
  asn1_node tpm2key;
  asn1_node tpm2key_asn1 = NULL;
  void *type_oid = NULL;
  grub_size_t type_oid_size = 0;
  void *empty_auth = NULL;
  grub_size_t empty_auth_size = 0;
  int tmp_size = 0;
  int ret;
  grub_err_t err;

  /*
   * TPMKey ::= SEQUENCE {
   *    type        OBJECT IDENTIFIER,
   *    emptyAuth   [0] EXPLICIT BOOLEAN OPTIONAL,
   *    policy      [1] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL,
   *    secret      [2] EXPLICIT OCTET STRING OPTIONAL,
   *    authPolicy  [3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL,
   *    description [4] EXPLICIT UTF8String OPTIONAL,
   *    rsaParent   [5] EXPLICIT BOOLEAN OPTIONAL,
   *    parent      INTEGER,
   *    pubkey      OCTET STRING,
   *    privkey     OCTET STRING
   * }
   */
  ret = asn1_array2tree (tpm2key_asn1_tab, &tpm2key_asn1, NULL);
  if (ret != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "failed to parse TPM2KEY ASN.1 array");

  ret = asn1_create_element (tpm2key_asn1, "TPM2KEY.TPMKey", &tpm2key);
  if (ret != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "failed to create TPM2KEY.TPMKey");

  ret = asn1_der_decoding (&tpm2key, data, size, NULL);
  if (ret != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "failed to decode TPM2KEY DER");

  /* Check if 'type' is Sealed Key or not */
  ret = asn1_allocate_and_read (tpm2key, "type", &type_oid, &type_oid_size);
  if (ret != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a valid TPM2KEY file");

  if (grub_memcmp (sealed_key_oid, type_oid, type_oid_size) != 0)
    {
      err = grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a valid TPM2KEY file");
      goto error;
    }

  /* 'emptyAuth' must be 'TRUE' since we don't support password authorization */
  ret = asn1_allocate_and_read (tpm2key, "emptyAuth", &empty_auth, &empty_auth_size);
  if (ret != ASN1_SUCCESS || grub_strncmp ("TRUE", empty_auth, empty_auth_size) != 0)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT, "emptyAuth not TRUE");
      goto error;
    }

  /* 'secret' should not be in a sealed key */
  ret = asn1_read_value (tpm2key, "secret", NULL, &tmp_size);
  if (ret != ASN1_ELEMENT_NOT_FOUND)
    {
      err = grub_error (GRUB_ERR_BAD_ARGUMENT, "\"secret\" not allowed for Sealed Key");
      goto error;
    }

  *parsed_tpm2key = tpm2key;

  err = GRUB_ERR_NONE;

 error:
  grub_free (type_oid);
  grub_free (empty_auth);

  return err;
}

void
grub_tpm2key_end_parsing (asn1_node tpm2key)
{
  asn1_delete_structure (&tpm2key);
  tpm2key = NULL;
}

grub_err_t
grub_tpm2key_get_rsaparent (asn1_node tpm2key, grub_uint8_t *rsaparent)
{
  void *bool_str = NULL;
  grub_size_t bool_str_size = 0;
  int ret;

  if (rsaparent == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "NULL pointer detected");

  if (tpm2key == NULL)
    return grub_error (GRUB_ERR_READ_ERROR, "invalid parent node");

  ret = asn1_allocate_and_read (tpm2key, "rsaParent", &bool_str, &bool_str_size);
  if (ret == ASN1_SUCCESS)
    {
      if (grub_strncmp ("TRUE", bool_str, bool_str_size) == 0)
	*rsaparent = 1;
      else
	*rsaparent = 0;
    }
  else if (ret == ASN1_ELEMENT_NOT_FOUND)
    *rsaparent = 0;
  else
    return grub_error (GRUB_ERR_READ_ERROR, "failed to retrieve rsaParent");

  grub_free (bool_str);

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tpm2key_get_parent (asn1_node tpm2key, grub_uint32_t *parent)
{
  int ret;

  if (parent == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "NULL pointer detected");

  if (tpm2key == NULL)
    return grub_error (GRUB_ERR_READ_ERROR, "invalid parent node");

  ret = asn1_read_uint32 (tpm2key, "parent", parent);
  if (ret != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_READ_ERROR, "failed to retrieve parent");

  return GRUB_ERR_NONE;
}

static grub_err_t
tpm2key_get_octstring (asn1_node tpm2key, const char *name, void **data, grub_size_t *size)
{
  int ret;

  if (name == NULL || data == NULL || size == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "invalid parameter(s)");

  if (tpm2key == NULL)
    return grub_error (GRUB_ERR_READ_ERROR, "invalid %s node", name);

  ret = asn1_allocate_and_read (tpm2key, name, data, size);
  if (ret != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_READ_ERROR, "failed to retrieve %s", name);

  return GRUB_ERR_NONE;
}

grub_err_t
grub_tpm2key_get_pubkey (asn1_node tpm2key, void **data, grub_size_t *size)
{
  return tpm2key_get_octstring (tpm2key, "pubkey", data, size);
}

grub_err_t
grub_tpm2key_get_privkey (asn1_node tpm2key, void **data, grub_size_t *size)
{
  return tpm2key_get_octstring (tpm2key, "privkey", data, size);
}

/*
 * The maximum and minimum number of elements for 'policy' and 'authPolicy' sequences
 *
 * Although there is no limit for the number of sequences elements, we set the upper
 * bound to 99 to make it easier to implement the code.
 *
 * Any 'policy' or 'authPolicy' contains more than 99 commands/policies would become
 * extremely complex to manage so it is impractical to support such use case.
 */
#define TPM2KEY_ELEMENTS_MAX 99
#define TPM2KEY_ELEMENTS_MIN 1

/*
 * The string to fetch 'Policy' from 'authPolicy':
 *   authPolicy.?XX.Policy
 */
#define AUTHPOLICY_POL_MAX_STR "authPolicy.?XX.Policy"
#define AUTHPOLICY_POL_MAX (sizeof (AUTHPOLICY_POL_MAX_STR))

/*
 * Expected strings for CommandCode and CommandPolicy:
 *   policy.?XX.CommandCode
 *   policy.?XX.CommandPolicy
 *   authPolicy.?XX.Policy.?YY.CommandCode
 *   authPolicy.?XX.Policy.?YY.CommandPolicy
 */
#define CMD_CODE_MAX_STR AUTHPOLICY_POL_MAX_STR".?YY.CommandCode"
#define CMD_POL_MAX_STR  AUTHPOLICY_POL_MAX_STR".?YY.CommandPolicy"
#define CMD_CODE_MAX (sizeof (CMD_CODE_MAX_STR))
#define CMD_POL_MAX  (sizeof (CMD_POL_MAX_STR))

static int
tpm2key_get_policy_seq (asn1_node tpm2key, const char *prefix,
			tpm2key_policy_t *policy_seq)
{
  tpm2key_policy_t tmp_seq = NULL;
  tpm2key_policy_t policy = NULL;
  int policy_n;
  char cmd_code[CMD_CODE_MAX];
  char cmd_pol[CMD_POL_MAX];
  grub_size_t cmd_policy_len;
  int i;
  int ret;

  ret = asn1_number_of_elements (tpm2key, prefix, &policy_n);
  if (ret != ASN1_SUCCESS)
    return ret;

  /*
   * Limit the number of policy commands to two digits (99)
   * Although there is no upper bound for the number of policy commands,
   * in practice, it takes one or two policy commands to unseal the key,
   * so the 99 commands limit is more than enough.
   */
  if (policy_n > TPM2KEY_ELEMENTS_MAX || policy_n < TPM2KEY_ELEMENTS_MIN)
    return ASN1_VALUE_NOT_VALID;

  /*
   * Iterate the policy commands backwards since grub_list_push() prepends
   * the item into the list.
   */
  for (i = policy_n; i >= 1; i--) {
    policy = grub_zalloc (sizeof (struct tpm2key_policy));
    if (policy == NULL)
      {
	ret = ASN1_MEM_ALLOC_ERROR;
	goto error;
      }
    grub_snprintf (cmd_code, CMD_CODE_MAX, "%s.?%d.CommandCode", prefix, i);
    grub_snprintf (cmd_pol, CMD_POL_MAX, "%s.?%d.CommandPolicy", prefix, i);

    /* CommandCode   [0] EXPLICIT INTEGER */
    ret = asn1_read_uint32 (tpm2key, cmd_code, &policy->cmd_code);
    if (ret != ASN1_SUCCESS)
      return ret;

    /* CommandPolicy [1] EXPLICIT OCTET STRING */
    ret = tpm2key_get_octstring (tpm2key, cmd_pol, &policy->cmd_policy,
				 &cmd_policy_len);
    if (ret != ASN1_SUCCESS)
      {
	goto error;
      }
    else if (cmd_policy_len > GRUB_TPM2_BUFFER_CAPACITY)
      {
	/*
	 * CommandPolicy is the marshalled parameters for the TPM command so
	 * it should not be larger than the maximum TPM2 buffer.
	 */
	ret = ASN1_VALUE_NOT_VALID;
	goto error;
      }
    policy->cmd_policy_len = (grub_uint16_t)cmd_policy_len;

    /* Prepend the policy command into the sequence */
    grub_list_push (GRUB_AS_LIST_P (&tmp_seq), GRUB_AS_LIST (policy));
  }

  *policy_seq = tmp_seq;

  return ASN1_SUCCESS;

 error:
  if (policy != NULL)
    {
      grub_free (policy->cmd_policy);
      grub_free (policy);
    }
  grub_tpm2key_free_policy_seq (tmp_seq);

  return ret;
}

grub_err_t
grub_tpm2key_get_policy_seq (asn1_node tpm2key, tpm2key_policy_t *policy_seq)
{
  int ret;

  ret = tpm2key_get_policy_seq (tpm2key, "policy", policy_seq);
  if (ret == ASN1_ELEMENT_NOT_FOUND)
    {
      /* "policy" is optional, so it may not be available */
      *policy_seq = NULL;
      return GRUB_ERR_NONE;
    }
  else if (ret != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_READ_ERROR, "failed to retrieve policy");

  return GRUB_ERR_NONE;
}

void
grub_tpm2key_free_policy_seq (tpm2key_policy_t policy_seq)
{
  tpm2key_policy_t policy;
  tpm2key_policy_t next;

  if (policy_seq == NULL)
    return;

  FOR_LIST_ELEMENTS_SAFE (policy, next, policy_seq)
    {
      grub_free (policy->cmd_policy);
      grub_free (policy);
    }
}

grub_err_t
grub_tpm2key_get_authpolicy_seq (asn1_node tpm2key, tpm2key_authpolicy_t *authpol_seq)
{
  tpm2key_authpolicy_t tmp_seq = NULL;
  tpm2key_authpolicy_t authpol = NULL;
  int authpol_n;
  char authpol_pol[AUTHPOLICY_POL_MAX];
  int i;
  int ret;
  grub_err_t err;

  ret = asn1_number_of_elements (tpm2key, "authPolicy", &authpol_n);
  if (ret == ASN1_ELEMENT_NOT_FOUND)
    {
      /* "authPolicy" is optional, so it may not be available */
      *authpol_seq = NULL;
      return GRUB_ERR_NONE;
    }
  else if (ret != ASN1_SUCCESS)
    return grub_error (GRUB_ERR_READ_ERROR, "failed to retrieve authPolicy");

  /* Limit the number of authPolicy elements to two digits (99) */
  if (authpol_n > TPM2KEY_ELEMENTS_MAX || authpol_n < TPM2KEY_ELEMENTS_MIN)
    return grub_error (GRUB_ERR_OUT_OF_RANGE, "invalid number of authPolicy elements");

  /*
   * Iterate the authPolicy elements backwards since grub_list_push() prepends
   * the item into the list.
   */
  for (i = authpol_n; i >= 1; i--) {
    authpol = grub_zalloc (sizeof (struct tpm2key_authpolicy));
    if (authpol == NULL)
      {
	err = grub_error (GRUB_ERR_OUT_OF_MEMORY, "failed to allocate memory for authPolicy");
	goto error;
      }
    grub_snprintf (authpol_pol, AUTHPOLICY_POL_MAX, "authPolicy.?%d.Policy", i);

    ret = tpm2key_get_policy_seq (tpm2key, authpol_pol, &authpol->policy_seq);
    if (ret != ASN1_SUCCESS)
      {
        err = grub_error (GRUB_ERR_READ_ERROR, "failed to retrieve policy from authPolicy");
        goto error;
      }

    /* Prepend the authPolicy element into the sequence */
    grub_list_push (GRUB_AS_LIST_P (&tmp_seq), GRUB_AS_LIST (authpol));
  }

  *authpol_seq = tmp_seq;

  return GRUB_ERR_NONE;

 error:
  if (authpol != NULL)
    {
      grub_tpm2key_free_policy_seq (authpol->policy_seq);
      grub_free (authpol);
    }

  grub_tpm2key_free_authpolicy_seq (tmp_seq);

  return err;
}

void
grub_tpm2key_free_authpolicy_seq (tpm2key_authpolicy_t authpol_seq)
{
  tpm2key_authpolicy_t authpol;
  tpm2key_authpolicy_t next;

  if (authpol_seq == NULL)
    return;

  FOR_LIST_ELEMENTS_SAFE (authpol, next, authpol_seq)
    {
      grub_tpm2key_free_policy_seq (authpol->policy_seq);
      grub_free (authpol);
    }
}
