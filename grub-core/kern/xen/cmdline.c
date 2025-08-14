/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2025  Free Software Foundation, Inc.
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

#include <grub/env.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/xen.h>
#include <grub/err.h>

enum splitter_state
{
  SPLITTER_NORMAL = 0x0,
  SPLITTER_HIT_BACKSLASH = 0x1,
  SPLITTER_IN_SINGLE_QUOTES = 0x2,
  SPLITTER_IN_DOUBLE_QUOTES = 0x4,
};
typedef enum splitter_state splitter_state_t;

/*
 * The initial size of the current_word buffer. The buffer may be resized as
 * needed.
 */
#define PARSER_BASE_WORD_SIZE 32

struct parser_state
{
  char **words;
  grub_size_t words_count;
  char *current_word;
  grub_size_t current_word_len;
  grub_size_t current_word_pos;
};
typedef struct parser_state parser_state_t;

static grub_err_t
append_char_to_word (parser_state_t *ps, char c, bool allow_null)
{
  /*
   * We ban any chars that are not in the ASCII printable range. If
   * allow_null == true, we make an exception for NUL. (This is needed so that
   * append_word_to_list can add a NUL terminator to the word).
   */
  if (!grub_isprint (c) && allow_null == false)
    return GRUB_ERR_BAD_ARGUMENT;
  else if (allow_null == true && c != '\0')
    return GRUB_ERR_BAD_ARGUMENT;

  if (ps->current_word_pos == ps->current_word_len)
    {
      ps->current_word = grub_realloc (ps->current_word, ps->current_word_len *= 2);
      if (ps->current_word == NULL)
        {
          ps->current_word_len /= 2;
          return grub_errno;
        }
    }

  ps->current_word[ps->current_word_pos++] = c;
  return GRUB_ERR_NONE;
}

static grub_err_t
append_word_to_list (parser_state_t *ps)
{
  /* No-op on empty words. */
  if (ps->current_word_pos == 0)
    return GRUB_ERR_NONE;

  if (append_char_to_word (ps, '\0', true) != GRUB_ERR_NONE)
    grub_fatal ("couldn't append NUL terminator to word during Xen cmdline parsing");

  ps->current_word_len = grub_strlen (ps->current_word) + 1;
  ps->current_word = grub_realloc (ps->current_word, ps->current_word_len);
  if (ps->current_word == NULL)
    return grub_errno;
  ps->words = grub_realloc (ps->words, ++ps->words_count * sizeof (char *));
  if (ps->words == NULL)
    return grub_errno;
  ps->words[ps->words_count - 1] = ps->current_word;

  ps->current_word_len = PARSER_BASE_WORD_SIZE;
  ps->current_word_pos = 0;
  ps->current_word = grub_malloc (ps->current_word_len);
  if (ps->current_word == NULL)
    return grub_errno;

  return GRUB_ERR_NONE;
}

static bool
is_key_safe (char *key, grub_size_t len)
{
  grub_size_t i;

  for (i = 0; i < len; i++)
    if (!grub_isalpha (key[i]) && key[i] != '_')
      return false;

  return true;
}

void
grub_parse_xen_cmdline (void)
{
  parser_state_t ps = {0};
  splitter_state_t ss = SPLITTER_NORMAL;

  const char *cmdline = (const char *) grub_xen_start_page_addr->cmd_line;
  grub_size_t cmdline_len;
  bool cmdline_valid = false;
  char **param_keys = NULL;
  char **param_vals = NULL;
  grub_size_t param_dict_len = 0;
  grub_size_t param_dict_pos = 0;
  char current_char = '\0';
  grub_size_t i = 0;

  /*
   * The following algorithm is used to parse the Xen command line:
   *
   * - The command line is split into space-separated words.
   *   - Single and double quotes may be used to suppress the splitting
   *     behavior of spaces.
   *   - Double quotes are appended to the current word verbatim if they
   *     appear within a single-quoted string portion, and vice versa.
   *   - Backslashes may be used to cause the next character to be
   *     appended to the current word verbatim. This is only useful when
   *     used to escape quotes, spaces, and backslashes, but for simplicity
   *     we allow backslash-escaping anything.
   * - After splitting the command line into words, each word is checked to
   *   see if it contains an equals sign.
   *   - If it does, it is split on the equals sign into a key-value pair. The
   *     key is then treated as an variable name, and the value is treated as
   *     the variable's value.
   *   - If it does not, the entire word is treated as a variable name. The
   *     variable's value is implicitly considered to be `1`.
   * - All variables detected on the command line are checked to see if their
   *   names begin with the string `xen_grub_env_`. Variables that do not pass
   *   this check are discarded, variables that do pass this check are
   *   exported so they are available to the GRUB configuration.
   *
   * This behavior is intended to somewhat mimic the splitter behavior in Bash
   * and in GRUB's config file parser.
   */

  ps.current_word_len = PARSER_BASE_WORD_SIZE;
  ps.current_word = grub_malloc (ps.current_word_len);
  if (ps.current_word == NULL)
    goto cleanup_main;

  for (i = 0; i < GRUB_XEN_MAX_GUEST_CMDLINE; i++)
    {
      if (cmdline[i] == '\0')
        {
          cmdline_valid = true;
          break;
        }
    }

  if (cmdline_valid == false)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT,
		  "command line from Xen is not NUL-terminated");
      grub_print_error ();
      goto cleanup_main;
    }

  cmdline_len = grub_strlen (cmdline);
  for (i = 0; i < cmdline_len; i++)
    {
      current_char = cmdline[i];

      /*
       * If the previous character was a backslash, append the current
       * character to the word verbatim
       */
      if (ss & SPLITTER_HIT_BACKSLASH)
        {
          ss &= ~SPLITTER_HIT_BACKSLASH;
          if (append_char_to_word (&ps, current_char, false) != GRUB_ERR_NONE)
            goto cleanup_main;
          continue;
        }

      switch (current_char)
        {
        case '\\':
          /* Backslashes escape arbitrary characters. */
          ss |= SPLITTER_HIT_BACKSLASH;
          break;

        case '\'':
          /*
           * Single quotes suppress word splitting and double quoting until
           * the next single quote is encountered.
           */
          if (ss & SPLITTER_IN_DOUBLE_QUOTES)
            {
              if (append_char_to_word (&ps, current_char, false) != GRUB_ERR_NONE)
                goto cleanup_main;
              break;
            }

          ss ^= SPLITTER_IN_SINGLE_QUOTES;
          break;

        case '"':
          /*
           * Double quotes suppress word splitting and single quoting until
           * the next double quote is encountered.
           */
          if (ss & SPLITTER_IN_SINGLE_QUOTES)
            {
              if (append_char_to_word (&ps, current_char, false) != GRUB_ERR_NONE)
                goto cleanup_main;
              break;
            }

          ss ^= SPLITTER_IN_DOUBLE_QUOTES;
          break;

        case ' ':
          /* Spaces separate words in the command line from each other. */
          if (ss & SPLITTER_IN_SINGLE_QUOTES ||
              ss & SPLITTER_IN_DOUBLE_QUOTES)
            {
              if (append_char_to_word (&ps, current_char, false) != GRUB_ERR_NONE)
                goto cleanup_main;
              break;
            }

          if (append_word_to_list (&ps) != GRUB_ERR_NONE)
            goto cleanup_main;
          break;

        default:
          if (append_char_to_word (&ps, current_char, false) != GRUB_ERR_NONE)
            goto cleanup_main;
        }
    }

  if (append_word_to_list (&ps) != GRUB_ERR_NONE)
    goto cleanup_main;

  param_keys = grub_malloc (ps.words_count * sizeof (char *));
  if (param_keys == NULL)
    goto cleanup_main;
  param_vals = grub_malloc (ps.words_count * sizeof (char *));
  if (param_vals == NULL)
    goto cleanup_main;

  for (i = 0; i < ps.words_count; i++)
    {
      char *eq_pos;

      ps.current_word = ps.words[i];
      ps.current_word_len = grub_strlen (ps.current_word) + 1;
      eq_pos = grub_strchr (ps.current_word, '=');

      if (eq_pos != NULL)
        {
          /*
           * Both pre_eq_len and post_eq_len represent substring lengths
           * without a NUL terminator.
           */
          grub_size_t pre_eq_len = (grub_size_t) (eq_pos - ps.current_word);
          /*
           * ps.current_word_len includes the NUL terminator, so we subtract
           * one to get rid of the terminator, and one more to get rid of the
           * equals sign.
           */
          grub_size_t post_eq_len = (ps.current_word_len - 2) - pre_eq_len;

          if (is_key_safe (ps.current_word, pre_eq_len) == true)
            {
              param_dict_pos = param_dict_len++;
              param_keys[param_dict_pos] = grub_malloc (pre_eq_len + 1);
              if (param_keys == NULL)
                goto cleanup_main;
              param_vals[param_dict_pos] = grub_malloc (post_eq_len + 1);
              if (param_vals == NULL)
                goto cleanup_main;

              grub_strncpy (param_keys[param_dict_pos], ps.current_word, pre_eq_len);
              grub_strncpy (param_vals[param_dict_pos],
			    ps.current_word + pre_eq_len + 1, post_eq_len);
              param_keys[param_dict_pos][pre_eq_len] = '\0';
              param_vals[param_dict_pos][post_eq_len] = '\0';
            }
        }
      else if (is_key_safe (ps.current_word, ps.current_word_len - 1) == true)
        {
          param_dict_pos = param_dict_len++;
          param_keys[param_dict_pos] = grub_malloc (ps.current_word_len);
          if (param_keys == NULL)
            goto cleanup_main;
          param_vals[param_dict_pos] = grub_zalloc (2);
          if (param_vals == NULL)
            goto cleanup_main;

          grub_strncpy (param_keys[param_dict_pos], ps.current_word,
			ps.current_word_len);
          if (param_keys[param_dict_pos][ps.current_word_len - 1] != '\0' )
            grub_fatal ("NUL terminator missing from key during Xen cmdline parsing");
          *param_vals[param_dict_pos] = '1';
        }
    }

  for (i = 0; i < param_dict_len; i++)
    {
      /*
       * Find keys that start with "xen_grub_env_" and export them
       * as environment variables.
       */
      if (grub_strncmp (param_keys[i],
			"xen_grub_env_",
			sizeof ("xen_grub_env_") - 1) != 0)
        continue;

      if (grub_env_set (param_keys[i], param_vals[i]) != GRUB_ERR_NONE)
        {
          grub_printf ("warning: could not set environment variable `%s' to value `%s'\n",
		       param_keys[i], param_vals[i]);
          continue;
        }

      if (grub_env_export (param_keys[i]) != GRUB_ERR_NONE)
        grub_printf ("warning: could not export environment variable `%s'",
		     param_keys[i]);
    }

 cleanup_main:
  for (i = 0; i < ps.words_count; i++)
    grub_free (ps.words[i]);

  for (i = 0; i < param_dict_len; i++)
    {
      grub_free (param_keys[i]);
      grub_free (param_vals[i]);
    }

  grub_free (param_keys);
  grub_free (param_vals);
  grub_free (ps.words);
}
