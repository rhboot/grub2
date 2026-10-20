/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2026 Free Software Foundation, Inc.
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

#include <grub/command.h>
#include <grub/dl.h>
#include <grub/misc.h>
#include <grub/normal.h>
#include <grub/procfs.h>
#include <grub/test.h>
#include <grub/term.h>

GRUB_MOD_LICENSE ("GPLv3+");

static const char silent_config[] = "true\n";
static const char nested_config[] =
  "configfile (proc)/deferred-clear-silent.cfg\n";
static unsigned int silent_config_reads;
static unsigned int nested_config_reads;

static char *
get_silent_config (grub_size_t *size)
{
  silent_config_reads++;
  *size = sizeof (silent_config) - 1;
  return grub_strdup (silent_config);
}

static char *
get_nested_config (grub_size_t *size)
{
  nested_config_reads++;
  *size = sizeof (nested_config) - 1;
  return grub_strdup (nested_config);
}

static struct grub_procfs_entry silent_config_entry =
  {
    .name = "deferred-clear-silent.cfg",
    .get_contents = get_silent_config
  };

static struct grub_procfs_entry nested_config_entry =
  {
    .name = "deferred-clear-nested.cfg",
    .get_contents = get_nested_config
  };

struct fake_state
{
  struct grub_term_coordinate pos;
  unsigned int chars;
  unsigned int clears;
  unsigned int chars_before_clear;
  struct grub_term_coordinate first_gotoxy;
  int have_gotoxy;
  int gotoxy_changed;
};

static void
fake_clear (struct grub_term_output *term)
{
  struct fake_state *state = term->data;

  if (state->clears == 0)
    state->chars_before_clear = state->chars;
  state->clears++;
  state->chars = 0;
  state->pos = (struct grub_term_coordinate) { 0, 0 };
}

static grub_err_t
fake_prepare (struct grub_term_output *term)
{
  if (term->flags & GRUB_TERM_OUTPUT_ACTIVE)
    return GRUB_ERR_NONE;

  term->flags |= GRUB_TERM_OUTPUT_ACTIVE;
  if (term->flags & GRUB_TERM_CLEAR_PENDING)
    {
      term->flags &= ~GRUB_TERM_CLEAR_PENDING;
      fake_clear (term);
    }

  return GRUB_ERR_NONE;
}

static void
fake_putchar (struct grub_term_output *term,
	      const struct grub_unicode_glyph *c)
{
  struct fake_state *state = term->data;

  fake_prepare (term);
  state->chars++;
  if (c->base == '\n')
    {
      state->pos.x = 0;
      state->pos.y++;
    }
  else
    state->pos.x++;
}

static struct grub_term_coordinate
fake_getwh (struct grub_term_output *term)
{
  fake_prepare (term);
  return (struct grub_term_coordinate) { 80, 25 };
}

static struct grub_term_coordinate
fake_getxy (struct grub_term_output *term)
{
  struct fake_state *state = term->data;

  return state->pos;
}

static void
fake_gotoxy (struct grub_term_output *term, struct grub_term_coordinate pos)
{
  struct fake_state *state = term->data;

  fake_prepare (term);
  if (!state->have_gotoxy)
    {
      state->first_gotoxy = pos;
      state->have_gotoxy = 1;
    }
  else if (state->first_gotoxy.x != pos.x || state->first_gotoxy.y != pos.y)
    state->gotoxy_changed = 1;
  state->pos = pos;
}

static void
fake_cls (struct grub_term_output *term)
{
  term->flags &= ~GRUB_TERM_CLEAR_PENDING;
  fake_prepare (term);
  fake_clear (term);
}

static void
reset_term (struct grub_term_output *term, struct fake_state *state,
	    int active)
{
  grub_memset (state, 0, sizeof (*state));
  state->pos = (struct grub_term_coordinate) { 7, 4 };
  term->flags &= ~(GRUB_TERM_OUTPUT_ACTIVE | GRUB_TERM_CLEAR_PENDING);
  if (active)
    term->flags |= GRUB_TERM_OUTPUT_ACTIVE;
}

static void
run_command (const char *name, int argc, char **argv)
{
  grub_command_t cmd = grub_command_find (name);

  grub_test_assert (cmd != NULL, "%s command is unavailable", name);
  if (cmd)
    grub_command_execute (name, argc, argv);
}

static void
deferred_clear_test (void)
{
  struct grub_term_output *saved_outputs = grub_term_outputs;
  struct fake_state first_state, second_state;
  struct grub_term_output second = {
    .name = "deferred-clear-second",
    .prepare = fake_prepare,
    .putchar = fake_putchar,
    .getwh = fake_getwh,
    .getxy = fake_getxy,
    .gotoxy = fake_gotoxy,
    .cls = fake_cls,
    .data = &second_state
  };
  struct grub_term_output first = {
    .next = &second,
    .name = "deferred-clear-first",
    .prepare = fake_prepare,
    .putchar = fake_putchar,
    .getwh = fake_getwh,
    .getxy = fake_getxy,
    .gotoxy = fake_gotoxy,
    .cls = fake_cls,
    .data = &first_state
  };
  char sleep_verbose_option[] = "--verbose";
  char sleep_value[] = "1";
  char echo_no_newline[] = "-n";
  char echo_value[] = "";
  char *sleep_verbose[] = { sleep_verbose_option, sleep_value };
  char *sleep_quiet[] = { sleep_value };
  char *echo_empty[] = { echo_no_newline, echo_value };
  char config_path[] = "(proc)/deferred-clear-silent.cfg";
  char nested_config_path[] = "(proc)/deferred-clear-nested.cfg";
  char *config[] = { config_path };
  char *nested[] = { nested_config_path };

  grub_procfs_register ("deferred-clear-silent.cfg", &silent_config_entry);
  grub_procfs_register ("deferred-clear-nested.cfg", &nested_config_entry);
  grub_dl_load ("configfile");
  grub_term_outputs = &first;

  reset_term (&first, &first_state, 0);
  reset_term (&second, &second_state, 0);
  grub_cls_deferred ();
  run_command ("help", 0, NULL);
  grub_test_assert (first_state.clears == 1,
		    "help did not prepare the first terminal");
  grub_test_assert (first_state.chars_before_clear == 0,
		    "help output was cleared after rendering started");
  grub_test_assert (second_state.clears == 1 && second_state.chars > 0 &&
		    second_state.chars_before_clear == 0,
		    "help output was cleared late on the second terminal");

  reset_term (&first, &first_state, 0);
  reset_term (&second, &second_state, 1);
  silent_config_reads = 0;
  run_command ("configfile", ARRAY_SIZE (config), config);
  grub_test_assert (silent_config_reads == 1,
		    "configfile did not read its target configuration");
  grub_test_assert (first_state.clears == 0 && first_state.chars == 0 &&
		    (first.flags & GRUB_TERM_CLEAR_PENDING),
		    "silent configfile cleared the untouched terminal");
  grub_test_assert (second_state.clears == 1 && second_state.chars == 0,
		    "silent configfile did not clear the active terminal");
  grub_xnputs ("visible", sizeof ("visible") - 1);
  grub_test_assert (first_state.clears == 1 &&
		    first_state.chars_before_clear == 0 &&
		    first_state.chars == sizeof ("visible") - 1,
		    "configfile clear did not precede later output");

  reset_term (&first, &first_state, 0);
  reset_term (&second, &second_state, 0);
  silent_config_reads = 0;
  nested_config_reads = 0;
  run_command ("configfile", ARRAY_SIZE (nested), nested);
  grub_test_assert (nested_config_reads == 1 && silent_config_reads == 1,
		    "nested configfile redirect did not read both configurations");
  grub_test_assert (first_state.clears == 0 && first_state.chars == 0 &&
		    (first.flags & GRUB_TERM_CLEAR_PENDING),
		    "nested silent configfile cleared the untouched terminal");

  reset_term (&first, &first_state, 0);
  reset_term (&second, &second_state, 0);
  grub_cls_deferred ();
  grub_xnputs ("direct", sizeof ("direct") - 1);
  grub_printf (" formatted\n");
  grub_test_assert (first_state.clears == 1 &&
		    first_state.chars_before_clear == 0 &&
		    first_state.chars > sizeof ("direct") - 1,
		    "formatted output erased direct output");

  reset_term (&first, &first_state, 0);
  reset_term (&second, &second_state, 0);
  grub_cls_deferred ();
  run_command ("sleep", ARRAY_SIZE (sleep_verbose), sleep_verbose);
  grub_test_assert (first_state.clears == 1 &&
		    first_state.chars_before_clear == 0,
		    "verbose sleep prepared the display too late");
  grub_test_assert (!first_state.gotoxy_changed,
		    "verbose sleep restored different cursor positions");
  grub_test_assert (first_state.have_gotoxy &&
		    first_state.first_gotoxy.x == 0 &&
		    first_state.first_gotoxy.y == 0 &&
		    second_state.have_gotoxy &&
		    second_state.first_gotoxy.x == 0 &&
		    second_state.first_gotoxy.y == 0,
		    "verbose sleep saved its cursor position before preparation");

  reset_term (&first, &first_state, 0);
  reset_term (&second, &second_state, 0);
  grub_cls_deferred ();
  run_command ("sleep", ARRAY_SIZE (sleep_quiet), sleep_quiet);
  grub_test_assert (first_state.clears == 0 &&
		    (first.flags & GRUB_TERM_CLEAR_PENDING),
		    "non-verbose sleep prepared the display");
  run_command ("echo", ARRAY_SIZE (echo_empty), echo_empty);
  grub_test_assert (first_state.clears == 0 && first_state.chars == 0,
		    "empty echo prepared the display (%u clears, %u chars)",
		    first_state.clears, first_state.chars);

  reset_term (&first, &first_state, 0);
  reset_term (&second, &second_state, 1);
  grub_cls_deferred ();
  grub_test_assert (first_state.clears == 0 &&
		    (first.flags & GRUB_TERM_CLEAR_PENDING),
		    "inactive terminal was cleared immediately");
  grub_test_assert (second_state.clears == 1,
		    "active terminal was not cleared immediately");
  grub_xnputs ("visible", sizeof ("visible") - 1);
  grub_test_assert (first_state.clears == 1 && second_state.clears == 1,
		    "multiple terminals were not prepared independently");

  reset_term (&first, &first_state, 0);
  reset_term (&second, &second_state, 0);
  grub_cls_deferred ();
  grub_cls ();
  grub_test_assert (first_state.clears == 1 &&
		    !(first.flags & GRUB_TERM_CLEAR_PENDING),
		    "explicit clear did not replace the deferred clear");

  grub_procfs_unregister (&nested_config_entry);
  grub_procfs_unregister (&silent_config_entry);
  grub_term_outputs = saved_outputs;
}

GRUB_FUNCTIONAL_TEST (deferred_clear_test, deferred_clear_test);
