/* parser.c - the part of the parser that can return partial tokens */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2005,2007,2009,2021  Free Software Foundation, Inc.
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

#include <grub/parser.h>
#include <grub/env.h>
#include <grub/misc.h>
#include <grub/mm.h>


/* All the possible state transitions on the command line.  If a
   transition can not be found, it is assumed that there is no
   transition and keep_value is assumed to be 1.  */
static struct grub_parser_state_transition state_transitions[] = {
  {GRUB_PARSER_STATE_TEXT, GRUB_PARSER_STATE_QUOTE, '\'', 0},
  {GRUB_PARSER_STATE_TEXT, GRUB_PARSER_STATE_DQUOTE, '\"', 0},
  {GRUB_PARSER_STATE_TEXT, GRUB_PARSER_STATE_VAR, '$', 0},
  {GRUB_PARSER_STATE_TEXT, GRUB_PARSER_STATE_ESC, '\\', 0},

  {GRUB_PARSER_STATE_ESC, GRUB_PARSER_STATE_TEXT, 0, 1},

  {GRUB_PARSER_STATE_QUOTE, GRUB_PARSER_STATE_TEXT, '\'', 0},

  {GRUB_PARSER_STATE_DQUOTE, GRUB_PARSER_STATE_TEXT, '\"', 0},
  {GRUB_PARSER_STATE_DQUOTE, GRUB_PARSER_STATE_QVAR, '$', 0},

  {GRUB_PARSER_STATE_VAR, GRUB_PARSER_STATE_VARNAME2, '{', 0},
  {GRUB_PARSER_STATE_VAR, GRUB_PARSER_STATE_VARNAME, 0, 1},
  {GRUB_PARSER_STATE_VARNAME, GRUB_PARSER_STATE_TEXT, ' ', 1},
  {GRUB_PARSER_STATE_VARNAME, GRUB_PARSER_STATE_TEXT, '\t', 1},
  {GRUB_PARSER_STATE_VARNAME2, GRUB_PARSER_STATE_TEXT, '}', 0},

  {GRUB_PARSER_STATE_QVAR, GRUB_PARSER_STATE_QVARNAME2, '{', 0},
  {GRUB_PARSER_STATE_QVAR, GRUB_PARSER_STATE_QVARNAME, 0, 1},
  {GRUB_PARSER_STATE_QVARNAME, GRUB_PARSER_STATE_TEXT, '\"', 0},
  {GRUB_PARSER_STATE_QVARNAME, GRUB_PARSER_STATE_DQUOTE, ' ', 1},
  {GRUB_PARSER_STATE_QVARNAME, GRUB_PARSER_STATE_DQUOTE, '\t', 1},
  {GRUB_PARSER_STATE_QVARNAME2, GRUB_PARSER_STATE_DQUOTE, '}', 0},

  {0, 0, 0, 0}
};


/* Determines the state following STATE, determined by C.  */
grub_parser_state_t
grub_parser_cmdline_state (grub_parser_state_t state, char c, char *result)
{
  struct grub_parser_state_transition *transition;
  struct grub_parser_state_transition default_transition;

  default_transition.to_state = state;
  default_transition.keep_value = 1;

  /* Look for a good translation.  */
  for (transition = state_transitions; transition->from_state; transition++)
    {
      if (transition->from_state != state)
	continue;
      /* An exact match was found, use it.  */
      if (transition->input == c)
	break;

      if (grub_isspace (transition->input) && !grub_isalpha (c)
	  && !grub_isdigit (c) && c != '_')
	break;

      /* A less perfect match was found, use this one if no exact
         match can be found.  */
      if (transition->input == 0)
	break;
    }

  if (!transition->from_state)
    transition = &default_transition;

  if (transition->keep_value)
    *result = c;
  else
    *result = 0;
  return transition->to_state;
}


/* Helper for grub_parser_split_cmdline.  */
static inline int
check_varstate (grub_parser_state_t s)
{
  return (s == GRUB_PARSER_STATE_VARNAME
	  || s == GRUB_PARSER_STATE_VARNAME2
	  || s == GRUB_PARSER_STATE_QVARNAME
	  || s == GRUB_PARSER_STATE_QVARNAME2);
}


static void
add_var (char *varname, char **bp, char **vp,
	 grub_parser_state_t state, grub_parser_state_t newstate)
{
  const char *val;

  /* Check if a variable was being read in and the end of the name
     was reached.  */
  if (!(check_varstate (state) && !check_varstate (newstate)))
    return;

  *((*vp)++) = '\0';
  val = grub_env_get (varname);
  *vp = varname;
  if (!val)
    return;

  /* Insert the contents of the variable in the buffer.  */
  for (; *val; val++)
    *((*bp)++) = *val;
}

static void
terminate_arg (char *buffer, char **bp, int *argc)
{
  if (*bp != buffer && *((*bp) - 1) != '\0')
    {
      *((*bp)++) = '\0';
      (*argc)++;
    }
}

static grub_err_t
process_char (char c, char *buffer, char **bp, char *varname, char **vp,
	      grub_parser_state_t state, int *argc,
	      grub_parser_state_t *newstate)
{
  char use;

  *newstate = grub_parser_cmdline_state (state, c, &use);

  /*
   * If a variable was being processed and this character does
   * not describe the variable anymore, write the variable to
   * the buffer.
   */
  add_var (varname, bp, vp, state, *newstate);

  if (check_varstate (*newstate))
    {
      if (use)
	*((*vp)++) = use;
    }
  else if (*newstate == GRUB_PARSER_STATE_TEXT &&
	   state != GRUB_PARSER_STATE_ESC && grub_isspace (use))
    {
      /*
       * Don't add more than one argument if multiple
       * spaces are used.
       */
      terminate_arg (buffer, bp, argc);
    }
  else if (use)
    *((*bp)++) = use;

  return GRUB_ERR_NONE;
}

grub_err_t
grub_parser_split_cmdline (const char *cmdline,
			   grub_reader_getline_t getline, void *getline_data,
			   int *argc, char ***argv)
{
  grub_parser_state_t state = GRUB_PARSER_STATE_TEXT;
  /* XXX: Fixed size buffer, perhaps this buffer should be dynamically
     allocated.  */
  char buffer[1024];
  char *bp = buffer;
  char *rd = (char *) cmdline;
  char *rp = rd;
  char varname[200];
  char *vp = varname;
  char *args;
  int i;

  *argc = 0;
  *argv = NULL;
  do
    {
      if (rp == NULL || *rp == '\0')
	{
	  if (rd != cmdline)
	    {
	      grub_free (rd);
	      rd = rp = NULL;
	    }
	  if (getline)
	    {
	      getline (&rd, 1, getline_data);
	      rp = rd;
	    }
	  else
	    break;
	}

      if (!rd)
	break;

      for (; *rp != '\0'; rp++)
	{
	  grub_parser_state_t newstate;

	  if (process_char (*rp, buffer, &bp, varname, &vp, state, argc,
			    &newstate) != GRUB_ERR_NONE)
	    goto fail;

	  state = newstate;
	}
    }
  while (state != GRUB_PARSER_STATE_TEXT && !check_varstate (state));

  /* A special case for when the last character was part of a
     variable.  */
  add_var (varname, &bp, &vp, state, GRUB_PARSER_STATE_TEXT);

  /* Ensure that the last argument is terminated. */
  terminate_arg (buffer, &bp, argc);

  /* If there are no args, then we're done. */
  if (!*argc)
    {
      grub_errno = GRUB_ERR_NONE;
      goto out;
    }

  /* Reserve memory for the return values.  */
  args = grub_malloc (bp - buffer);
  if (!args)
    goto fail;
  grub_memcpy (args, buffer, bp - buffer);

  *argv = grub_calloc (*argc + 1, sizeof (char *));
  if (!*argv)
    goto fail;

  /* The arguments are separated with 0's, setup argv so it points to
     the right values.  */
  bp = args;
  for (i = 0; i < *argc; i++)
    {
      (*argv)[i] = bp;
      while (*bp)
	bp++;
      bp++;
    }

  grub_errno = GRUB_ERR_NONE;

 out:
  if (rd != cmdline)
    grub_free (rd);

  return grub_errno;

 fail:
  grub_free (*argv);
  grub_free (args);
  goto out;
}

/* Helper for grub_parser_execute.  */
static grub_err_t
grub_parser_execute_getline (char **line, int cont __attribute__ ((unused)),
			     void *data)
{
  char **source = data;
  char *p;

  if (!*source)
    {
      *line = 0;
      return 0;
    }

  p = grub_strchr (*source, '\n');

  if (p)
    *line = grub_strndup (*source, p - *source);
  else
    *line = grub_strdup (*source);
  *source = p ? p + 1 : 0;
  return 0;
}

grub_err_t
grub_parser_execute (char *source)
{
  while (source)
    {
      char *line;

      grub_parser_execute_getline (&line, 0, &source);
      grub_rescue_parse_line (line, grub_parser_execute_getline, &source);
      grub_free (line);
      grub_print_error ();
    }

  return grub_errno;
}
