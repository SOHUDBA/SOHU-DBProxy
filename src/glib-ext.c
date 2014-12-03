/* $%BEGINLICENSE%$
 Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; version 2 of the
 License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 02110-1301  USA

 $%ENDLICENSE%$ */
 

#include <glib.h>

#include "glib-ext.h"
#include "sys-pedantic.h"
#include <string.h>

#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

/** @file
 * helper functions for common glib operations
 *
 * - g_list_string_free()
 */

#define C(x) x, sizeof(x) - 1
#define S(x) x->str, x->len



#define TRANSLATE(group, str) (((group)->translate_func ? (* (group)->translate_func) ((str), (group)->translate_data) : (str)))

#define NO_ARG(entry) ((entry)->arg == G_OPTION_ARG_NONE ||       \
                       ((entry)->arg == G_OPTION_ARG_CALLBACK &&  \
                        ((entry)->flags & G_OPTION_FLAG_NO_ARG)))

#define OPTIONAL_ARG(entry) ((entry)->arg == G_OPTION_ARG_CALLBACK &&  \
                       (entry)->flags & G_OPTION_FLAG_OPTIONAL_ARG)

typedef struct
{
  GOptionArg arg_type;
  gpointer arg_data;
  union
  {
    gboolean bool;
    gint integer;
    gchar *str;
    gchar **array;
    gdouble dbl;
    gint64 int64;
  } prev;
  union
  {
    gchar *str;
    struct
    {
      gint len;
      gchar **data;
    } array;
  } allocated;
} Change;

typedef struct
{
  gchar **ptr;
  gchar *value;
} PendingNull;

struct _GOptionContext
{
  GList           *groups;

  gchar           *parameter_string;
  gchar           *summary;
  gchar           *description;

  GTranslateFunc   translate_func;
  GDestroyNotify   translate_notify;
  gpointer         translate_data;

  guint            help_enabled   : 1;
  guint            ignore_unknown : 1;

  GOptionGroup    *main_group;

  /* We keep a list of change so we can revert them */
  GList           *changes;

  /* We also keep track of all argv elements
   * that should be NULLed or modified.
   */
  GList           *pending_nulls;
};

struct _GOptionGroup
{
  gchar           *name;
  gchar           *description;
  gchar           *help_description;

  GDestroyNotify   destroy_notify;
  gpointer         user_data;

  GTranslateFunc   translate_func;
  GDestroyNotify   translate_notify;
  gpointer         translate_data;

  GOptionEntry    *entries;
  gint             n_entries;

  GOptionParseFunc pre_parse_func;
  GOptionParseFunc post_parse_func;
  GOptionErrorFunc error_func;
};

static void free_changes_list (GOptionContext *context,
                               gboolean        revert);
static void free_pending_nulls (GOptionContext *context,
                                gboolean        perform_nulls);

static gboolean
context_has_h_entry (GOptionContext *context)
{
  gint i;
  GList *list;

  if (context->main_group)
    {
      for (i = 0; i < context->main_group->n_entries; i++)
        {
          if (context->main_group->entries[i].short_name == 'h')
            return TRUE;
        }
    }

  for (list = context->groups; list != NULL; list = g_list_next (list))
    {
     GOptionGroup *group;

      group = (GOptionGroup*)list->data;
      for (i = 0; i < group->n_entries; i++)
        {
          if (group->entries[i].short_name == 'h')
            return TRUE;
        }
    }
  return FALSE;
}

G_GNUC_NORETURN
static void
print_help (GOptionContext *context,
            gboolean        main_help,
            GOptionGroup   *group)
{
  gchar *help;

  help = g_option_context_get_help (context, main_help, group);
  g_print ("%s", help);
  g_free (help);

  exit (0);
}

static gboolean
parse_int (const gchar *arg_name,
           const gchar *arg,
           gint        *result,
           GError     **error)
{
  gchar *end;
  glong tmp;

  errno = 0;
  tmp = strtol (arg, &end, 0);

  if (*arg == '\0' || *end != '\0')
    {
      g_set_error (error,
                   G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                   ("Cannot parse integer value '%s' for %s"),
                   arg, arg_name);
      return FALSE;
    }

  *result = tmp;
  if (*result != tmp || errno == ERANGE)
    {
      g_set_error (error,
                   G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                   ("Integer value '%s' for %s out of range"),
                   arg, arg_name);
      return FALSE;
    }

  return TRUE;
}


static gboolean
parse_double (const gchar *arg_name,
           const gchar *arg,
           gdouble        *result,
           GError     **error)
{
  gchar *end;
  gdouble tmp;

  errno = 0;
  tmp = g_strtod (arg, &end);

  if (*arg == '\0' || *end != '\0')
    {
      g_set_error (error,
                   G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                   ("Cannot parse double value '%s' for %s"),
                   arg, arg_name);
      return FALSE;
    }
  if (errno == ERANGE)
    {
      g_set_error (error,
                   G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                   ("Double value '%s' for %s out of range"),
                   arg, arg_name);
      return FALSE;
    }

  *result = tmp;

  return TRUE;
}


static gboolean
parse_int64 (const gchar *arg_name,
             const gchar *arg,
             gint64      *result,
             GError     **error)
{
  gchar *end;
  gint64 tmp;

  errno = 0;
  tmp = g_ascii_strtoll (arg, &end, 0);

  if (*arg == '\0' || *end != '\0')
    {
      g_set_error (error,
                   G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                   ("Cannot parse integer value '%s' for %s"),
                   arg, arg_name);
      return FALSE;
    }
  if (errno == ERANGE)
    {
      g_set_error (error,
                   G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                   ("Integer value '%s' for %s out of range"),
                   arg, arg_name);
      return FALSE;
    }

  *result = tmp;

  return TRUE;
}


static Change *
get_change (GOptionContext *context,
            GOptionArg      arg_type,
            gpointer        arg_data)
{
  GList *list;
  Change *change = NULL;

  for (list = context->changes; list != NULL; list = list->next)
    {
      change = list->data;

      if (change->arg_data == arg_data)
        goto found;
    }

  change = g_new0 (Change, 1);
  change->arg_type = arg_type;
  change->arg_data = arg_data;

  context->changes = g_list_prepend (context->changes, change);

 found:

  return change;
}

static void
add_pending_null (GOptionContext *context,
                  gchar         **ptr,
                  gchar          *value)
{
  PendingNull *n;

  n = g_new0 (PendingNull, 1);
  n->ptr = ptr;
  n->value = value;

  context->pending_nulls = g_list_prepend (context->pending_nulls, n);
}

static gboolean
parse_arg (GOptionContext *context,
           GOptionGroup   *group,
           GOptionEntry   *entry,
           const gchar    *value,
           const gchar    *option_name,
           GError        **error)

{
  Change *change;

  g_assert (value || OPTIONAL_ARG (entry) || NO_ARG (entry));

  switch (entry->arg)
    {
    case G_OPTION_ARG_NONE:
      {
        change = get_change (context, G_OPTION_ARG_NONE,
                             entry->arg_data);

        *(gboolean *)entry->arg_data = !(entry->flags & G_OPTION_FLAG_REVERSE);
        break;
      }
    case G_OPTION_ARG_STRING:
      {
        gchar *data;

        data = g_locale_to_utf8 (value, -1, NULL, NULL, error);

        if (!data)
          return FALSE;

        change = get_change (context, G_OPTION_ARG_STRING,
                             entry->arg_data);
        g_free (change->allocated.str);

        change->prev.str = *(gchar **)entry->arg_data;
        change->allocated.str = data;

        *(gchar **)entry->arg_data = data;
        break;
      }
    case G_OPTION_ARG_STRING_ARRAY:
      {
        gchar *data;

        data = g_locale_to_utf8 (value, -1, NULL, NULL, error);

        if (!data)
          return FALSE;

        change = get_change (context, G_OPTION_ARG_STRING_ARRAY,
                             entry->arg_data);

        if (change->allocated.array.len == 0)
          {
            change->prev.array = *(gchar ***)entry->arg_data;
            change->allocated.array.data = g_new (gchar *, 2);
          }
        else
          change->allocated.array.data =
            g_renew (gchar *, change->allocated.array.data,
                     change->allocated.array.len + 2);

        change->allocated.array.data[change->allocated.array.len] = data;
        change->allocated.array.data[change->allocated.array.len + 1] = NULL;

        change->allocated.array.len ++;

        *(gchar ***)entry->arg_data = change->allocated.array.data;

        break;
      }

    case G_OPTION_ARG_FILENAME:
      {
        gchar *data;

#ifdef G_OS_WIN32
        data = g_locale_to_utf8 (value, -1, NULL, NULL, error);

        if (!data)
          return FALSE;
#else
        data = g_strdup (value);
#endif
        change = get_change (context, G_OPTION_ARG_FILENAME,
                             entry->arg_data);
        g_free (change->allocated.str);

        change->prev.str = *(gchar **)entry->arg_data;
        change->allocated.str = data;

        *(gchar **)entry->arg_data = data;
        break;
      }

    case G_OPTION_ARG_FILENAME_ARRAY:
      {
        gchar *data;

#ifdef G_OS_WIN32
        data = g_locale_to_utf8 (value, -1, NULL, NULL, error);

        if (!data)
          return FALSE;
#else
        data = g_strdup (value);
#endif
        change = get_change (context, G_OPTION_ARG_STRING_ARRAY,
                             entry->arg_data);

        if (change->allocated.array.len == 0)
          {
            change->prev.array = *(gchar ***)entry->arg_data;
            change->allocated.array.data = g_new (gchar *, 2);
          }
        else
          change->allocated.array.data =
            g_renew (gchar *, change->allocated.array.data,
                     change->allocated.array.len + 2);

        change->allocated.array.data[change->allocated.array.len] = data;
        change->allocated.array.data[change->allocated.array.len + 1] = NULL;

        change->allocated.array.len ++;

        *(gchar ***)entry->arg_data = change->allocated.array.data;

        break;
      }

    case G_OPTION_ARG_INT:
      {
        gint data;

        if (!parse_int (option_name, value,
                        &data,
                        error))
          return FALSE;

        change = get_change (context, G_OPTION_ARG_INT,
                             entry->arg_data);
        change->prev.integer = *(gint *)entry->arg_data;
        *(gint *)entry->arg_data = data;
        break;
      }
    case G_OPTION_ARG_CALLBACK:
      {
        gchar *data;
        gboolean retval;

        if (!value && entry->flags & G_OPTION_FLAG_OPTIONAL_ARG)
          data = NULL;
        else if (entry->flags & G_OPTION_FLAG_NO_ARG)
          data = NULL;
        else if (entry->flags & G_OPTION_FLAG_FILENAME)
          {
#ifdef G_OS_WIN32
            data = g_locale_to_utf8 (value, -1, NULL, NULL, error);
#else
            data = g_strdup (value);
#endif
          }
        else
          data = g_locale_to_utf8 (value, -1, NULL, NULL, error);

        if (!(entry->flags & (G_OPTION_FLAG_NO_ARG|G_OPTION_FLAG_OPTIONAL_ARG)) &&
            !data)
          return FALSE;

        retval = (* (GOptionArgFunc) entry->arg_data) (option_name, data, group->user_data, error);

        if (!retval && error != NULL && *error == NULL)
          g_set_error (error,
                       G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
                       ("Error parsing option %s"), option_name);

        g_free (data);

        return retval;

        break;
      }
    case G_OPTION_ARG_DOUBLE:
      {
        gdouble data;

        if (!parse_double (option_name, value,
                        &data,
                        error))
          {
            return FALSE;
          }

        change = get_change (context, G_OPTION_ARG_DOUBLE,
                             entry->arg_data);
        change->prev.dbl = *(gdouble *)entry->arg_data;
        *(gdouble *)entry->arg_data = data;
        break;
      }
    case G_OPTION_ARG_INT64:
      {
        gint64 data;

        if (!parse_int64 (option_name, value,
                         &data,
                         error))
          {
            return FALSE;
          }

        change = get_change (context, G_OPTION_ARG_INT64,
                             entry->arg_data);
        change->prev.int64 = *(gint64 *)entry->arg_data;
        *(gint64 *)entry->arg_data = data;
        break;
      }
    default:
      g_assert_not_reached ();
    }

  return TRUE;
}

static gboolean
parse_short_option (GOptionContext *context,
                    GOptionGroup   *group,
                    gint            idx,
                    gint           *new_idx,
                    gchar           arg,
                    gint           *argc,
                    gchar        ***argv,
                    GError        **error,
                    gboolean       *parsed)
{
  gint j;

  for (j = 0; j < group->n_entries; j++)
    {
      if (arg == group->entries[j].short_name)
        {
          gchar *option_name;
          gchar *value = NULL;

          option_name = g_strdup_printf ("-%c", group->entries[j].short_name);

          if (NO_ARG (&group->entries[j]))
            value = NULL;
          else
            {
              if (*new_idx > idx)
                {
                  g_set_error (error,
                               G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
                               ("Error parsing option %s"), option_name);
                  g_free (option_name);
                  return FALSE;
                }

              if (idx < *argc - 1)
                {
                  if (!OPTIONAL_ARG (&group->entries[j]))
                    {
                      value = (*argv)[idx + 1];
                      add_pending_null (context, &((*argv)[idx + 1]), NULL);
                      *new_idx = idx + 1;
                    }
                  else
                    {
                      if ((*argv)[idx + 1][0] == '-')
                        value = NULL;
                      else
                        {
                          value = (*argv)[idx + 1];
                          add_pending_null (context, &((*argv)[idx + 1]), NULL);
                          *new_idx = idx + 1;
                        }
                    }
                }
              else if (idx >= *argc - 1 && OPTIONAL_ARG (&group->entries[j]))
                value = NULL;
              else
                {
                  g_set_error (error,
                               G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                               ("Missing argument for %s"), option_name);
                  g_free (option_name);
                  return FALSE;
                }
            }

          if (!parse_arg (context, group, &group->entries[j],
                          value, option_name, error))
            {
              g_free (option_name);
              return FALSE;
            }

          g_free (option_name);
          *parsed = TRUE;
        }
    }

  return TRUE;
}

static gboolean
parse_long_option (GOptionContext *context,
                   GOptionGroup   *group,
                   gint           *idx,
                   gchar          *arg,
                   gboolean        aliased,
                   gint           *argc,
                   gchar        ***argv,
                   GError        **error,
                   gboolean       *parsed)
{
  gint j;

  for (j = 0; j < group->n_entries; j++)
    {
      if (*idx >= *argc)
        return TRUE;

      if (aliased && (group->entries[j].flags & G_OPTION_FLAG_NOALIAS))
        continue;

      if (NO_ARG (&group->entries[j]) &&
          strcmp (arg, group->entries[j].long_name) == 0)
        {
          gchar *option_name;
          gboolean retval;

          option_name = g_strconcat ("--", group->entries[j].long_name, NULL);
          retval = parse_arg (context, group, &group->entries[j],
                              NULL, option_name, error);
          g_free (option_name);

          add_pending_null (context, &((*argv)[*idx]), NULL);
          *parsed = TRUE;

          return retval;
        }
      else
        {
          gint len = strlen (group->entries[j].long_name);

          if (strncmp (arg, group->entries[j].long_name, len) == 0 &&
              (arg[len] == '=' || arg[len] == 0))
            {
              gchar *value = NULL;
              gchar *option_name;

              add_pending_null (context, &((*argv)[*idx]), NULL);
              option_name = g_strconcat ("--", group->entries[j].long_name, NULL);

              if (arg[len] == '=')
                value = arg + len + 1;
              else if (*idx < *argc - 1)
                {
                  if (!OPTIONAL_ARG (&group->entries[j]))
                    {
                      value = (*argv)[*idx + 1];
                      add_pending_null (context, &((*argv)[*idx + 1]), NULL);
                      (*idx)++;
                    }
                  else
                    {
                      if ((*argv)[*idx + 1][0] == '-')
                        {
                          gboolean retval;
                          retval = parse_arg (context, group, &group->entries[j],
                                              NULL, option_name, error);
                          *parsed = TRUE;
                          g_free (option_name);
                          return retval;
                        }
                      else
                        {
                          value = (*argv)[*idx + 1];
                          add_pending_null (context, &((*argv)[*idx + 1]), NULL);
                          (*idx)++;
                        }
                    }
                }
              else if (*idx >= *argc - 1 && OPTIONAL_ARG (&group->entries[j]))
                {
                    gboolean retval;
                    retval = parse_arg (context, group, &group->entries[j],
                                        NULL, option_name, error);
                    *parsed = TRUE;
                    g_free (option_name);
                    return retval;
                }
              else
                {
                  g_set_error (error,
                               G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                               ("Missing argument for %s"), option_name);
                  g_free (option_name);
                  return FALSE;
                }

              if (!parse_arg (context, group, &group->entries[j],
                              value, option_name, error))
                {
                  g_free (option_name);
                  return FALSE;
                }

              g_free (option_name);
              *parsed = TRUE;
            }
        }
    }

  return TRUE;
}

static gboolean
parse_remaining_arg (GOptionContext *context,
                     GOptionGroup   *group,
                     gint           *idx,
                     gint           *argc,
                     gchar        ***argv,
                     GError        **error,
                     gboolean       *parsed)
{
  gint j;

  for (j = 0; j < group->n_entries; j++)
    {
      if (*idx >= *argc)
        return TRUE;

      if (group->entries[j].long_name[0])
        continue;

      g_return_val_if_fail (group->entries[j].arg == G_OPTION_ARG_CALLBACK ||
                            group->entries[j].arg == G_OPTION_ARG_STRING_ARRAY ||
                            group->entries[j].arg == G_OPTION_ARG_FILENAME_ARRAY, FALSE);

      add_pending_null (context, &((*argv)[*idx]), NULL);

      if (!parse_arg (context, group, &group->entries[j], (*argv)[*idx], "", error))
        return FALSE;

      *parsed = TRUE;
      return TRUE;
    }

  return TRUE;
}

static void
free_changes_list (GOptionContext *context,
                   gboolean        revert)
{
  GList *list;

  for (list = context->changes; list != NULL; list = list->next)
    {
      Change *change = list->data;

      if (revert)
        {
          switch (change->arg_type)
            {
            case G_OPTION_ARG_NONE:
              *(gboolean *)change->arg_data = change->prev.bool;
              break;
            case G_OPTION_ARG_INT:
              *(gint *)change->arg_data = change->prev.integer;
              break;
            case G_OPTION_ARG_STRING:
            case G_OPTION_ARG_FILENAME:
              g_free (change->allocated.str);
              *(gchar **)change->arg_data = change->prev.str;
              break;
            case G_OPTION_ARG_STRING_ARRAY:
            case G_OPTION_ARG_FILENAME_ARRAY:
              g_strfreev (change->allocated.array.data);
              *(gchar ***)change->arg_data = change->prev.array;
              break;
            case G_OPTION_ARG_DOUBLE:
              *(gdouble *)change->arg_data = change->prev.dbl;
              break;
            case G_OPTION_ARG_INT64:
              *(gint64 *)change->arg_data = change->prev.int64;
              break;
            default:
              g_assert_not_reached ();
            }
        }

      g_free (change);
    }

  g_list_free (context->changes);
  context->changes = NULL;
}


/* Use a platform-specific mechanism to look up the first argument to
 * the current process.
 * Note if you implement this for other platforms, also add it to
 * tests/option-argv0.c
 */
static char *
platform_get_argv0 (void)
{
#if defined __linux
  char *cmdline;
  char *base_arg0;
  gsize len;

  if (!g_file_get_contents ("/proc/self/cmdline",
			    &cmdline,
			    &len,
			    NULL))
    return NULL;
  /* Sanity check for a NUL terminator. */
  if (!memchr (cmdline, 0, len))
    return NULL;
  /* We could just return cmdline, but I think it's better
   * to hold on to a smaller malloc block; the arguments
   * could be large.
   */
  base_arg0 = g_path_get_basename (cmdline);
  g_free (cmdline);
  return base_arg0;
#elif defined __OpenBSD__
  char **cmdline = NULL;
  char *base_arg0;
  gsize len = PATH_MAX;

  int mib[] = { CTL_KERN, KERN_PROC_ARGS, getpid(), KERN_PROC_ARGV };

  cmdline = (char **) realloc (cmdline, len);

  if (sysctl (mib, G_N_ELEMENTS (mib), cmdline, &len, NULL, 0) == -1)
    {
      g_free (cmdline);
      return NULL;
    }

  /* We could just return cmdline, but I think it's better
   * to hold on to a smaller malloc block; the arguments
   * could be large.
   */
  base_arg0 = g_path_get_basename (*cmdline);
  g_free (cmdline);
  return base_arg0;
#endif

  return NULL;
}

static void
free_pending_nulls (GOptionContext *context,
                    gboolean        UNUSED_PARAM(perform_nulls))
{
  GList *list;

  for (list = context->pending_nulls; list != NULL; list = list->next)
    {
      PendingNull *n = list->data;

#if 0
        {
          if (n->value)
            {
              /* Copy back the short options */
              *(n->ptr)[0] = '-';
              strcpy (*n->ptr + 1, n->value);
            }
          else
            *n->ptr = NULL;
        }
#endif
      n->ptr = NULL;
      g_free (n->value);
      g_free (n);
    }

  g_list_free (context->pending_nulls);
  context->pending_nulls = NULL;
}

gboolean
my_g_option_context_parse (GOptionContext   *context,
                        gint             *argc,
                        gchar          ***argv,
                        GError          **error)
{
  gint i, j, k;
  GList *list;

  /* Set program name */
  if (!g_get_prgname())
    {
      gchar *prgname;

      if (argc && argv && *argc)
	prgname = g_path_get_basename ((*argv)[0]);
      else
	prgname = platform_get_argv0 ();

      if (prgname)
	g_set_prgname (prgname);
      else
	g_set_prgname ("<unknown>");

      g_free (prgname);
    }

  /* Call pre-parse hooks */
  list = context->groups;
  while (list)
    {
      GOptionGroup *group = list->data;

      if (group->pre_parse_func)
        {
          if (!(* group->pre_parse_func) (context, group,
                                          group->user_data, error))
            goto fail;
        }

      list = list->next;
    }

  if (context->main_group && context->main_group->pre_parse_func)
    {
      if (!(* context->main_group->pre_parse_func) (context, context->main_group,
                                                    context->main_group->user_data, error))
        goto fail;
    }

  if (argc && argv)
    {
      gboolean stop_parsing = FALSE;
      gboolean has_unknown = FALSE;
      gint separator_pos = 0;

      for (i = 1; i < *argc; i++)
        {
          gchar *arg, *dash;
          gboolean parsed = FALSE;

          if ((*argv)[i][0] == '-' && (*argv)[i][1] != '\0' && !stop_parsing)
            {
              if ((*argv)[i][1] == '-')
                {
                  /* -- option */

                  arg = (*argv)[i] + 2;

                  /* '--' terminates list of arguments */
                  if (*arg == 0)
                    {
                      separator_pos = i;
                      stop_parsing = TRUE;
                      continue;
                    }

                  /* Handle help options */
                  if (context->help_enabled)
                    {
                      if (strcmp (arg, "help") == 0)
                        print_help (context, TRUE, NULL);
                      else if (strcmp (arg, "help-all") == 0)
                        print_help (context, FALSE, NULL);
                      else if (strncmp (arg, "help-", 5) == 0)
                        {
                          list = context->groups;

                          while (list)
                            {
                              GOptionGroup *group = list->data;

                              if (strcmp (arg + 5, group->name) == 0)
                                print_help (context, FALSE, group);

                              list = list->next;
                            }
                        }
                    }

                  if (context->main_group &&
                      !parse_long_option (context, context->main_group, &i, arg,
                                          FALSE, argc, argv, error, &parsed))
                    goto fail;

                  if (parsed)
                    continue;

                  /* Try the groups */
                  list = context->groups;
                  while (list)
                    {
                      GOptionGroup *group = list->data;

                      if (!parse_long_option (context, group, &i, arg,
                                              FALSE, argc, argv, error, &parsed))
                        goto fail;

                      if (parsed)
                        break;

                      list = list->next;
                    }

                  if (parsed)
                    continue;

                  /* Now look for --<group>-<option> */
                  dash = strchr (arg, '-');
                  if (dash)
                    {
                      /* Try the groups */
                      list = context->groups;
                      while (list)
                        {
                          GOptionGroup *group = list->data;

                          if (strncmp (group->name, arg, dash - arg) == 0)
                            {
                              if (!parse_long_option (context, group, &i, dash + 1,
                                                      TRUE, argc, argv, error, &parsed))
                                goto fail;

                              if (parsed)
                                break;
                            }

                          list = list->next;
                        }
                    }

                  if (context->ignore_unknown)
                    continue;
                }
              else
                { /* short option */
                  gint new_i = i, arg_length;
                  gboolean *nulled_out = NULL;
                  gboolean has_h_entry = context_has_h_entry (context);
                  arg = (*argv)[i] + 1;
                  arg_length = strlen (arg);
                  nulled_out = g_newa (gboolean, arg_length);
                  memset (nulled_out, 0, arg_length * sizeof (gboolean));
                  for (j = 0; j < arg_length; j++)
                    {
                      if (context->help_enabled && (arg[j] == '?' ||
                        (arg[j] == 'h' && !has_h_entry)))
                        print_help (context, TRUE, NULL);
                      parsed = FALSE;
                      if (context->main_group &&
                          !parse_short_option (context, context->main_group,
                                               i, &new_i, arg[j],
                                               argc, argv, error, &parsed))
                        goto fail;
                      if (!parsed)
                        {
                          /* Try the groups */
                          list = context->groups;
                          while (list)
                            {
                              GOptionGroup *group = list->data;
                              if (!parse_short_option (context, group, i, &new_i, arg[j],
                                                       argc, argv, error, &parsed))
                                goto fail;
                              if (parsed)
                                break;
                              list = list->next;
                            }
                        }

                      if (context->ignore_unknown && parsed)
                        nulled_out[j] = TRUE;
                      else if (context->ignore_unknown)
                        continue;
                      else if (!parsed)
                        break;
                      /* !context->ignore_unknown && parsed */
                    }
                  if (context->ignore_unknown)
                    {
                      gchar *new_arg = NULL;
                      gint arg_index = 0;
                      for (j = 0; j < arg_length; j++)
                        {
                          if (!nulled_out[j])
                            {
                              if (!new_arg)
                                new_arg = g_malloc (arg_length + 1);
                              new_arg[arg_index++] = arg[j];
                            }
                        }
                      if (new_arg)
                        new_arg[arg_index] = '\0';
                      add_pending_null (context, &((*argv)[i]), new_arg);
                    }
                  else if (parsed)
                    {
                      add_pending_null (context, &((*argv)[i]), NULL);
                      i = new_i;
                    }
                }

              if (!parsed)
                has_unknown = TRUE;

              if (!parsed && !context->ignore_unknown)
                {
                  g_set_error (error,
                               G_OPTION_ERROR, G_OPTION_ERROR_UNKNOWN_OPTION,
                                   ("Unknown option %s"), (*argv)[i]);
                  goto fail;
                }
            }
          else
            {
              /* Collect remaining args */
              if (context->main_group &&
                  !parse_remaining_arg (context, context->main_group, &i,
                                        argc, argv, error, &parsed))
                goto fail;

              if (!parsed && (has_unknown || (*argv)[i][0] == '-'))
                separator_pos = 0;
            }
        }

      if (separator_pos > 0)
        add_pending_null (context, &((*argv)[separator_pos]), NULL);

    }

  /* Call post-parse hooks */
  list = context->groups;
  while (list)
    {
      GOptionGroup *group = list->data;

      if (group->post_parse_func)
        {
          if (!(* group->post_parse_func) (context, group,
                                           group->user_data, error))
            goto fail;
        }

      list = list->next;
    }

  if (context->main_group && context->main_group->post_parse_func)
    {
      if (!(* context->main_group->post_parse_func) (context, context->main_group,
                                                     context->main_group->user_data, error))
        goto fail;
    }

  if (argc && argv)
    {
      free_pending_nulls (context, TRUE);

      for (i = 1; i < *argc; i++)
        {
          for (k = i; k < *argc; k++)
            if ((*argv)[k] != NULL)
              break;

          if (k > i)
            {
              k -= i;
              for (j = i + k; j < *argc; j++)
                {
                  (*argv)[j-k] = (*argv)[j];
                  (*argv)[j] = NULL;
                }
              *argc -= k;
            }
        }
    }

  return TRUE;

 fail:

  /* Call error hooks */
  list = context->groups;
  while (list)
    {
      GOptionGroup *group = list->data;

      if (group->error_func)
        (* group->error_func) (context, group,
                               group->user_data, error);

      list = list->next;
    }

  if (context->main_group && context->main_group->error_func)
    (* context->main_group->error_func) (context, context->main_group,
                                         context->main_group->user_data, error);

  free_changes_list (context, TRUE);
  free_pending_nulls (context, FALSE);

  return FALSE;
}
/**
 * free function for GStrings in a GList
 */
void g_list_string_free(gpointer data, gpointer UNUSED_PARAM(user_data)) {
	g_string_free(data, TRUE);
}

/**
 * free function for GStrings in a GHashTable
 */
void g_hash_table_string_free(gpointer data) {
	g_string_free(data, TRUE);
}

/**
 * added by jinxuan hou, 2013/04/10
 * free function for gint in a GHashTable
 */
void g_hash_table_int_free(gpointer data) {
	g_free(data);
}

void g_hash_table_pool_config_free(gpointer data) {
	g_free(data);
}

void g_hash_table_pool_status_free(gpointer data) {
	g_free(data);
}

/**
 * hash function for GString
 */
guint g_hash_table_string_hash(gconstpointer _key) {
	return g_string_hash(_key);
}

/**
 * compare function for GString
 */
gboolean g_hash_table_string_equal(gconstpointer _a, gconstpointer _b) {
	return g_string_equal(_a, _b);
}

/**
 * true-function for g_hash_table_foreach
 */
gboolean g_hash_table_true(gpointer UNUSED_PARAM(key), gpointer UNUSED_PARAM(value), gpointer UNUSED_PARAM(u)) {
	return TRUE;
}	

gpointer g_hash_table_lookup_const(GHashTable *h, const gchar *name, gsize name_len) {
	GString key;

	key.str = (char *)name; /* we are still const */
	key.len = name_len;

	return g_hash_table_lookup(h, &key);
}

/**
 * hash function for case-insensitive strings 
 */
guint g_istr_hash(gconstpointer v) {
	/* djb2 */
	const unsigned char *p = v;
	unsigned char c;
	guint32 h = 5381;
	
	while ((c = *p++)) {
		h = ((h << 5) + h) + g_ascii_toupper(c);
	}
	
	return h;
}

/**
 * duplicate a GString
 */
GString *g_string_dup(GString *src) {
	GString *dst = g_string_sized_new(src->len);

	g_string_assign(dst, src->str);

	return dst;
}

/**
 * compare two strings (gchar arrays), whose lengths are known
 */
gboolean strleq(const gchar *a, gsize a_len, const gchar *b, gsize b_len) {
	if (a_len != b_len) return FALSE;
	return (0 == memcmp(a, b, a_len));
}

int g_string_get_time(GString *s, GTimeVal *gt) {
	time_t t = gt->tv_sec;

#ifndef HAVE_GMTIME_R
	//static GStaticMutex m = G_STATIC_MUTEX_INIT; /* gmtime() isn't thread-safe */
	static GStaticMutex m = { .mutex = NULL }; /* gmtime() isn't thread-safe */

	g_static_mutex_lock(&m);

	s->len = strftime(s->str, s->allocated_len, "%Y-%m-%dT%H:%M:%S.", gmtime(&(t)));
	
	g_static_mutex_unlock(&m);
#else
	struct tm tm;
	gmtime_r(&(t), &tm);
	s->len = strftime(s->str, s->allocated_len, "%Y-%m-%dT%H:%M:%S.", &tm);
#endif

	/* append microsec + Z */
	g_string_append_printf(s, "%03ldZ", gt->tv_usec / 1000);
	
	return 0;
}

int g_string_get_current_time(GString *s) {
	GTimeVal gt;

	g_get_current_time(&gt);

	return g_string_get_time(s, &gt);
}

/**
 * calculate the difference between two GTimeVal values, in usec
 * positive return value in *tdiff means *told is indeed "earlier" than *tnew,
 * negative return value means the reverse
 * Caller is responsible for passing valid pointers
 */
void ge_gtimeval_diff(GTimeVal *told, GTimeVal *tnew, gint64 *tdiff) {
	*tdiff = (gint64) tnew->tv_sec - told->tv_sec;
	*tdiff *= G_USEC_PER_SEC;
	*tdiff += (gint64) tnew->tv_usec - told->tv_usec;
}

GString * g_string_assign_len(GString *s, const char *str, gsize str_len) {
	g_string_truncate(s, 0);
	return g_string_append_len(s, str, str_len);
}

void g_debug_hexdump(const char *msg, const void *_s, size_t len) {
	GString *hex;
	size_t i;
	const unsigned char *s = _s;
		
       	hex = g_string_new(NULL);

	for (i = 0; i < len; i++) {
		if (i % 16 == 0) {
			g_string_append_printf(hex, "[%04"G_GSIZE_MODIFIER"x]  ", i);
		}
		g_string_append_printf(hex, "%02x", s[i]);

		if ((i + 1) % 16 == 0) {
			size_t j;
			g_string_append_len(hex, C("  "));
			for (j = i - 15; j <= i; j++) {
				g_string_append_c(hex, g_ascii_isprint(s[j]) ? s[j] : '.');
			}
			g_string_append_len(hex, C("\n  "));
		} else {
			g_string_append_c(hex, ' ');
		}
	}

	if (i % 16 != 0) {
		/* fill up the line */
		size_t j;

		for (j = 0; j < 16 - (i % 16); j++) {
			g_string_append_len(hex, C("   "));
		}

		g_string_append_len(hex, C(" "));
		for (j = i - (len % 16); j < i; j++) {
			g_string_append_c(hex, g_ascii_isprint(s[j]) ? s[j] : '.');
		}
	}

	g_debug("(%s) %"G_GSIZE_FORMAT" bytes:\n  %s", 
			msg, 
			len,
			hex->str);

	g_string_free(hex, TRUE);
}

/**
 * compare two GStrings for case-insensitive equality using UTF8
 */
gboolean g_string_equal_ci(const GString *a, const GString *b) {
	char *a_ci, *b_ci;
	gsize a_ci_len, b_ci_len;
	gboolean is_equal = FALSE;

	if (g_string_equal(a, b)) return TRUE;

	a_ci = g_utf8_casefold(S(a));
	a_ci_len = strlen(a_ci);
	
	b_ci = g_utf8_casefold(S(b));
	b_ci_len = strlen(b_ci);

	is_equal = strleq(a_ci, a_ci_len, b_ci, b_ci_len);

	g_free(a_ci);
	g_free(b_ci);

	return is_equal;
}

/**
 * compare two memory records for equality
 */
gboolean g_memeq(const char *a, gsize a_len, const char *b, gsize b_len) {
	if (a_len != b_len) return FALSE;

	return (0 == memcmp(a, b, b_len));
}

/**
 * sohu-inc.com
 * 大小写无关的string的hash函数
 * @param data
 * @return
 */
guint g_hash_table_charset_string_hash(gconstpointer _key) {
	GString *lower_key = g_string_new( ((GString *)_key)->str );
	guint r = 0;
	g_string_ascii_down (lower_key);
	r = g_string_hash(lower_key);
	g_string_free(lower_key, TRUE);
	return (r);
}

/**
 * sohu-inc.com
 * 大小写无关的字符串的对比函数
 * @param data
 * @return
 */
gboolean g_hash_table_charset_string_equal(gconstpointer _a, gconstpointer _b) {
	GString *a = (GString *)_a;
	GString *b = (GString *)_b;
	if (a->len != b->len) {
		return FALSE;
	}
	return (0 == g_ascii_strcasecmp (a->str, b->str));
}

/**
 * sohu-inc.com
 * gstring的replace函数
 * @param mystring src rep
 * @return None
 */
void g_string_myreplace(GString *mystring, const gchar *src, const gchar* rep) {
	gchar *start_pos = mystring->str;
	int start_offset = 0;
	gchar *end_pos = NULL;
	int pos;
	while (NULL != (end_pos = strstr(start_pos, src))) {
		pos = start_offset + end_pos - start_pos;
		g_string_erase(mystring, pos, strlen(src));
		g_string_insert(mystring, pos, rep);		
		start_offset += end_pos -start_pos + strlen(rep);
		start_pos += end_pos - start_pos + strlen(rep);
	}
}


/**
 * http://www.codeproject.com/Articles/1088/Wildcard-string-compare-globbing
 */
gboolean wildcard_string_match1(const gchar *pattern, const gchar *string)
{
	const char *cp = NULL;
	const char *mp = NULL;

	while ( (*string) && (*pattern != '%') )
	{
		if ( (*pattern != *string) && (*pattern != '_') )
		{
			return FALSE;
		}
		pattern++;
		string++;
	}

	while ( *string )
	{
		if ( *pattern == '%' )
		{
			if ( ! *++pattern )
			{
				return TRUE;
			}
			mp = pattern;
			cp = string + 1;

		}
		else if ( (*pattern == *string) || (*pattern == '_') )
		{
			pattern++;
			string++;
		}
		else
		{
			pattern = mp;
			string = cp++;
		}
	}

	while ( *pattern == '%')
	{
		pattern++;
	}

	return !*pattern;
}

/**
 * http://www.drdobbs.com/architecture-and-design/matching-wildcards-an-algorithm/210200888
 */
//This function compares text strings, one of which can have wildcards ('*').
//
gboolean wildcard_string_match(const gchar *pWildText, const gchar *pTameText) {
	static const gboolean bCaseSensitive = FALSE;  // By default, match on 'X' vs 'x'
	static const gchar cAltTerminator = '\0'; // For function names, for example, you can stop at the first '('
	gboolean bMatch = TRUE;
	const gchar * pAfterLastWild = NULL; // The location after the last '*', if we’ve encountered one
	const gchar * pAfterLastTame = NULL; // The location in the tame string, from which we started after last wildcard
	gchar t, w;

	// Walk the text strings one character at a time.
	while (1) {
		t = *pTameText;
		w = *pWildText;

		// How do you match a unique text string?
		if (!t || t == cAltTerminator) {
			// Easy: unique up on it!
			if (!w || w == cAltTerminator) {
				break;                                   // "x" matches "x"
			} else if (w == '%') {
				pWildText++;
				continue;                           // "x*" matches "x" or "xy"
			} else if (pAfterLastTame) {
				if (!(*pAfterLastTame) || *pAfterLastTame == cAltTerminator) {
					bMatch = FALSE;
					break;
				}
				pTameText = pAfterLastTame++;
				pWildText = pAfterLastWild;
				continue;
			}

			bMatch = FALSE;
			break;                                         // "x" doesn't match "xy"
		} else {
			if (!bCaseSensitive) {
				// Lowercase the characters to be compared.
				if (t >= 'A' && t <= 'Z') {
					t += ('a' - 'A');
				}

				if (w >= 'A' && w <= 'Z') {
					w += ('a' - 'A');
				}
			}

			// How do you match a tame text string?
			if (t != w) {
				// The tame way: unique up on it!
				if (w == '%') {
					pAfterLastWild = ++pWildText;
					pAfterLastTame = pTameText;
					w = *pWildText;

					if (!w || w == cAltTerminator) {
						break;                           // "*" matches "x"
					}
					continue;                           // "*y" matches "xy"
				} else if (pAfterLastWild) {
					if (pAfterLastWild != pWildText) {
						pWildText = pAfterLastWild;
						w = *pWildText;

						if (!bCaseSensitive && w >= 'A' && w <= 'Z') {
							w += ('a' - 'A');
						}

						if (t == w) {
							pWildText++;
						}
					}
					pTameText++;
					continue;                       // "*sip*" matches "mississippi"
				} else {
					bMatch = FALSE;
					break;                                  // "x" doesn't match "y"
				}
			}
		}

		pTameText++;
		pWildText++;
	}

	return bMatch;
}



GString *time_us_to_str(guint64 time_us, GString *str) {
	struct tm *tm = NULL;
	time_t t = time_us / 1000000L;
	tm = localtime(&t);
	str->len = strftime(str->str, str->allocated_len, "%Y-%m-%dT%H:%M:%S", tm);
	g_string_append_printf(str, ".%.6ld", (time_us - t * 1000000) );
	return str;
}



/*eof*/
