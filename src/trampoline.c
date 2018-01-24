/*
 *  Copyright (C) 2018 Joseph Benden <joe@benden.us>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define NDEBUG

#include <assert.h>
#include <stdio.h>
#include <errno.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "trampoline.h"

#ifndef MAX_PATH
#define MAX_PATH 16536
#endif

#ifndef EXEEXT
#define EXEEXT ""
#endif

#ifndef AIRCRACK_LIBEXEC_PATH
#define AIRCRACK_LIBEXEC_PATH "/usr/local/libexec/aircrack-ng"
#endif

#ifndef TRAMPOLINE_TARGET
#define TRAMPOLINE_TARGET "aircrack-ng"
#endif

static void
simd_select_best_binary (char * buffer, size_t buffer_remaining, int simd_features)
{
  assert (buffer != NULL);
  assert (buffer_remaining > 0);

  if (simd_features & SIMD_SUPPORTS_AVX2)
  {
    strncat (buffer, TRAMPOLINE_TARGET "--avx2" EXEEXT, buffer_remaining);
  }
  else if (simd_features & SIMD_SUPPORTS_AVX)
  {
    strncat (buffer, TRAMPOLINE_TARGET "--avx" EXEEXT, buffer_remaining);
  }
  else if (simd_features & SIMD_SUPPORTS_SSE2)
  {
    strncat (buffer, TRAMPOLINE_TARGET "--sse2" EXEEXT, buffer_remaining);
  }
  /*
  else if (simd_features & SIMD_SUPPORTS_MMX)
  {
    strncat (buffer, TRAMPOLINE_TARGET "--mmx" EXEEXT, buffer_remaining);
  }
  */
  else if (simd_features & SIMD_SUPPORTS_ASIMD)
  {
    strncat (buffer, TRAMPOLINE_TARGET "--asimd" EXEEXT, buffer_remaining);
  }
  else if (simd_features & SIMD_SUPPORTS_NEON)
  {
    strncat (buffer, TRAMPOLINE_TARGET "--neon" EXEEXT, buffer_remaining);
  }
  else if (simd_features & SIMD_SUPPORTS_POWER8)
  {
    strncat (buffer, TRAMPOLINE_TARGET "--power8" EXEEXT, buffer_remaining);
  }
  else if (simd_features & SIMD_SUPPORTS_ALTIVEC)
  {
    strncat (buffer, TRAMPOLINE_TARGET "--altivec" EXEEXT, buffer_remaining);
  }
  else
  {
    strncat (buffer, TRAMPOLINE_TARGET "--generic" EXEEXT, buffer_remaining);
  }
}

static void
determine_path_envvar (char * binary_path)
{
  assert (binary_path != NULL);

  strncpy (binary_path, "PATH=", MAX_PATH);

  if (getenv ("PATH"))
  {
    strncat (binary_path, getenv ("PATH"), MAX_PATH - strlen(binary_path) - 1);
  }
  else
  {
    strncat (binary_path, "/bin:/usr/bin:/usr/local/bin", MAX_PATH - strlen(binary_path) - 1);
  }
}

static void
initialize_full_path (char * binary_path)
{
  assert (binary_path != NULL);

  strncpy (binary_path, AIRCRACK_LIBEXEC_PATH, MAX_PATH);

  if (getenv ("AIRCRACK_LIBEXEC_PATH"))
  {
    strncpy (binary_path, getenv ("AIRCRACK_LIBEXEC_PATH"), MAX_PATH);
  }

  strncat (binary_path, "/", MAX_PATH - strlen (binary_path) - 1);
}

static int
perform_simd_detection (void)
{
  int result;

  simd_init ();

  result = simd_get_supported_features ();

#ifndef NDEBUG
  (void) printf ("D: simd_features=%d\n", result);
#endif

  simd_destroy ();

  return (result);
}

int
main (int argc, char * argv[])
{
  int rc = 0;
  int simd_features;
  char binary_path[MAX_PATH + 1];
  char path_env[MAX_PATH + 1];
  char ** args = NULL;
  char ** environment = NULL;

  memset (binary_path, 0, MAX_PATH + 1);
  memset (path_env, 0, MAX_PATH + 1);

  initialize_full_path (binary_path);

  simd_features = perform_simd_detection ();

  // select the best binary, based on the CPU features detected
  simd_select_best_binary (binary_path, MAX_PATH - strlen (binary_path) - 1, simd_features);

  // set-up PATH environment variable
  determine_path_envvar (path_env);

  // prepare arguments
  args = calloc (argc + 1, sizeof (char *));
  size_t n_args = 0;

  if (!args)
  {
    (void) fprintf (stderr, "F: Memory allocation failure: %s\n", strerror (errno));
    goto out;
  }

  // add the binary as the first parameter
  args[n_args] = strdup (binary_path);

  if (!args[n_args])
  {
    (void) fprintf (stderr, "F: Memory allocation failure: %s\n", strerror (errno));
    goto out;
  }

  ++n_args;

  // add in all passed parameters
  for (size_t idx = 1; idx < (size_t) argc; ++idx)
  {
    args[n_args] = strdup (argv[idx]);

    if (!args[n_args])
    {
      (void) fprintf (stderr, "F: Memory allocation failure: %s\n", strerror (errno));
      goto out;
    }

    ++n_args;
  }

  // prepare sanitized environment variables
  environment = calloc (2, sizeof (char *));
  size_t n_envs = 0;

  if (!environment)
  {
    (void) fprintf (stderr, "F: Memory allocation failure: %s\n", strerror (errno));
    goto out;
  }

  environment[n_envs] = strdup (path_env);
  if (!environment[n_envs])
  {
    (void) fprintf (stderr, "F: Memory allocation failure: %s\n", strerror (errno));
    goto out;
  }
  ++n_envs;

#ifndef NDEBUG
  (void) printf ("D: Launching %s\n", binary_path);
  for (size_t idx = 0; idx < n_args; ++idx)
  {
    (void) printf ("D: Arg %lu: %s\n", (unsigned long) idx, args[idx]);
  }
  for (size_t idx = 0; idx < n_envs; ++idx)
  {
    (void) printf ("D: Env %lu: %s\n", (unsigned long) idx, environment[idx]);
  }
#endif

  rc = execve (binary_path, (char * const *) args, (char * const *) environment);
  if (rc == -1)
  {
    (void) fprintf (stderr, "F: Failed to spawn binary: %s\n", strerror (errno));
  }

 out:
  if (args)
  {
    // release arguments
    for (size_t idx = 0; idx < n_args; ++idx)
    {
      if (args[idx])
      {
        free (args[idx]);
      }
    }

    free (args);
  }

  if (environment)
  {
    // release environment variables
    for (size_t idx = 0; idx < n_envs; ++idx)
    {
      if (environment[idx])
      {
        free (environment[idx]);
      }
    }

    free (environment);
  }

  return (rc);
}
