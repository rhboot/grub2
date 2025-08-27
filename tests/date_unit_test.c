/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2013 Free Software Foundation, Inc.
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

#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include <grub/misc.h>
#include <grub/datetime.h>
#include <grub/test.h>

static void
date_test (grub_int64_t v)
{
  struct grub_datetime dt;
  time_t t = v;
  struct tm *g;
  int w;
  grub_int64_t back = 0;

  g = gmtime (&t);

  grub_unixtime2datetime (v, &dt);

  w = grub_get_weekday (&dt);

  grub_datetime2unixtime (&dt, &back);

  grub_test_assert (g->tm_sec == dt.second, "time %lld bad second: %d vs %d", (long long) v,
		    g->tm_sec, dt.second);
  grub_test_assert (g->tm_min == dt.minute, "time %lld bad minute: %d vs %d", (long long) v,
		    g->tm_min, dt.minute);
  grub_test_assert (g->tm_hour == dt.hour, "time %lld bad hour: %d vs %d", (long long) v,
		    g->tm_hour, dt.hour);
  grub_test_assert (g->tm_mday == dt.day, "time %lld bad day: %d vs %d", (long long) v,
		    g->tm_mday, dt.day);
  grub_test_assert (g->tm_mon + 1 == dt.month, "time %lld bad month: %d vs %d",(long long) v,
		    g->tm_mon + 1, dt.month);
  grub_test_assert (g->tm_year + 1900 == dt.year,
                   "time %lld bad year: %d vs %d", (long long) v,
		    g->tm_year + 1900, dt.year);
  grub_test_assert (g->tm_wday == w, "time %lld bad week day: %d vs %d", (long long) v,
		    g->tm_wday, w);
  grub_test_assert (back == v, "time %lld bad back transform: %lld", (long long) v,
                   (long long) back);
}

static void
date_test_iter (void)
{
  /*
   * Test several interesting UNIX timestamps in 32-bit time:
   *   1.             -1: 1969-12-31 23:59:59 - Just before EPOCH
   *   2.              0: 1970-01-01 00:00:00 - EPOCH
   *   3.             +1: 1970-01-01 00:00:01 - Just after EPOCH
   *   4.      978224552: 2000-12-31 01:02:32 - Leap year, after Feb
   *   5.    -2133156255: 1902-05-28 16:35:45 - Nominal value
   *   6.    -2110094321: 1903-02-19 14:41:19 - Nominal value
   *   7. GRUB_INT32_MIN: 1901-12-13 20:45:52 - 32-bit Min value
   *   8. GRUB_INT32_MAX: 2038-01-19 03:14:07 - 32-bit Max value
   */
  grub_int32_t tests[] = { -1, 0, +1, 978224552, -2133156255, -2110094321, GRUB_INT32_MIN,
			   GRUB_INT32_MAX };
  /*
   * Test several known UNIX timestamps outside 32-bit time:
   *   1. 5774965200:   2152-12-31 21:00:00  - Leap year
   *   2. 4108700725:   2100-03-14 09:45:25  - Not a leap year
   *   3. -5029179792:  1810-08-19 21:36:48  - Not a leap year
   *   4. -62135596799: 0001-01-01 00:00:00  - Minimum AD
   *   5. 253402300799: 9999-12-31 23:59:59  - Maximum 4 digit year
   */
  grub_int64_t tests64[] = { (grub_int64_t) 5774965200,
                             (grub_int64_t) 4108700725,
                             (grub_int64_t) -5029179792,
                             (grub_int64_t) -62135596799,
                             (grub_int64_t) 253402300799 };
  unsigned i;

  for (i = 0; i < ARRAY_SIZE (tests); i++)
    date_test (tests[i]);
  srand (42);
  for (i = 0; i < 1000000; i++)
    {
      grub_int32_t x = rand ();
      date_test (x);
      date_test (-x);
    }

  if (sizeof (time_t) > 4)
    {
      for (i = 0; i < ARRAY_SIZE (tests64); i++)
        date_test (tests64[i]);
      for (i = 0; i < 5000000; i++)
        {
          /*
           * Test some pseudo-random dates/times between 1970 and 9999
           * "117" is used to scale the random 32-bit int from range
           * 0..2147483648 to 0..251255586816. This is reasonably
           * close to max 9999 date represented by 253402300799.
           */
          grub_int64_t x = (grub_int64_t) rand () * (grub_int64_t) 117;
          date_test (x);
        }
      for (i = 0; i < 5000000; i++)
        {
          /*
           * Test some pseudo-random dates/times between 0001 and 1969
           * "-28" is used to scale the random 32-bit int from range
           * 0..2147483648 to -60129542144..0. This is reasonably
           * close to min 0001 date represented by -62135596799.
           */
          grub_int64_t x = (grub_int64_t) rand () * (grub_int64_t) -28;
          date_test (x);
        }
    }
}

GRUB_UNIT_TEST ("date_unit_test", date_test_iter);
