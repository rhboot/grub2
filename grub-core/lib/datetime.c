/* datetime.c - Module for common datetime function.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2008  Free Software Foundation, Inc.
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

#include <grub/datetime.h>
#include <grub/i18n.h>
#include <grub/misc.h>
#include <grub/mm.h>
#ifdef GRUB_MACHINE_EMU
#include <grub/dl.h>

GRUB_MOD_LICENSE ("GPLv3+");
#endif

static const char *const grub_weekday_names[] =
{
  N_("Sunday"),
  N_("Monday"),
  N_("Tuesday"),
  N_("Wednesday"),
  N_("Thursday"),
  N_("Friday"),
  N_("Saturday"),
};

int
grub_get_weekday (struct grub_datetime *datetime)
{
  unsigned a, y, m;

  if (datetime->month <= 2)
    a = 1;
  else
    a = 0;
  y = datetime->year - a;
  m = datetime->month + 12 * a - 2;

  return (datetime->day + y + y / 4 - y / 100 + y / 400 + (31 * m / 12)) % 7;
}

const char *
grub_get_weekday_name (struct grub_datetime *datetime)
{
  return _ (grub_weekday_names[grub_get_weekday (datetime)]);
}

#define SECPERMIN 60
#define SECPERHOUR (60*SECPERMIN)
#define SECPERDAY (24*SECPERHOUR)
#define DAYSPERYEAR 365
#define DAYSPER4YEARS (4*DAYSPERYEAR+1)
/* 24 leap years in 100 years */
#define DAYSPER100YEARS (100 * DAYSPERYEAR + 24)
/* 97 leap years in 400 years */
#define DAYSPER400YEARS (400 * DAYSPERYEAR + 97)

void
grub_unixtime2datetime (grub_int64_t nix, struct grub_datetime *datetime)
{
  int i;
  grub_uint8_t months[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  /* In the period of validity of unixtime all years divisible by 4
     are bissextile*/
  /* Convenience: let's have 3 consecutive non-bissextile years
     at the beginning of the counting date. So count from 1901. */
  int days_epoch;
  /* Number of days since 1st January, 1 (proleptic). */
  unsigned days;
  /* Seconds into current day.  */
  unsigned secs_in_day;
  /* Tracks whether this is a leap year. */
  bool bisextile;

  /* Transform C divisions and modulos to mathematical ones */
  if (nix < 0)
    /*
     * The result of division here shouldn't be larger than GRUB_INT_MAX.
     * So, it's safe to store the result back in an int.
     */
    days_epoch = -(grub_divmod64 (((grub_int64_t) (SECPERDAY) - nix - 1), SECPERDAY, NULL));
  else
    days_epoch = grub_divmod64 (nix, SECPERDAY, NULL);

  secs_in_day = nix - days_epoch * SECPERDAY;
  /*
   * 1970 is Unix Epoch. Adjust to a year 1 epoch:
   *  Leap year logic:
   *   - Years evenly divisible by 400 are leap years
   *   - Otherwise, if divisible by 100 are not leap years
   *   - Otherwise, if divisible by 4 are leap years
   *  There are four 400-year periods (1600 years worth of days with leap days)
   *  There are 369 years in addition to the four 400 year periods
   *  There are three 100-year periods worth of leap days (3*24)
   *  There are 17 leap days in 69 years (beyond the three 100 year periods)
   */
  days = 4 * DAYSPER400YEARS + 369 * DAYSPERYEAR + 3 * 24 + 17 + days_epoch;

  datetime->year = 1 + 400 * (days / DAYSPER400YEARS);
  days %= DAYSPER400YEARS;

  /*
   * On 31st December of bissextile (leap) years 365 days from the beginning
   * of the year elapsed but year isn't finished yet - every 400 years
   * 396 is 4 years less than 400 year leap cycle
   * 96 is 1 day less than number of leap days in 400 years
   */
  if (days / DAYSPER100YEARS == 4)
    {
      datetime->year += 396;
      days -= 396 * DAYSPERYEAR + 96;
    }
  else
    {
      datetime->year += 100 * (days / DAYSPER100YEARS);
      days %= DAYSPER100YEARS;
    }

  datetime->year += 4 * (days / DAYSPER4YEARS);
  days %= DAYSPER4YEARS;
  /*
   * On 31st December of bissextile (leap) years 365 days from the beginning
   * of the year elapsed but year isn't finished yet - every 4 years
   */
  if (days / DAYSPERYEAR == 4)
    {
      datetime->year += 3;
      days -= 3 * DAYSPERYEAR;
    }
  else
    {
      datetime->year += days / DAYSPERYEAR;
      days %= DAYSPERYEAR;
    }

  bisextile = (datetime->year % 4 == 0
               && (datetime->year % 100 != 0
                   || datetime->year % 400 == 0)) ? true : false;
  for (i = 0;
       i < 12 && days >= ((i == 1 && bisextile == true) ? 29 : months[i]);
       i++)
    days -= ((i == 1 && bisextile == true) ? 29 : months[i]);
  datetime->month = i + 1;
  datetime->day = 1 + days;
  datetime->hour = (secs_in_day / SECPERHOUR);
  secs_in_day %= SECPERHOUR;
  datetime->minute = secs_in_day / SECPERMIN;
  datetime->second = secs_in_day % SECPERMIN;
}
