/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020 IBM Corporation
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

#ifndef LIBTASN1_WRAP_TESTS_H
#define LIBTASN1_WRAP_TESTS_H

void test_CVE_2018_1000654 (void);

void test_object_id_encoding (void);

void test_object_id_decoding (void);

void test_octet_string (void);

void test_overflow (void);

void test_reproducers (void);

void test_simple (void);

void test_strings (void);

#endif
