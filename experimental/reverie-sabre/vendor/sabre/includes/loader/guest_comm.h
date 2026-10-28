/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef SABRE_LOADER_GUEST_COMM_H
#define SABRE_LOADER_GUEST_COMM_H

#include <stdbool.h>
#include <stddef.h>

/* The loader's genuine client argv supplies a NUL-terminated program name.
 * Match Path::file_name and Linux's 15-byte task-name limit, including raw
 * non-UTF8 bytes. No loader or neutral staging basename replaces argv[0]. */
static inline bool sbr_guest_comm_from_program(const char *program,
                                              char name[16]) {
  if (program == NULL)
    return false;
  size_t end = 0;
  while (program[end] != '\0')
    ++end;
  size_t start;
  for (;;) {
    while (end > 0 && program[end - 1] == '/')
      --end;
    if (end == 0)
      return false;
    start = end;
    while (start > 0 && program[start - 1] != '/')
      --start;
    if (end - start != 1 || program[start] != '.')
      break;
    end = start;
  }
  if (end - start == 2 && program[start] == '.' && program[start + 1] == '.')
    return false;
  size_t length = end - start;
  if (length > 15)
    length = 15;
  for (size_t index = 0; index < 16; ++index)
    name[index] = index < length ? program[start + index] : '\0';
  return true;
}

#endif
