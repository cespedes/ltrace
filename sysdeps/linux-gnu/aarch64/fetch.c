/*
 * This file is part of ltrace.
 * Copyright (C) 2014 Petr Machata, Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <stdlib.h>
#include <string.h>

#include "fetch.h"
#include "proc.h"
#include "type.h"
#include "value.h"

struct fetch_context
{
};

struct fetch_context *
arch_fetch_arg_init(enum tof type, struct process *proc,
		    struct arg_type_info *ret_info)
{
	return NULL;
}

struct fetch_context *
arch_fetch_arg_clone(struct process *proc, struct fetch_context *context)
{
	struct fetch_context *ret = malloc(sizeof(*ret));
	if (ret == NULL)
		return NULL;
	return memcpy(ret, context, sizeof(*ret));
}

int
arch_fetch_arg_next(struct fetch_context *context, enum tof type,
		    struct process *proc, struct arg_type_info *info,
		    struct value *valuep)
{
	return -1;
}

int
arch_fetch_retval(struct fetch_context *context, enum tof type,
		  struct process *proc, struct arg_type_info *info,
		  struct value *valuep)
{
	return -1;
}

void
arch_fetch_arg_done(struct fetch_context *context)
{
	if (context != NULL)
		free(context);
}

size_t
arch_type_sizeof(struct process *proc, struct arg_type_info *arg)
{
	return (size_t) -2;
}

size_t
arch_type_alignof(struct process *proc, struct arg_type_info *arg)
{
	return (size_t) -2;
}
