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

#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <stdlib.h>
#include <string.h>

#include "fetch.h"
#include "proc.h"
#include "type.h"
#include "value.h"

int aarch64_read_gregs(struct process *proc, struct user_pt_regs *regs);
int aarch64_read_fregs(struct process *proc, struct user_fpsimd_state *regs);


struct fetch_context
{
	struct user_pt_regs gregs;
	struct user_fpsimd_state fpregs;
	arch_addr_t nsaa;
	unsigned ngrn;
	unsigned nsrn;
};

static int
context_init(struct fetch_context *context, enum tof type, struct process *proc)
{
	if (aarch64_read_gregs(proc, &context->gregs) < 0
	    || aarch64_read_fregs(proc, &context->fpregs) < 0)
		return -1;

	/* XXX double cast */
	context->ngrn = 0;
	context->nsrn = 0;
	context->nsaa = (arch_addr_t) (uintptr_t) context->gregs.sp;

	return 0;
}

struct fetch_context *
arch_fetch_arg_init(enum tof type, struct process *proc,
		    struct arg_type_info *ret_info)
{
	struct fetch_context *ret = malloc(sizeof *ret);
	if (ret == NULL || context_init(ret, type, proc) < 0) {
		free(ret);
		return NULL;
	}

	return ret;
}

struct fetch_context *
arch_fetch_arg_clone(struct process *proc, struct fetch_context *context)
{
	struct fetch_context *ret = malloc(sizeof(*ret));
	if (ret == NULL)
		return NULL;
	return memcpy(ret, context, sizeof(*ret));
}

static int
copy_from(struct value *value, size_t sz, uint64_t u)
{
	if (sz < 8)
		sz = 8;
	unsigned char *buf = value_reserve(value, sz);
	if (buf == NULL)
		return -1;
	memcpy(buf, &u, sz);
	return 0;
}

static int
pass_arg(struct fetch_context *context, enum tof type,
	 struct process *proc, struct arg_type_info *info,
	 struct value *value)
{
	size_t sz = type_sizeof(proc, info);
	if (sz == (size_t) -1)
		return -1;

	switch (info->type) {
	case ARGTYPE_VOID:
		return 0;

	case ARGTYPE_INT:
	case ARGTYPE_UINT:
	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
	case ARGTYPE_CHAR:
	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
	case ARGTYPE_POINTER:
		if (context->ngrn < 8 && sz <= 8)
			return copy_from(value, sz,
					 context->gregs.regs[context->ngrn++]);

	case ARGTYPE_FLOAT:
	case ARGTYPE_DOUBLE:
	case ARGTYPE_ARRAY:
	case ARGTYPE_STRUCT:
		break;
	}
	return -1;
}

int
arch_fetch_arg_next(struct fetch_context *context, enum tof type,
		    struct process *proc, struct arg_type_info *info,
		    struct value *value)
{
	return pass_arg(context, type, proc, info, value);
}

int
arch_fetch_retval(struct fetch_context *context, enum tof type,
		  struct process *proc, struct arg_type_info *info,
		  struct value *value)
{
	if (context_init(context, type, proc) < 0)
		return -1;

	return pass_arg(context, type, proc, info, value);
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
