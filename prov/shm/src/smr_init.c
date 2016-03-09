/*
 * Copyright (c) 2015-2016 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <rdma/fi_errno.h>

#include <prov.h>
#include "smr.h"


int smr_check_info(struct fi_info *info)
{
	return fi_check_info(&smr_prov, &smr_info, info);
}

static int smr_getinfo(uint32_t version, const char *node, const char *service,
			uint64_t flags, struct fi_info *hints, struct fi_info **info)
{
	/* A SHM address namespace is not yet defined.
	 * We require FI_SOURCE with valid node and service parameters.
	 * The proposed name space is:
	 * process ID - unique for each process
	 * &ep_cntr - handle case where app links against library more
	 *            than once, e.g. libfabric is included by two libraries
	 * cntr_val - unique value for each EP
	 */
	if (!(flags & FI_SOURCE) || !node | !service) {
		FI_INFO(&smr_prov, FI_LOG_CORE,
			"SHM requires FI_SOURCE + node + service\n");
		return -FI_ENODATA;
	}

	return util_getinfo(&smr_prov, version, node, service, flags,
			    &smr_info, hints, info);
}

static void smr_fini(void)
{
	/* yawn */
}

struct fi_provider smr_prov = {
	.name = "SHM",
	.version = FI_VERSION(SMR_MAJOR_VERSION, SMR_MINOR_VERSION),
	.fi_version = FI_VERSION(1, 3),
	.getinfo = smr_getinfo,
	.fabric = smr_fabric,
	.cleanup = smr_fini
};

UDP_INI
{
	return &smr_prov;
}
