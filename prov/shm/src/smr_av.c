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

#include "smr.h"

static int smr_av_close(struct fid *fid)
{
        int ret;
        struct util_av *av;

        av = container_of(fid, struct util_av, av_fid);

        ret = ofi_av_close(av);
        if (ret)
                return ret;

        free(av);
        return 0;
}

/*
 * Input address: smr name (string)
 * Internal address: peer_id (integer), the input to util_av
 * output address: index (integer), the output from util_av
 */
static int smr_av_insert(struct fid_av *av_fid, const void *addr, size_t count,
			 fi_addr_t *fi_addr, uint64_t flags, void *context)
{
	struct smr_addr *smr_names = (void *)addr;
	struct util_av *av;
	struct smr_domain *domain;
	int peer_id, index;
	int i, ret;
	int succ_count = 0;

	av = container_of(av_fid, struct util_av, av_fid);
	domain = container_of(av->domain, struct smr_domain, util_domain);

	for (i = 0; i < count; i++) {
		/* TODO: handle duplication */
		ret = smr_map_add(domain->smr_map, smr_names[i].name, &peer_id);
		if (ret) {
                        if (av->eq)
                                ofi_av_write_event(av, i, -ret, context);
			continue;
		}

		ret = ofi_av_insert_addr(av, &peer_id, 0, &index);
                if (ret) {
                        if (av->eq)
                                ofi_av_write_event(av, i, -ret, context);
			continue;
                }

		succ_count++;

                if (fi_addr)
                        fi_addr[i] = (ret == 0) ? index : FI_ADDR_NOTAVAIL;
        }

	if (!(flags & FI_EVENT))
		return succ_count;

	ofi_av_write_event(av, succ_count, 0, context);
	return 0;
}

static int smr_av_remove(struct fid_av *av_fid, fi_addr_t *fi_addr, size_t count,
			 uint64_t flags)
{
        return 0;
}

static int smr_av_lookup(struct fid_av *av, fi_addr_t fi_addr, void *addr,
			 size_t *addrlen)
{
	struct util_av *util_av;
	struct smr_domain *domain;
	struct smr_region *peer_smr;
	int index = (int)fi_addr;
	int peer_id;

	util_av = container_of(av, struct util_av, av_fid);
	domain = container_of(util_av->domain, struct smr_domain, util_domain);
	peer_id = *(int *)ofi_av_get_addr(util_av, index);
	peer_smr = smr_map_get(domain->smr_map, peer_id);
	if (!peer_smr)
		return -FI_ADDR_NOTAVAIL;

	strncpy((char *)addr, smr_name(peer_smr), *addrlen);
	*addrlen = sizeof(struct smr_addr);
	return 0;
}

static const char *smr_av_straddr(struct fid_av *av, const void *addr,
				  char *buf, size_t *len)
{
	/* the input address is a string format */
	if (buf)
		strncpy(buf, (char *)addr, *len);

	*len = strlen((char *)addr) + 1;
	return buf;
}

static struct fi_ops smr_av_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = smr_av_close,
	.bind = ofi_av_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_av smr_av_ops = {
        .size = sizeof(struct fi_ops_av),
        .insert = smr_av_insert,
        .insertsvc = fi_no_av_insertsvc,
        .insertsym = fi_no_av_insertsym,
        .remove = smr_av_remove,
        .lookup = smr_av_lookup,
        .straddr = smr_av_straddr,
};

int smr_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
		struct fid_av **av, void *context)
{
	struct util_domain *util_domain;
	struct util_av_attr util_attr;
	struct util_av *util_av;
	int ret;

	if (!attr)
		return -FI_EINVAL;

	if (attr->name)
		return -FI_ENOSYS;

	if (attr->type == FI_AV_UNSPEC)
		attr->type = FI_AV_TABLE;

	util_domain = container_of(domain, struct util_domain, domain_fid);

        util_av = calloc(1, sizeof *util_av);
        if (!util_av)
                return -FI_ENOMEM;

	util_attr.addrlen = sizeof(int);
	util_attr.overhead = 0;
	util_attr.flags = 0;

	ret = ofi_av_init(util_domain, attr, &util_attr, util_av, context);
	if (ret) {
		free(util_av);
		return ret;
	}

	*av = &util_av->av_fid;
	(*av)->fid.ops = &smr_av_fi_ops;
	(*av)->ops = &smr_av_ops;
	return 0;
}

