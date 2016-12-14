/*
 * Copyright (c) 2016 Intel Corporation. All rights reserved.
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

#ifndef _FI_SHM_H_
#define _FI_SHM_H_

#include "config.h"

#include <stdint.h>
#include <stddef.h>

#include <fi_atom.h>
#include <fi_proto.h>
#include <fi_mem.h>
#include <fi_rbuf.h>

#include <rdma/providers/fi_prov.h>

#ifdef __cplusplus
extern "C" {
#endif


#define SMR_VERSION	1

#ifdef HAVE_ATOMICS
#define SMR_FLAG_ATOMIC	(1 << 0)
#else
#define SMR_FLAG_ATOMIC	(0 << 0)
#endif

#if ENABLE_DEBUG
#define SMR_FLAG_DEBUG	(1 << 1)
#else
#define SMR_FLAG_DEBUG	(0 << 1)
#endif


/* SMR op_data: Specifies data source location */
enum {
	smr_op_inline,	/* command data */
	smr_op_inject,	/* inject buffers */
	smr_op_iov,	/* reference iovec via CMA */
};

struct smr_cmd_hdr {
	struct ofi_op_hdr	op;
	uint32_t		cmd_id;
	uint32_t		rx_key;
};

#define SMR_CMD_SIZE		128	/* align with 64-byte cache line */
#define SMR_CMD_DATA_LEN	(128 - sizeof(struct smr_cmd_hdr))

union smr_cmd_data {
	uint8_t			msg[SMR_CMD_DATA_LEN];
	struct iovec		iov[SMR_CMD_DATA_LEN / sizeof(struct iovec)];
	struct ofi_rma_iov	rma_iov[SMR_CMD_DATA_LEN / sizeof(struct ofi_rma_iov)];
	struct ofi_rma_ioc	rma_ioc[SMR_CMD_DATA_LEN / sizeof(struct ofi_rma_ioc)];
};

struct smr_cmd {
	struct smr_cmd_hdr	hdr;
	union smr_cmd_data	data;
};

enum {
	SMR_INJECT_SIZE = 4096
};

struct smr_region;
DECLARE_FREESTACK(struct smr_region *, smr_peer);

struct smr_map {
	const struct fi_provider *prov;
	atomic_t	lock;
	struct smr_peer	peer;	/* must be last */
};

struct smr_region {
	const struct fi_provider *prov;
	uint8_t		version;
	uint8_t		resv;
	uint16_t	flags;
	int		pid;
	atomic_t	lock;
	struct smr_map	*map;

	size_t		total_size;

	/* offsets from start of smr_region */
	size_t		cmd_queue_offset;
	size_t		tx_ctx_offset;
	size_t		resp_queue_offset;
	size_t		inject_pool_offset;
	size_t		name_offset;
};


struct smr_req {
	void		*context;
	void		*buffer;
	uint64_t	flags;
};

struct smr_resp {
	uint32_t	cmd_id;
	uint32_t	status;
};

struct smr_inject_buf {
	uint8_t		data[SMR_INJECT_SIZE];
};

DECLARE_CIRQUE(struct smr_cmd, smr_cmd_queue);
DECLARE_FREESTACK(struct smr_req, smr_tx_ctx);
DECLARE_CIRQUE(struct smr_resp, smr_resp_queue);
DECLARE_FREESTACK(struct smr_inject_buf, smr_inject_pool);

static inline struct smr_peer *smr_peer(struct smr_region *smr)
{
	return &smr->map->peer;
}
static inline struct smr_region *smr_peer_region(struct smr_region *smr, int i)
{
	return smr->map->peer.buf[i];
}
static inline struct smr_cmd_queue *smr_cmd_queue(struct smr_region *smr)
{
	return (struct smr_cmd_queue *) ((char *) smr + smr->cmd_queue_offset);
}
static inline struct smr_tx_ctx *smr_tx_ctx(struct smr_region *smr)
{
	return (struct smr_tx_ctx *) ((char *) smr + smr->tx_ctx_offset);
}
static inline struct smr_resp_queue *smr_resp_queue(struct smr_region *smr)
{
	return (struct smr_resp_queue *) ((char *) smr + smr->resp_queue_offset);
}
static inline struct smr_inject_pool *smr_inject_pool(struct smr_region *smr)
{
	return (struct smr_inject_pool *) ((char *) smr + smr->inject_pool_offset);
}
static inline const char *smr_name(struct smr_region *smr)
{
	return (const char *) smr + smr->name_offset;
}

static inline void smr_lock(atomic_t *lock)
{
	do {
	} while (atomic_compare_swap(lock, 0, 1));
}
static inline void smr_unlock(atomic_t *lock)
{
	atomic_set(lock, 0);
}

static inline void smr_set_map(struct smr_region *smr, struct smr_map *map)
{
	smr->map = map;
}

struct smr_attr {
	const char	*name;
	size_t		rx_count;
	size_t		tx_count;
};

int	smr_map_create(const struct fi_provider *prov, int peer_count,
		       struct smr_map **map);
int	smr_map_add(struct smr_map *map, const char *name, int *id);
void	smr_map_del(struct smr_map *map, int id);
void	smr_map_free(struct smr_map *map);

struct smr_region *smr_map_get(struct smr_map *map, int id);

int	smr_create(struct smr_map *map, const struct smr_attr *attr,
		   struct smr_region **smr);
void	smr_free(struct smr_region *smr);

#ifdef __cplusplus
}
#endif

#endif /* _FI_SHM_H_ */
