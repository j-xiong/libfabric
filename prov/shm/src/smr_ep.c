/*
 * Copyright (c) 2013-2016 Intel Corporation. All rights reserved.
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

#include <stdlib.h>
#include <string.h>

#include "smr.h"


int smr_setname(fid_t fid, void *addr, size_t addrlen)
{
	struct smr_ep *ep;
	char *name;

	ep = container_of(fid, struct smr_ep, util_ep.ep_fid.fid);
	name = strdup(addr);
	if (!name)
		return -FI_ENOMEM;

	if (ep->name)
		free((void *) ep->name);
	ep->name = name;
	return 0;
}

int smr_getname(fid_t fid, void *addr, size_t *addrlen)
{
	struct smr_ep *ep;
	int ret = 0;

	ep = container_of(fid, struct smr_ep, util_ep.ep_fid.fid);
	if (!ep->name)
		return -FI_EADDRNOTAVAIL;

	if (!addr || *addrlen == 0 ||
	    snprintf(addr, *addrlen, "%s", ep->name) >= *addrlen)
		ret = -FI_ETOOSMALL;
	*addrlen = strlen(ep->name) + 1;
	return ret;
}

static struct fi_ops_cm smr_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.setname = smr_setname,
	.getname = smr_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = fi_no_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
	.shutdown = fi_no_shutdown,
};

int smr_getopt(fid_t fid, int level, int optname,
		void *optval, size_t *optlen)
{
	return -FI_ENOPROTOOPT;
}

int smr_setopt(fid_t fid, int level, int optname,
		const void *optval, size_t optlen)
{
	return -FI_ENOPROTOOPT;
}

static struct fi_ops_ep smr_ep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = fi_no_cancel,
	.getopt = smr_getopt,
	.setopt = smr_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

static void smr_tx_comp(struct smr_ep *ep, void *context)
{
	struct fi_cq_data_entry *comp;

	comp = cirque_tail(ep->util_ep.tx_cq->cirq);
	comp->op_context = context;
	comp->flags = FI_SEND;
	comp->len = 0;
	comp->buf = NULL;
	comp->data = 0;
	cirque_commit(ep->util_ep.tx_cq->cirq);
}

static void smr_tx_comp_signal(struct smr_ep *ep, void *context)
{
	smr_tx_comp(ep, context);
	ep->util_ep.tx_cq->wait->signal(ep->util_ep.tx_cq->wait);
}

static void smr_rx_comp(struct smr_ep *ep, void *context, uint64_t flags,
			 size_t len, void *buf, void *addr)
{
	struct fi_cq_data_entry *comp;

	comp = cirque_tail(ep->util_ep.rx_cq->cirq);
	comp->op_context = context;
	comp->flags = FI_RECV | flags;
	comp->len = len;
	comp->buf = buf;
	comp->data = 0;
	cirque_commit(ep->util_ep.rx_cq->cirq);
}

static void smr_rx_src_comp(struct smr_ep *ep, void *context, uint64_t flags,
			     size_t len, void *buf, void *addr)
{
	ep->util_ep.rx_cq->src[cirque_windex(ep->util_ep.rx_cq->cirq)] =
		(uint32_t) (uintptr_t) addr;
	smr_rx_comp(ep, context, flags, len, buf, addr);
}

static void smr_rx_comp_signal(struct smr_ep *ep, void *context,
			uint64_t flags, size_t len, void *buf, void *addr)
{
	smr_rx_comp(ep, context, flags, len, buf, addr);
	ep->util_ep.rx_cq->wait->signal(ep->util_ep.rx_cq->wait);
}

static void smr_rx_src_comp_signal(struct smr_ep *ep, void *context,
			uint64_t flags, size_t len, void *buf, void *addr)
{
	smr_rx_src_comp(ep, context, flags, len, buf, addr);
	ep->util_ep.rx_cq->wait->signal(ep->util_ep.rx_cq->wait);

}

void smr_ep_progress(struct smr_ep *ep)
{
	struct smr_ep_entry *entry;
	int ret;

	fastlock_acquire(&ep->util_ep.rx_cq->cq_lock);
	if (cirque_isempty(ep->rxq))
		goto out;

	entry = cirque_head(ep->rxq);

	/* TODO: write me */

	if (ret >= 0) {
		ep->rx_comp(ep, entry->context, 0, ret, NULL, &addr);
		cirque_discard(ep->rxq);
	}
out:
	fastlock_release(&ep->util_ep.rx_cq->cq_lock);
}

ssize_t smr_recvmsg(struct fid_ep *ep_fid, const struct fi_msg *msg,
		uint64_t flags)
{
	struct smr_ep *ep;
	struct smr_ep_entry *entry;
	ssize_t ret;

	ep = container_of(ep_fid, struct smr_ep, ep_fid.fid);
	fastlock_acquire(&ep->util_ep.rx_cq->cq_lock);
	if (cirque_isfull(ep->rxq)) {
		ret = -FI_EAGAIN;
		goto out;
	}

	entry = cirque_tail(ep->rxq);
	entry->context = msg->context;
	for (entry->iov_count = 0; entry->iov_count < msg->iov_count;
	     entry->iov_count++) {
		entry->iov[entry->iov_count] = msg->msg_iov[entry->iov_count];
	}
	entry->flags = 0;

	cirque_commit(ep->rxq);
	ret = 0;
out:
	fastlock_release(&ep->util_ep.rx_cq->cq_lock);
	return ret;
}

ssize_t smr_recvv(struct fid_ep *ep_fid, const struct iovec *iov, void **desc,
		size_t count, fi_addr_t src_addr, void *context)
{
	struct fi_msg msg;

	msg.msg_iov = iov;
	msg.iov_count = count;
	msg.context = context;
	return smr_recvmsg(ep_fid, &msg, 0);
}

ssize_t smr_recv(struct fid_ep *ep_fid, void *buf, size_t len, void *desc,
		fi_addr_t src_addr, void *context)
{
	struct smr_ep *ep;
	struct smr_ep_entry *entry;
	ssize_t ret;

	ep = container_of(ep_fid, struct smr_ep, util_ep.ep_fid.fid);
	fastlock_acquire(&ep->util_ep.rx_cq->cq_lock);
	if (cirque_isfull(ep->rxq)) {
		ret = -FI_EAGAIN;
		goto out;
	}

	entry = cirque_tail(ep->rxq);
	entry->context = context;
	entry->iov_count = 1;
	entry->iov[0].iov_base = buf;
	entry->iov[0].iov_len = len;
	entry->flags = 0;

	cirque_commit(ep->rxq);
	ret = 0;
out:
	fastlock_release(&ep->util_ep.rx_cq->cq_lock);
	return ret;
}

static void smr_format_inject_msg(struct shm_cmd *cmd, void *buf, size_t len)
{
	cmd->hdr.version = OFI_OP_VERSION;
	cmd->hdr.rx_index = 0;
	cmd->hdr.op = ofi_op_msg;
	cmd->hdr.op_data = shm_op_inject;
	cmd->hdr.flags = 0;

	cmd->hdr.size = 0;
	cmd->hdr.data = 0;
	cmd->hdr.resv = 0;
}

ssize_t smr_send(struct fid_ep *ep_fid, const void *buf, size_t len, void *desc,
		fi_addr_t dest_addr, void *context)
{
	struct smr_ep *ep;
	struct shm_region *peer_smr;
	struct smr_req *tx_req;
	struct smr_inject_buf *tx_buf;
	struct shm_cmd *cmd;
	int peer_id;
	ssize_t ret = 0;

	ep = container_of(ep_fid, struct smr_ep, util_ep.ep_fid.fid);
	peer_id = ofi_av_get_data(ep->util_ep.av, dest_addr);

	fastlock_acquire(&ep->util_ep.tx_cq->cq_lock);
	if (freestack_isempty(smr_tx_ctx(ep->region))) {
		ret = -FI_EAGAIN;
		goto out;
	}

	peer_smr = smr_peer_region(ep->region, peer_id);
	tx_req = freestack_pop(smr_tx_ctx(ep->region));
	tx_buf = freestack_pop(smr_inject_pool(ep->region));

	memcpy(tx_buf->data, buf, len);

	smr_lock(peer_smr);
	if (cirque_isfull(smr_cmd_queue(peer_smr))) {
		freestack_push(smr_tx_ctx(ep->region), tx_req);
		freestack_push(smr_inject_pool(ep->region), tx_buf);
		ret = -FI_EAGAIN;
		goto unlock;
	}

	cmd = cirque_tail(smr_cmd_queue(peer_smr));
	smr_format_send(cmd);

	cirque_commit(smr_cmd_queue(peer_smr));
unlock:
	smr_unlock(peer_smr);
out:
	fastlock_release(&ep->util_ep.tx_cq->cq_lock);
	return ret;
}

ssize_t smr_sendmsg(struct fid_ep *ep_fid, const struct fi_msg *msg,
		uint64_t flags)
{
	struct smr_ep *ep;
	ssize_t ret;

	ep = container_of(ep_fid, struct smr_ep, util_ep.ep_fid.fid);

	fastlock_acquire(&ep->util_ep.tx_cq->cq_lock);
	if (cirque_isfull(ep->util_ep.tx_cq->cirq)) {
		ret = -FI_EAGAIN;
		goto out;
	}

	/* TODO: write me */

	if (ret >= 0) {
		ep->tx_comp(ep, msg->context);
		ret = 0;
	} else {
		ret = -errno;
	}
out:
	fastlock_release(&ep->util_ep.tx_cq->cq_lock);
	return ret;
}

ssize_t smr_sendv(struct fid_ep *ep_fid, const struct iovec *iov, void **desc,
		size_t count, fi_addr_t dest_addr, void *context)
{
	struct fi_msg msg;

	msg.msg_iov = iov;
	msg.iov_count = count;
	msg.addr = dest_addr;
	msg.context = context;

	return smr_sendmsg(ep_fid, &msg, 0);
}

ssize_t smr_inject(struct fid_ep *ep_fid, const void *buf, size_t len,
		fi_addr_t dest_addr)
{
	struct smr_ep *ep;
	ssize_t ret;

	ep = container_of(ep_fid, struct smr_ep, util_ep.ep_fid.fid);

	/* TODO: write me */

	return ret == len ? 0 : -errno;
}

static struct fi_ops_msg smr_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = smr_recv,
	.recvv = smr_recvv,
	.recvmsg = smr_recvmsg,
	.send = smr_send,
	.sendv = smr_sendv,
	.sendmsg = smr_sendmsg,
	.inject = smr_inject,
	.senddata = fi_no_msg_senddata,
	.injectdata = fi_no_msg_injectdata,
};

static int smr_ep_close(struct fid *fid)
{
	struct smr_ep *ep;
	struct util_wait_fd *wait;

	ep = container_of(fid, struct smr_ep, util_ep.ep_fid.fid);

	if (ep->util_ep.av)
		atomic_dec(&ep->util_ep.av->ref);

	if (ep->util_ep.rx_cq) {
		fid_list_remove(&ep->util_ep.rx_cq->list,
				&ep->util_ep.rx_cq->list_lock,
				&ep->util_ep.ep_fid.fid);
		atomic_dec(&ep->util_ep.rx_cq->ref);
	}

	if (ep->util_ep.tx_cq)
		atomic_dec(&ep->util_ep.tx_cq->ref);

	if (ep->region)
		smr_free(ep->region);

	smr_rx_cirq_free(ep->rxq);
	atomic_dec(&ep->util_ep.domain->ref);
	free(ep);
	return 0;
}

static int smr_ep_bind_cq(struct smr_ep *ep, struct util_cq *cq, uint64_t flags)
{
	struct util_wait_fd *wait;
	int ret;

	if (flags & ~(FI_TRANSMIT | FI_RECV)) {
		FI_WARN(&smr_prov, FI_LOG_EP_CTRL,
			"unsupported flags\n");
		return -FI_EBADFLAGS;
	}

	if (((flags & FI_TRANSMIT) && ep->util_ep.tx_cq) ||
	    ((flags & FI_RECV) && ep->util_ep.rx_cq)) {
		FI_WARN(&smr_prov, FI_LOG_EP_CTRL,
			"duplicate CQ binding\n");
		return -FI_EINVAL;
	}

	if (flags & FI_TRANSMIT) {
		ep->util_ep.tx_cq = cq;
		atomic_inc(&cq->ref);
		ep->tx_comp = cq->wait ? smr_tx_comp_signal : smr_tx_comp;
	}

	if (flags & FI_RECV) {
		ep->util_ep.rx_cq = cq;
		atomic_inc(&cq->ref);

		if (cq->wait) {
			ep->rx_comp = (cq->domain->caps & FI_SOURCE) ?
				      smr_rx_src_comp_signal :
				      smr_rx_comp_signal;

			wait = container_of(cq->wait,
					    struct util_wait_fd, util_wait);
			if (ret)
				return ret;
		} else {
			ep->rx_comp = (cq->domain->caps & FI_SOURCE) ?
				      smr_rx_src_comp : smr_rx_comp;
		}

		ret = fid_list_insert(&cq->list,
				      &cq->list_lock,
				      &ep->util_ep.ep_fid.fid);
		if (ret)
			return ret;
	}

	return 0;
}

static int smr_ep_bind(struct fid *ep_fid, struct fid *bfid, uint64_t flags)
{
	struct smr_ep *ep;
	struct util_av *av;
	int ret = 0;

	ep = container_of(ep_fid, struct smr_ep, util_ep.ep_fid.fid);
	switch (bfid->fclass) {
	case FI_CLASS_AV:
		if (ep->av) {
			FI_WARN(&smr_prov, FI_LOG_EP_CTRL,
				"duplicate AV binding\n");
			return -FI_EINVAL;
		}
		av = container_of(bfid, struct util_av, av_fid.fid);
		atomic_inc(&av->ref);
		ep->util_ep.av = av;
		break;
	case FI_CLASS_CQ:
		ret = smr_ep_bind_cq(ep, container_of(bfid, struct smr_cq,
						      cq_fid.fid), flags);
		break;
	case FI_CLASS_EQ:
		break;
	default:
		FI_WARN(&smr_prov, FI_LOG_EP_CTRL,
			"invalid fid class\n");
		ret = -FI_EINVAL;
		break;
	}
	return ret;
}

static int smr_ep_ctrl(struct fid *fid, int command, void *arg)
{
	struct smr_attr attr;
	struct smr_ep *ep;
	int ret;

	ep = container_of(fid, struct smr_ep, util_ep.ep_fid.fid);
	switch (command) {
	case FI_ENABLE:
		if (!ep->util_ep.rx_cq || !ep->util_ep.tx_cq)
			return -FI_ENOCQ;
		if (!ep->util_ep.av)
			return -FI_ENOAV;

		attr.name = ep->name;
		attr.peer_count = ep->util_ep.av->count;
		attr.rx_count = ep->rxq->size;
		attr.tx_count = ep->tx_size;
		ret = smr_create(&smr_prov, &attr, &ep->region);
		break;
	default:
		return -FI_ENOSYS;
	}
	return ret;
}

static struct fi_ops smr_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = smr_ep_close,
	.bind = smr_ep_bind,
	.control = smr_ep_ctrl,
	.ops_open = fi_no_ops_open,
};

int smr_endpoint(struct fid_domain *domain, struct fi_info *info,
		  struct fid_ep **ep_fid, void *context)
{
	struct smr_ep *ep;
	int ret;

	if (!info || !info->ep_attr || !info->rx_attr || !info->tx_attr)
		return -FI_EINVAL;

	ret = smr_check_info(info);
	if (ret)
		return ret;

	ep = calloc(1, sizeof(*ep));
	if (!ep)
		return -FI_ENOMEM;

	if (info->src_addr && info->src_addrlen) {
		ret = smr_setname(&ep->util_ep.ep_fid.fid, info->src_addr,
				  info->src_addrlen);
		if (ret)
			goto err;
	}

	ep->tx_size = info->tx_attr->size;
	ep->rxq = smr_rx_cirq_create(info->rx_attr->size);
	if (!ep->rxq) {
		ret = -FI_ENOMEM;
		goto err;
	}

	ep->util_ep.ep_fid.fid.fclass = FI_CLASS_EP;
	ep->util_ep.ep_fid.fid.context = context;
	ep->util_ep.ep_fid.fid.ops = &smr_ep_fi_ops;
	ep->util_ep.ep_fid.ops = &smr_ep_ops;
	ep->util_ep.ep_fid.cm = &smr_cm_ops;
	ep->util_ep.ep_fid.msg = &smr_msg_ops;
	ep->util_ep.progress = smr_ep_progress;

	ep->util_ep.domain = container_of(domain, struct util_domain, domain_fid);
	atomic_inc(&ep->util_ep.domain->ref);

	*ep_fid = &ep->util_ep.ep_fid;
	return 0;
err:
	free(ep->name);
	free(ep);
	return ret;
}
