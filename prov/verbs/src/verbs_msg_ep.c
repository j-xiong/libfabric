/*
 * Copyright (c) 2013-2015 Intel Corporation, Inc.  All rights reserved.
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

#include "config.h"

#include "fi_verbs.h"


#define VERBS_CM_DATA_SIZE 56
#define VERBS_RESOLVE_TIMEOUT 2000	// ms


static int
fi_ibv_msg_ep_getopt(fid_t fid, int level, int optname,
		  void *optval, size_t *optlen)
{
	switch (level) {
	case FI_OPT_ENDPOINT:
		switch (optname) {
		case FI_OPT_CM_DATA_SIZE:
			if (*optlen < sizeof(size_t))
				return -FI_ETOOSMALL;
			*((size_t *) optval) = VERBS_CM_DATA_SIZE;
			*optlen = sizeof(size_t);
			return 0;
		default:
			return -FI_ENOPROTOOPT;
		}
	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

static int
fi_ibv_msg_ep_setopt(fid_t fid, int level, int optname,
		  const void *optval, size_t optlen)
{
	switch (level) {
	case FI_OPT_ENDPOINT:
		return -FI_ENOPROTOOPT;
	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

static struct fi_ops_ep fi_ibv_msg_ep_base_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = fi_no_cancel,
	.getopt = fi_ibv_msg_ep_getopt,
	.setopt = fi_ibv_msg_ep_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

static struct fi_ibv_msg_ep *fi_ibv_alloc_msg_ep(struct fi_info *info)
{
	struct fi_ibv_msg_ep *ep;

	ep = calloc(1, sizeof *ep);
	if (!ep)
		return NULL;

	ep->info = fi_dupinfo(info);
	if (!ep->info)
		goto err;

	return ep;
err:
	free(ep);
	return NULL;
}

static void fi_ibv_free_msg_ep(struct fi_ibv_msg_ep *ep)
{
	fi_freeinfo(ep->info);
	free(ep);
}

static int fi_ibv_msg_ep_close(fid_t fid)
{
	struct fi_ibv_msg_ep *ep;

	ep = container_of(fid, struct fi_ibv_msg_ep, ep_fid.fid);
	rdma_destroy_ep(ep->id);

	fi_ibv_cleanup_cq(ep);

	VERBS_INFO(FI_LOG_DOMAIN, "EP %p was closed \n", ep);

	fi_ibv_free_msg_ep(ep);

	return 0;
}

static int fi_ibv_msg_ep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct fi_ibv_msg_ep *ep;
	int ret;

	ep = container_of(fid, struct fi_ibv_msg_ep, ep_fid.fid);
	ret = ofi_ep_bind_valid(&fi_ibv_prov, bfid, flags);
	if (ret)
		return ret;

	switch (bfid->fclass) {
	case FI_CLASS_CQ:
		/* Must bind a CQ to either RECV or SEND completions, and
		 * the FI_SELECTIVE_COMPLETION flag is only valid when binding the
		 * FI_SEND CQ. */
		if (!(flags & (FI_RECV|FI_SEND))
				|| (flags & (FI_SEND|FI_SELECTIVE_COMPLETION))
							== FI_SELECTIVE_COMPLETION) {
			return -EINVAL;
		}
		if (flags & FI_RECV) {
			if (ep->rcq)
				return -EINVAL;
			ep->rcq = container_of(bfid, struct fi_ibv_cq, cq_fid.fid);
		}
		if (flags & FI_SEND) {
			if (ep->scq)
				return -EINVAL;
			ep->scq = container_of(bfid, struct fi_ibv_cq, cq_fid.fid);
			if (flags & FI_SELECTIVE_COMPLETION)
				ep->ep_flags |= FI_SELECTIVE_COMPLETION;
			else
				ep->info->tx_attr->op_flags |= FI_COMPLETION;
		}
		break;
	case FI_CLASS_EQ:
		ep->eq = container_of(bfid, struct fi_ibv_eq, eq_fid.fid);
		ret = rdma_migrate_id(ep->id, ep->eq->channel);
		if (ret)
			return -errno;
		break;
	case FI_CLASS_SRX_CTX:
		ep->srq_ep = container_of(bfid, struct fi_ibv_srq_ep, ep_fid.fid);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int fi_ibv_msg_ep_enable(struct fid_ep *ep_fid)
{
	struct ibv_qp_init_attr attr = { 0 };
	struct fi_ibv_msg_ep *ep;
	struct ibv_pd *pd;
	int ret;

	ep = container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	if (!ep->eq) {
		VERBS_WARN(FI_LOG_EP_CTRL,
			   "Endpoint is not bound to an event queue\n");
		return -FI_ENOEQ;
	}

	if (!ep->scq && !ep->rcq) {
		VERBS_WARN(FI_LOG_EP_CTRL, "Endpoint is not bound to "
			   "a send or receive completion queue\n");
		return -FI_ENOCQ;
	}

	if (!ep->scq && (ofi_send_allowed(ep->info->caps) ||
				ofi_rma_initiate_allowed(ep->info->caps))) {
		VERBS_WARN(FI_LOG_EP_CTRL, "Endpoint is not bound to "
			   "a send completion queue when it has transmit "
			   "capabilities enabled (FI_SEND | FI_RMA).\n");
		return -FI_ENOCQ;
	}

	if (!ep->rcq && ofi_recv_allowed(ep->info->caps)) {
		VERBS_WARN(FI_LOG_EP_CTRL, "Endpoint is not bound to "
			   "a receive completion queue when it has receive "
			   "capabilities enabled. (FI_RECV)\n");
		return -FI_ENOCQ;
	}

	if (ep->scq) {
		attr.cap.max_send_wr = ep->info->tx_attr->size;
		attr.cap.max_send_sge = ep->info->tx_attr->iov_limit;
		attr.send_cq = ep->scq->cq;
		pd = ep->scq->domain->pd;
	} else {
		attr.send_cq = ep->rcq->cq;
		pd = ep->rcq->domain->pd;
	}

	if (ep->rcq) {
		attr.cap.max_recv_wr = ep->info->rx_attr->size;
		attr.cap.max_recv_sge = ep->info->rx_attr->iov_limit;
		attr.recv_cq = ep->rcq->cq;
	} else {
		attr.recv_cq = ep->scq->cq;
	}

	attr.cap.max_inline_data = ep->info->tx_attr->inject_size;

	if (ep->srq_ep) {
		attr.srq = ep->srq_ep->srq;
		/* Use of SRQ, no need to allocate recv_wr entries in the QP */
		attr.cap.max_recv_wr = 0;

		/* Override the default ops to prevent the user from posting WRs to a
		 * QP where a SRQ is attached to */
		ep->ep_fid.msg = &fi_ibv_msg_srq_ep_msg_ops;
	}

	attr.qp_type = IBV_QPT_RC;
	attr.sq_sig_all = 1;
	attr.qp_context = ep;

	ret = rdma_create_qp(ep->id, pd, &attr);
	if (ret) {
		ret = -errno;
		VERBS_WARN(FI_LOG_EP_CTRL, "Unable to create rdma qp: %s (%d)\n",
			   fi_strerror(-ret), -ret);
		return ret;
	}
	return 0;
}

static int fi_ibv_msg_ep_control(struct fid *fid, int command, void *arg)
{
	struct fid_ep *ep;

	switch (fid->fclass) {
	case FI_CLASS_EP:
		ep = container_of(fid, struct fid_ep, fid);
		switch (command) {
		case FI_ENABLE:
			return fi_ibv_msg_ep_enable(ep);
			break;
		default:
			return -FI_ENOSYS;
		}
		break;
	default:
		return -FI_ENOSYS;
	}
}

static struct fi_ops fi_ibv_msg_ep_ops = {
	.size = sizeof(struct fi_ops),
	.close = fi_ibv_msg_ep_close,
	.bind = fi_ibv_msg_ep_bind,
	.control = fi_ibv_msg_ep_control,
	.ops_open = fi_no_ops_open,
};

int fi_ibv_open_ep(struct fid_domain *domain, struct fi_info *info,
		   struct fid_ep **ep_fid, void *context)
{
	struct fi_ibv_domain *dom;
	struct fi_ibv_msg_ep *ep;
	struct fi_ibv_connreq *connreq;
	struct fi_ibv_pep *pep;
	struct fi_info *fi;
	int ret;

	dom = container_of(domain, struct fi_ibv_domain,
			   util_domain.domain_fid);
	if (strcmp(dom->verbs->device->name, info->domain_attr->name)) {
		VERBS_INFO(FI_LOG_DOMAIN, "Invalid info->domain_attr->name\n");
		return -FI_EINVAL;
	}

	fi = dom->info;

	if (info->ep_attr) {
		ret = fi_ibv_check_ep_attr(info, fi);
		if (ret)
			return ret;
	}

	if (info->tx_attr) {
		ret = ofi_check_tx_attr(&fi_ibv_prov, fi->tx_attr,
					info->tx_attr, info->mode);
		if (ret)
			return ret;
	}

	if (info->rx_attr) {
		ret = fi_ibv_check_rx_attr(info->rx_attr, info, fi);
		if (ret)
			return ret;
	}

	ep = fi_ibv_alloc_msg_ep(info);
	if (!ep)
		return -FI_ENOMEM;

	if (!info->handle) {
		ret = fi_ibv_create_ep(NULL, NULL, 0, info, NULL, &ep->id);
		if (ret)
			goto err1;
	} else if (info->handle->fclass == FI_CLASS_CONNREQ) {
		connreq = container_of(info->handle, struct fi_ibv_connreq, handle);
		ep->id = connreq->id;
        } else if (info->handle->fclass == FI_CLASS_PEP) {
		pep = container_of(info->handle, struct fi_ibv_pep, pep_fid.fid);
		ep->id = pep->id;
		pep->id = NULL;

		if (rdma_resolve_addr(ep->id, info->src_addr, info->dest_addr,
				      VERBS_RESOLVE_TIMEOUT)) {
			ret = -errno;
			VERBS_INFO(FI_LOG_DOMAIN, "Unable to rdma_resolve_addr\n");
			goto err2;
		}

		if (rdma_resolve_route(ep->id, VERBS_RESOLVE_TIMEOUT)) {
			ret = -errno;
			VERBS_INFO(FI_LOG_DOMAIN, "Unable to rdma_resolve_route\n");
			goto err2;
		}
	} else {
		ret = -FI_ENOSYS;
		goto err1;
	}

	ep->id->context = &ep->ep_fid.fid;
	ep->ep_fid.fid.fclass = FI_CLASS_EP;
	ep->ep_fid.fid.context = context;
	ep->ep_fid.fid.ops = &fi_ibv_msg_ep_ops;
	ep->ep_fid.ops = &fi_ibv_msg_ep_base_ops;
	ep->ep_fid.msg = &fi_ibv_msg_ep_msg_ops;
	ep->ep_fid.cm = &fi_ibv_msg_ep_cm_ops;
	ep->ep_fid.rma = &fi_ibv_msg_ep_rma_ops;
	ep->ep_fid.atomic = &fi_ibv_msg_ep_atomic_ops;

	ep->domain = dom;
	*ep_fid = &ep->ep_fid;

	return FI_SUCCESS;
err2:
	rdma_destroy_ep(ep->id);
err1:
	fi_ibv_free_msg_ep(ep);
	return ret;
}

static int fi_ibv_pep_bind(fid_t fid, struct fid *bfid, uint64_t flags)
{
	struct fi_ibv_pep *pep;
	int ret;

	pep = container_of(fid, struct fi_ibv_pep, pep_fid.fid);
	if (bfid->fclass != FI_CLASS_EQ)
		return -FI_EINVAL;

	pep->eq = container_of(bfid, struct fi_ibv_eq, eq_fid.fid);
	ret = rdma_migrate_id(pep->id, pep->eq->channel);
	if (ret)
		return -errno;

	return 0;
}

static int fi_ibv_pep_control(struct fid *fid, int command, void *arg)
{
	struct fi_ibv_pep *pep;
	int ret = 0;

	switch (fid->fclass) {
	case FI_CLASS_PEP:
		pep = container_of(fid, struct fi_ibv_pep, pep_fid.fid);
		switch (command) {
		case FI_BACKLOG:
			if (!arg)
				return -FI_EINVAL;
			pep->backlog = *(int *) arg;
			break;
		default:
			ret = -FI_ENOSYS;
			break;
		}
		break;
	default:
		ret = -FI_ENOSYS;
		break;
	}

	return ret;
}

static int fi_ibv_pep_close(fid_t fid)
{
	struct fi_ibv_pep *pep;

	pep = container_of(fid, struct fi_ibv_pep, pep_fid.fid);
	if (pep->id)
		rdma_destroy_ep(pep->id);

	fi_freeinfo(pep->info);
	free(pep);
	return 0;
}

static struct fi_ops fi_ibv_pep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = fi_ibv_pep_close,
	.bind = fi_ibv_pep_bind,
	.control = fi_ibv_pep_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_ep fi_ibv_pep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.getopt = fi_ibv_msg_ep_getopt,
	.setopt = fi_no_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

int fi_ibv_passive_ep(struct fid_fabric *fabric, struct fi_info *info,
		      struct fid_pep **pep, void *context)
{
	struct fi_ibv_pep *_pep;
	int ret;

	_pep = calloc(1, sizeof *_pep);
	if (!_pep)
		return -FI_ENOMEM;

	if (!(_pep->info = fi_dupinfo(info))) {
		ret = -FI_ENOMEM;
		goto err1;
	}

	ret = rdma_create_id(NULL, &_pep->id, &_pep->pep_fid.fid, RDMA_PS_TCP);
	if (ret) {
		VERBS_INFO(FI_LOG_DOMAIN, "Unable to create rdma_cm_id\n");
		goto err2;
	}

	if (info->src_addr) {
		ret = rdma_bind_addr(_pep->id, (struct sockaddr *)info->src_addr);
		if (ret) {
			VERBS_INFO(FI_LOG_DOMAIN, "Unable to bind address to rdma_cm_id\n");
			goto err3;
		}
		_pep->bound = 1;
	}

	_pep->pep_fid.fid.fclass = FI_CLASS_PEP;
	_pep->pep_fid.fid.context = context;
	_pep->pep_fid.fid.ops = &fi_ibv_pep_fi_ops;
	_pep->pep_fid.ops = &fi_ibv_pep_ops;
	_pep->pep_fid.cm = fi_ibv_pep_ops_cm(_pep);

	_pep->src_addrlen = info->src_addrlen;

	*pep = &_pep->pep_fid;
	return 0;

err3:
	rdma_destroy_id(_pep->id);
err2:
	fi_freeinfo(_pep->info);
err1:
	free(_pep);
	return ret;
}

static inline int fi_ibv_poll_reap_unsig_cq(struct fi_ibv_msg_ep *ep)
{
	struct fi_ibv_wce *wce;
	struct ibv_wc wc[10];
	int ret, i;

	ep->scq->cq_fastlock_acquire(&ep->scq->lock);
	/* TODO: retrieve WCs as much as possbile in a single
	 * ibv_poll_cq call */
	while (1) {
		ret = ibv_poll_cq(ep->scq->cq, 10, wc);
		if (ret <= 0) {
			ep->scq->cq_fastlock_release(&ep->scq->lock);
			return ret;
		}

		for (i = 0; i < ret; i++) {
			if (!fi_ibv_process_wc(ep->scq, &wc[i]))
				continue;
			if (OFI_LIKELY(!fi_ibv_wc_2_wce(ep->scq, &wc[i], &wce)))
				slist_insert_tail(&wce->entry, &ep->scq->wcq);
		}
	}

	ep->scq->cq_fastlock_release(&ep->scq->lock);
	return FI_SUCCESS;
}

static inline ssize_t
fi_ibv_send_poll_cq_if_needed(struct fi_ibv_msg_ep *ep, struct ibv_send_wr *wr)
{
	int ret;
	struct ibv_send_wr *bad_wr;

	ret = fi_ibv_handle_post(ibv_post_send(ep->id->qp, wr, &bad_wr));
	if (OFI_UNLIKELY(ret == -FI_EAGAIN)) {
		ret = fi_ibv_poll_reap_unsig_cq(ep);
		if (OFI_UNLIKELY(ret))
			return -FI_EAGAIN;
		/* Try again and return control to a caller */
		ret = fi_ibv_handle_post(ibv_post_send(ep->id->qp, wr, &bad_wr));
	}
	return ret;
}

/* WR must be filled out by now except for context */
static inline ssize_t
fi_ibv_send(struct fi_ibv_msg_ep *ep, struct ibv_send_wr *wr)
{
	if (wr->send_flags & IBV_SEND_SIGNALED) {
		struct ibv_send_wr *bad_wr;

		return fi_ibv_handle_post(ibv_post_send(ep->id->qp, wr, &bad_wr));
	} else {
		return fi_ibv_send_poll_cq_if_needed(ep, wr);
	}
}

static inline ssize_t
fi_ibv_send_buf(struct fi_ibv_msg_ep *ep, struct ibv_send_wr *wr,
		const void *buf, size_t len, void *desc)
{
	struct ibv_sge sge = fi_ibv_init_sge(buf, len, desc);

	wr->sg_list = &sge;
	wr->num_sge = 1;

	return fi_ibv_send(ep, wr);
}

static inline ssize_t
fi_ibv_send_buf_inline(struct fi_ibv_msg_ep *ep, struct ibv_send_wr *wr,
		       const void *buf, size_t len)
{
	struct ibv_sge sge = fi_ibv_init_sge_inline(buf, len);

	wr->sg_list = &sge;
	wr->num_sge = 1;

	return fi_ibv_send_poll_cq_if_needed(ep, wr);
}

static inline ssize_t
fi_ibv_send_iov_flags(struct fi_ibv_msg_ep *ep, struct ibv_send_wr *wr,
		      const struct iovec *iov, void **desc, int count,
		      uint64_t flags)
{
	size_t len = 0;

	if (!desc)
		fi_ibv_set_sge_iov_inline(wr->sg_list, iov, count, len);
	else
		fi_ibv_set_sge_iov(wr->sg_list, iov, count, desc, len);

	wr->num_sge = count;
	wr->send_flags = VERBS_INJECT_FLAGS(ep, len, flags) | VERBS_COMP_FLAGS(ep, flags);

	if (flags & FI_FENCE)
		wr->send_flags |= IBV_SEND_FENCE;

	return fi_ibv_send(ep, wr);
}

static ssize_t
fi_ibv_msg_ep_recvmsg(struct fid_ep *ep_fid, const struct fi_msg *msg, uint64_t flags)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_sge *sge = NULL;
	struct ibv_recv_wr wr = {
		.wr_id = (uintptr_t)msg->context,
		.num_sge = msg->iov_count,
		.next = NULL,
	};
	size_t i;
	struct ibv_recv_wr *bad_wr;

	assert(ep->rcq);

	sge = alloca(sizeof(*sge) * msg->iov_count);
	for (i = 0; i < msg->iov_count; i++) {
		sge[i].addr = (uintptr_t)msg->msg_iov[i].iov_base;
		sge[i].length = (uint32_t)msg->msg_iov[i].iov_len;
		sge[i].lkey = (uint32_t)(uintptr_t)(msg->desc[i]);
	}
	wr.sg_list = sge;

	return fi_ibv_handle_post(ibv_post_recv(ep->id->qp, &wr, &bad_wr));
}

static ssize_t
fi_ibv_msg_ep_recv(struct fid_ep *ep, void *buf, size_t len,
		void *desc, fi_addr_t src_addr, void *context)
{
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = len,
	};
	struct fi_msg msg = {
		.msg_iov = &iov,
		.desc = &desc,
		.iov_count = 1,
		.addr = src_addr,
		.context = context,
	};

	return fi_ibv_msg_ep_recvmsg(ep, &msg, 0);
}

static ssize_t
fi_ibv_msg_ep_recvv(struct fid_ep *ep, const struct iovec *iov, void **desc,
                 size_t count, fi_addr_t src_addr, void *context)
{
	struct fi_msg msg = {
		.msg_iov = iov,
		.desc = desc,
		.iov_count = count,
		.addr = src_addr,
		.context = context,
	};

	return fi_ibv_msg_ep_recvmsg(ep, &msg, 0);
}

static ssize_t
fi_ibv_msg_ep_sendmsg(struct fid_ep *ep_fid, const struct fi_msg *msg, uint64_t flags)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)msg->context,
	};

	if (flags & FI_REMOTE_CQ_DATA) {
		wr.opcode = IBV_WR_SEND_WITH_IMM;
		wr.imm_data = htonl((uint32_t)msg->data);
	} else {
		wr.opcode = IBV_WR_SEND;
	}

	return fi_ibv_send_msg(ep, &wr, msg, flags);
}

static ssize_t
fi_ibv_msg_ep_send(struct fid_ep *ep_fid, const void *buf, size_t len,
		void *desc, fi_addr_t dest_addr, void *context)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)context,
		.opcode = IBV_WR_SEND,
		.send_flags = VERBS_INJECT(ep, len) | VERBS_COMP(ep),
	};

	return fi_ibv_send_buf(ep, &wr, buf, len, desc);
}

static ssize_t
fi_ibv_msg_ep_senddata(struct fid_ep *ep_fid, const void *buf, size_t len,
		       void *desc, uint64_t data, fi_addr_t dest_addr, void *context)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)context,
		.opcode = IBV_WR_SEND_WITH_IMM,
		.imm_data = htonl((uint32_t)data),
		.send_flags = VERBS_INJECT(ep, len) | VERBS_COMP(ep),
	};

	return fi_ibv_send_buf(ep, &wr, buf, len, desc);
}

static ssize_t
fi_ibv_msg_ep_sendv(struct fid_ep *ep_fid, const struct iovec *iov, void **desc,
		    size_t count, fi_addr_t dest_addr, void *context)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)context,
		.opcode = IBV_WR_SEND,
	};

	return fi_ibv_send_iov(ep, &wr, iov, desc, count);
}

static ssize_t fi_ibv_msg_ep_inject(struct fid_ep *ep_fid, const void *buf, size_t len,
		fi_addr_t dest_addr)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.opcode = IBV_WR_SEND,
		.send_flags = IBV_SEND_INLINE,
	};

	return fi_ibv_send_buf_inline(ep, &wr, buf, len);
}

static ssize_t fi_ibv_msg_ep_injectdata(struct fid_ep *ep_fid, const void *buf, size_t len,
		    uint64_t data, fi_addr_t dest_addr)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.opcode = IBV_WR_SEND_WITH_IMM,
		.imm_data = htonl((uint32_t)data),
		.send_flags = IBV_SEND_INLINE,
	};

	return fi_ibv_send_buf_inline(ep, &wr, buf, len);
}

struct fi_ops_msg fi_ibv_msg_ep_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = fi_ibv_msg_ep_recv,
	.recvv = fi_ibv_msg_ep_recvv,
	.recvmsg = fi_ibv_msg_ep_recvmsg,
	.send = fi_ibv_msg_ep_send,
	.sendv = fi_ibv_msg_ep_sendv,
	.sendmsg = fi_ibv_msg_ep_sendmsg,
	.inject = fi_ibv_msg_ep_inject,
	.senddata = fi_ibv_msg_ep_senddata,
	.injectdata = fi_ibv_msg_ep_injectdata,
};

struct fi_ops_msg fi_ibv_msg_srq_ep_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = fi_no_msg_recv,
	.recvv = fi_no_msg_recvv,
	.recvmsg = fi_no_msg_recvmsg,
	.send = fi_ibv_msg_ep_send,
	.sendv = fi_ibv_msg_ep_sendv,
	.sendmsg = fi_ibv_msg_ep_sendmsg,
	.inject = fi_ibv_msg_ep_inject,
	.senddata = fi_ibv_msg_ep_senddata,
	.injectdata = fi_ibv_msg_ep_injectdata,
};

static struct fi_ops_ep fi_ibv_srq_ep_base_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = fi_no_cancel,
	.getopt = fi_no_getopt,
	.setopt = fi_no_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

static struct fi_ops_cm fi_ibv_srq_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.setname = fi_no_setname,
	.getname = fi_no_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = fi_no_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
	.shutdown = fi_no_shutdown,
	.join = fi_no_join,
};

static struct fi_ops_rma fi_ibv_srq_rma_ops = {
	.size = sizeof(struct fi_ops_rma),
	.read = fi_no_rma_read,
	.readv = fi_no_rma_readv,
	.readmsg = fi_no_rma_readmsg,
	.write = fi_no_rma_write,
	.writev = fi_no_rma_writev,
	.writemsg = fi_no_rma_writemsg,
	.inject = fi_no_rma_inject,
	.writedata = fi_no_rma_writedata,
	.injectdata = fi_no_rma_injectdata,
};

static struct fi_ops_atomic fi_ibv_srq_atomic_ops = {
	.size = sizeof(struct fi_ops_atomic),
	.write = fi_no_atomic_write,
	.writev = fi_no_atomic_writev,
	.writemsg = fi_no_atomic_writemsg,
	.inject = fi_no_atomic_inject,
	.readwrite = fi_no_atomic_readwrite,
	.readwritev = fi_no_atomic_readwritev,
	.readwritemsg = fi_no_atomic_readwritemsg,
	.compwrite = fi_no_atomic_compwrite,
	.compwritev = fi_no_atomic_compwritev,
	.compwritemsg = fi_no_atomic_compwritemsg,
	.writevalid = fi_no_atomic_writevalid,
	.readwritevalid = fi_no_atomic_readwritevalid,
	.compwritevalid = fi_no_atomic_compwritevalid,
};

static ssize_t
fi_ibv_srq_ep_recvmsg(struct fid_ep *ep_fid, const struct fi_msg *msg, uint64_t flags)
{
	struct fi_ibv_srq_ep *ep =
		container_of(ep_fid, struct fi_ibv_srq_ep, ep_fid);
	struct ibv_sge *sge = NULL;
	struct ibv_recv_wr wr = {
		.num_sge = msg->iov_count,
		.next = NULL,
	};
	size_t i;
	struct ibv_recv_wr *bad_wr;

	assert(ep->srq);

	wr.wr_id = (uintptr_t)msg->context;
	sge = alloca(sizeof(*sge) * msg->iov_count);
	for (i = 0; i < msg->iov_count; i++) {
		sge[i].addr = (uintptr_t)msg->msg_iov[i].iov_base;
		sge[i].length = (uint32_t)msg->msg_iov[i].iov_len;
		sge[i].lkey = (uint32_t)(uintptr_t)(msg->desc[i]);
	}
	wr.sg_list = sge;

	return fi_ibv_handle_post(ibv_post_srq_recv(ep->srq, &wr, &bad_wr));
}

static ssize_t
fi_ibv_srq_ep_recv(struct fid_ep *ep, void *buf, size_t len,
		void *desc, fi_addr_t src_addr, void *context)
{
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = len,
	};
	struct fi_msg msg = {
		.msg_iov = &iov,
		.desc = &desc,
		.iov_count = 1,
		.addr = src_addr,
		.context = context,
	};

	return fi_ibv_srq_ep_recvmsg(ep, &msg, 0);
}

static ssize_t
fi_ibv_srq_ep_recvv(struct fid_ep *ep, const struct iovec *iov, void **desc,
                 size_t count, fi_addr_t src_addr, void *context)
{
	struct fi_msg msg = {
		.msg_iov = iov,
		.desc = desc,
		.iov_count = count,
		.addr = src_addr,
		.context = context,
	};

	return fi_ibv_srq_ep_recvmsg(ep, &msg, 0);
}

static struct fi_ops_msg fi_ibv_srq_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = fi_ibv_srq_ep_recv,
	.recvv = fi_ibv_srq_ep_recvv,
	.recvmsg = fi_ibv_srq_ep_recvmsg,
	.send = fi_no_msg_send,
	.sendv = fi_no_msg_sendv,
	.sendmsg = fi_no_msg_sendmsg,
	.inject = fi_no_msg_inject,
	.senddata = fi_no_msg_senddata,
	.injectdata = fi_no_msg_injectdata,
};

static int fi_ibv_srq_close(fid_t fid)
{
	struct fi_ibv_srq_ep *srq_ep;
	int ret;

	srq_ep = container_of(fid, struct fi_ibv_srq_ep, ep_fid.fid);
	ret = ibv_destroy_srq(srq_ep->srq);
	if (ret)
		VERBS_WARN(FI_LOG_EP_CTRL,
			   "Cannot destroy SRQ rc=%d\n", ret);

	free(srq_ep);

	return FI_SUCCESS;
}

static struct fi_ops fi_ibv_srq_ep_ops = {
	.size = sizeof(struct fi_ops),
	.close = fi_ibv_srq_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

int fi_ibv_srq_context(struct fid_domain *domain, struct fi_rx_attr *attr,
		       struct fid_ep **srq_ep_fid, void *context)
{
	struct ibv_srq_init_attr srq_init_attr = { 0 };
	struct fi_ibv_domain *dom;
	struct fi_ibv_srq_ep *srq_ep;
	int ret;

	if (!domain)
		return -FI_EINVAL;

	srq_ep = calloc(1, sizeof(*srq_ep));
	if (!srq_ep) {
		ret = -FI_ENOMEM;
		goto err1;
	}

	dom = container_of(domain, struct fi_ibv_domain,
			   util_domain.domain_fid);

	srq_ep->ep_fid.fid.fclass = FI_CLASS_SRX_CTX;
	srq_ep->ep_fid.fid.context = context;
	srq_ep->ep_fid.fid.ops = &fi_ibv_srq_ep_ops;
	srq_ep->ep_fid.ops = &fi_ibv_srq_ep_base_ops;
	srq_ep->ep_fid.msg = &fi_ibv_srq_msg_ops;
	srq_ep->ep_fid.cm = &fi_ibv_srq_cm_ops;
	srq_ep->ep_fid.rma = &fi_ibv_srq_rma_ops;
	srq_ep->ep_fid.atomic = &fi_ibv_srq_atomic_ops;

	srq_init_attr.attr.max_wr = attr->size;
	srq_init_attr.attr.max_sge = attr->iov_limit;

	srq_ep->srq = ibv_create_srq(dom->pd, &srq_init_attr);
	if (!srq_ep->srq) {
		VERBS_INFO_ERRNO(FI_LOG_DOMAIN, "ibv_create_srq", errno);
		ret = -errno;
		goto err2;
	}

	*srq_ep_fid = &srq_ep->ep_fid;

	return FI_SUCCESS;
err2:
	free(srq_ep);
err1:
	return ret;
}

#define VERBS_COMP_READ_FLAGS(ep, flags) \
	((!VERBS_SELECTIVE_COMP(ep) || (flags & \
	  (FI_COMPLETION | FI_TRANSMIT_COMPLETE | FI_DELIVERY_COMPLETE))) ? \
	   IBV_SEND_SIGNALED : 0)
#define VERBS_COMP_READ(ep) \
	VERBS_COMP_READ_FLAGS(ep, ep->info->tx_attr->op_flags)

static ssize_t
fi_ibv_msg_ep_rma_write(struct fid_ep *ep_fid, const void *buf, size_t len,
		     void *desc, fi_addr_t dest_addr,
		     uint64_t addr, uint64_t key, void *context)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)context,
		.opcode = IBV_WR_RDMA_WRITE,
		.wr.rdma.remote_addr = addr,
		.wr.rdma.rkey = (uint32_t)key,
		.send_flags = VERBS_INJECT(ep, len) | VERBS_COMP(ep),
	};

	return fi_ibv_send_buf(ep, &wr, buf, len, desc);
}

static ssize_t
fi_ibv_msg_ep_rma_writev(struct fid_ep *ep_fid, const struct iovec *iov, void **desc,
		      size_t count, fi_addr_t dest_addr,
		      uint64_t addr, uint64_t key, void *context)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)context,
		.opcode = IBV_WR_RDMA_WRITE,
		.wr.rdma.remote_addr = addr,
		.wr.rdma.rkey = (uint32_t)key,
	};

	return fi_ibv_send_iov(ep, &wr, iov, desc, count);
}

static ssize_t
fi_ibv_msg_ep_rma_writemsg(struct fid_ep *ep_fid, const struct fi_msg_rma *msg,
			uint64_t flags)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)msg->context,
		.wr.rdma.remote_addr = msg->rma_iov->addr,
		.wr.rdma.rkey = (uint32_t)msg->rma_iov->key,
	};

	if (flags & FI_REMOTE_CQ_DATA) {
		wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
		wr.imm_data = htonl((uint32_t)msg->data);
	} else {
		wr.opcode = IBV_WR_RDMA_WRITE;
	}

	return fi_ibv_send_msg(ep, &wr, msg, flags);
}

static ssize_t
fi_ibv_msg_ep_rma_read(struct fid_ep *ep_fid, void *buf, size_t len,
		    void *desc, fi_addr_t src_addr,
		    uint64_t addr, uint64_t key, void *context)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)context,
		.opcode = IBV_WR_RDMA_READ,
		.wr.rdma.remote_addr = addr,
		.wr.rdma.rkey = (uint32_t)key,
		.send_flags = VERBS_COMP_READ(ep),
	};

	return fi_ibv_send_buf(ep, &wr, buf, len, desc);
}

static ssize_t
fi_ibv_msg_ep_rma_readv(struct fid_ep *ep_fid, const struct iovec *iov, void **desc,
		     size_t count, fi_addr_t src_addr,
		     uint64_t addr, uint64_t key, void *context)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)context,
		.opcode = IBV_WR_RDMA_READ,
		.wr.rdma.remote_addr = addr,
		.wr.rdma.rkey = (uint32_t)key,
		.send_flags = VERBS_COMP_READ(ep),
		.num_sge = count,
	};
	size_t len = 0;

	fi_ibv_set_sge_iov(wr.sg_list, iov, count, desc, len);

	return fi_ibv_send(ep, &wr);
}

static ssize_t
fi_ibv_msg_ep_rma_readmsg(struct fid_ep *ep_fid, const struct fi_msg_rma *msg,
			uint64_t flags)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)msg->context,
		.opcode = IBV_WR_RDMA_READ,
		.wr.rdma.remote_addr = msg->rma_iov->addr,
		.wr.rdma.rkey = (uint32_t)msg->rma_iov->key,
		.send_flags = VERBS_COMP_READ_FLAGS(ep, flags),
		.num_sge = msg->iov_count,
	};
	size_t len = 0;

	fi_ibv_set_sge_iov(wr.sg_list, msg->msg_iov, msg->iov_count, msg->desc, len);

	return fi_ibv_send(ep, &wr);
}

static ssize_t
fi_ibv_msg_ep_rma_writedata(struct fid_ep *ep_fid, const void *buf, size_t len,
			void *desc, uint64_t data, fi_addr_t dest_addr,
			uint64_t addr, uint64_t key, void *context)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)context,
		.opcode = IBV_WR_RDMA_WRITE_WITH_IMM,
		.imm_data = htonl((uint32_t)data),
		.wr.rdma.remote_addr = addr,
		.wr.rdma.rkey = (uint32_t)key,
		.send_flags = VERBS_INJECT(ep, len) | VERBS_COMP(ep),
	};

	return fi_ibv_send_buf(ep, &wr, buf, len, desc);
}

static ssize_t
fi_ibv_msg_ep_rma_inject_write(struct fid_ep *ep_fid, const void *buf, size_t len,
		     fi_addr_t dest_addr, uint64_t addr, uint64_t key)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.opcode = IBV_WR_RDMA_WRITE,
		.wr.rdma.remote_addr = addr,
		.wr.rdma.rkey = (uint32_t)key,
		.send_flags = IBV_SEND_INLINE,
	};

	return fi_ibv_send_buf_inline(ep, &wr, buf, len);
}

static ssize_t
fi_ibv_msg_ep_rma_inject_writedata(struct fid_ep *ep_fid, const void *buf, size_t len,
			uint64_t data, fi_addr_t dest_addr, uint64_t addr,
			uint64_t key)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.opcode = IBV_WR_RDMA_WRITE_WITH_IMM,
		.imm_data = htonl((uint32_t)data),
		.wr.rdma.remote_addr = addr,
		.wr.rdma.rkey = (uint32_t)key,
		.send_flags = IBV_SEND_INLINE,
	};

	return fi_ibv_send_buf_inline(ep, &wr, buf, len);
}

struct fi_ops_rma fi_ibv_msg_ep_rma_ops = {
	.size = sizeof(struct fi_ops_rma),
	.read = fi_ibv_msg_ep_rma_read,
	.readv = fi_ibv_msg_ep_rma_readv,
	.readmsg = fi_ibv_msg_ep_rma_readmsg,
	.write = fi_ibv_msg_ep_rma_write,
	.writev = fi_ibv_msg_ep_rma_writev,
	.writemsg = fi_ibv_msg_ep_rma_writemsg,
	.inject = fi_ibv_msg_ep_rma_inject_write,
	.writedata = fi_ibv_msg_ep_rma_writedata,
	.injectdata = fi_ibv_msg_ep_rma_inject_writedata,
};

#define fi_ibv_atomicvalid(name, flags)					\
static int fi_ibv_msg_ep_atomic_ ## name(struct fid_ep *ep_fid,		\
			      enum fi_datatype datatype,  		\
			      enum fi_op op, size_t *count)             \
{                                                                       \
	struct fi_ibv_msg_ep *ep = container_of(ep_fid,			\
						struct fi_ibv_msg_ep,   \
						ep_fid);                \
	struct fi_atomic_attr attr;                                     \
	int ret;                                                        \
                                                                        \
	ret = fi_ibv_query_atomic(&ep->domain->util_domain.domain_fid,	\
				  datatype, op, &attr, flags);		\
	if (!ret)                                                       \
		*count = attr.count;                                    \
	return ret;                                                     \
}                                                                       \

fi_ibv_atomicvalid(writevalid, 0);
fi_ibv_atomicvalid(readwritevalid, FI_FETCH_ATOMIC);
fi_ibv_atomicvalid(compwritevalid, FI_COMPARE_ATOMIC);

int fi_ibv_query_atomic(struct fid_domain *domain_fid, enum fi_datatype datatype,
			enum fi_op op, struct fi_atomic_attr *attr,
			uint64_t flags)
{
	struct fi_ibv_domain *domain = container_of(domain_fid,
						    struct fi_ibv_domain,
						    util_domain.domain_fid);
	char *log_str_fetch = "fi_fetch_atomic with FI_SUM op";
	char *log_str_comp = "fi_compare_atomic";
	char *log_str;

	if (flags & FI_TAGGED)
		return -FI_ENOSYS;

	if ((flags & FI_FETCH_ATOMIC) && (flags & FI_COMPARE_ATOMIC))
		return -FI_EBADFLAGS;

	if (!flags) {
		switch (op) {
		case FI_ATOMIC_WRITE:
			break;
		default:
			return -FI_ENOSYS;
		}
	} else {
		if (flags & FI_FETCH_ATOMIC) {
			switch (op) {
			case FI_ATOMIC_READ:
				goto check_datatype;
			case FI_SUM:
				log_str = log_str_fetch;
				break;
			default:
				return -FI_ENOSYS;
			}
		} else if (flags & FI_COMPARE_ATOMIC) {
			if (op != FI_CSWAP)
				return -FI_ENOSYS;
			log_str = log_str_comp;
		} else {
			return  -FI_EBADFLAGS;
		}
		if (domain->info->tx_attr->op_flags & FI_INJECT) {
			VERBS_INFO(FI_LOG_EP_DATA,
				   "FI_INJECT not supported for %s\n", log_str);
			return -FI_EINVAL;
		}
	}
check_datatype:
	switch (datatype) {
	case FI_INT64:
	case FI_UINT64:
#if __BITS_PER_LONG == 64
	case FI_DOUBLE:
	case FI_FLOAT:
#endif
		break;
	default:
		return -FI_EINVAL;
	}

	attr->size = ofi_datatype_size(datatype);
	if (attr->size == 0)
		return -FI_EINVAL;

	attr->count = 1;
	return 0;
}

static ssize_t
fi_ibv_msg_ep_atomic_write(struct fid_ep *ep_fid, const void *buf, size_t count,
			void *desc, fi_addr_t dest_addr, uint64_t addr, uint64_t key,
			enum fi_datatype datatype, enum fi_op op, void *context)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)context,
		.opcode = IBV_WR_RDMA_WRITE,
		.wr.rdma.remote_addr = addr,
		.wr.rdma.rkey = (uint32_t)(uintptr_t)key,
		.send_flags = VERBS_INJECT(ep, sizeof(uint64_t)) |
			      VERBS_COMP(ep) | IBV_SEND_FENCE,
	};
	size_t count_copy;
	int ret;

	if (OFI_UNLIKELY(count != 1))
		return -FI_E2BIG;

	if (OFI_UNLIKELY(op != FI_ATOMIC_WRITE))
		return -FI_ENOSYS;

	count_copy = count;

	ret = fi_ibv_msg_ep_atomic_writevalid(ep_fid, datatype, op, &count_copy);
	if (ret)
		return ret;

	return fi_ibv_send_buf(ep, &wr, buf, sizeof(uint64_t), desc);
}

static ssize_t
fi_ibv_msg_ep_atomic_writev(struct fid_ep *ep,
                        const struct fi_ioc *iov, void **desc, size_t count,
                        fi_addr_t dest_addr, uint64_t addr, uint64_t key,
                        enum fi_datatype datatype, enum fi_op op, void *context)
{
	if (OFI_UNLIKELY(iov->count != 1))
		return -FI_E2BIG;

	return fi_ibv_msg_ep_atomic_write(ep, iov->addr, count, desc[0],
			dest_addr, addr, key, datatype, op, context);
}

static ssize_t
fi_ibv_msg_ep_atomic_writemsg(struct fid_ep *ep_fid,
                        const struct fi_msg_atomic *msg, uint64_t flags)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)msg->context,
		.wr.rdma.remote_addr = msg->rma_iov->addr,
		.wr.rdma.rkey = (uint32_t)(uintptr_t)msg->rma_iov->key,
		.send_flags = VERBS_INJECT_FLAGS(ep, sizeof(uint64_t), flags) |
			      VERBS_COMP_FLAGS(ep, flags) | IBV_SEND_FENCE,
	};
	size_t count_copy;
	int ret;

	if (OFI_UNLIKELY(msg->iov_count != 1 || msg->msg_iov->count != 1))
		return -FI_E2BIG;

	if (OFI_UNLIKELY(msg->op != FI_ATOMIC_WRITE))
		return -FI_ENOSYS;

	count_copy = msg->iov_count;

	ret = fi_ibv_msg_ep_atomic_writevalid(ep_fid, msg->datatype, msg->op,
			&count_copy);
	if (ret)
		return ret;

	if (flags & FI_REMOTE_CQ_DATA) {
		wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
		wr.imm_data = htonl((uint32_t)msg->data);
	} else {
		wr.opcode = IBV_WR_RDMA_WRITE;
	}

	return fi_ibv_send_buf(ep, &wr, msg->msg_iov->addr, sizeof(uint64_t),
			msg->desc[0]);
}

static ssize_t
fi_ibv_msg_ep_atomic_readwrite(struct fid_ep *ep_fid, const void *buf, size_t count,
			void *desc, void *result, void *result_desc,
			fi_addr_t dest_addr, uint64_t addr, uint64_t key,
			enum fi_datatype datatype,
			enum fi_op op, void *context)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)context,
		.send_flags = VERBS_COMP(ep) | IBV_SEND_FENCE,
	};
	size_t count_copy;
	int ret;

	if (OFI_UNLIKELY(count != 1))
		return -FI_E2BIG;

	count_copy = count;

	ret = fi_ibv_msg_ep_atomic_readwritevalid(ep_fid, datatype, op,
			&count_copy);
	if (ret)
		return ret;

	switch (op) {
	case FI_ATOMIC_READ:
		wr.opcode = IBV_WR_RDMA_READ;
		wr.wr.rdma.remote_addr = addr;
		wr.wr.rdma.rkey = (uint32_t)(uintptr_t)key;
		break;
	case FI_SUM:
		wr.opcode = IBV_WR_ATOMIC_FETCH_AND_ADD;
		wr.wr.atomic.remote_addr = addr;
		wr.wr.atomic.compare_add = (uintptr_t)buf;
		wr.wr.atomic.swap = 0;
		wr.wr.atomic.rkey = (uint32_t)(uintptr_t)key;
		break;
	default:
		return -FI_ENOSYS;
	}

	return fi_ibv_send_buf(ep, &wr, result, sizeof(uint64_t), result_desc);
}

static ssize_t
fi_ibv_msg_ep_atomic_readwritev(struct fid_ep *ep, const struct fi_ioc *iov,
			void **desc, size_t count,
			struct fi_ioc *resultv, void **result_desc,
			size_t result_count, fi_addr_t dest_addr, uint64_t addr,
			uint64_t key, enum fi_datatype datatype,
			enum fi_op op, void *context)
{
	if (OFI_UNLIKELY(iov->count != 1))
		return -FI_E2BIG;

        return fi_ibv_msg_ep_atomic_readwrite(ep, iov->addr, count,
			desc[0], resultv->addr, result_desc[0],
			dest_addr, addr, key, datatype, op, context);
}

static ssize_t
fi_ibv_msg_ep_atomic_readwritemsg(struct fid_ep *ep_fid,
				const struct fi_msg_atomic *msg,
				struct fi_ioc *resultv, void **result_desc,
				size_t result_count, uint64_t flags)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)msg->context,
		.send_flags = VERBS_COMP_FLAGS(ep, flags) | IBV_SEND_FENCE,
	};
	size_t count_copy;
	int ret;

	if (OFI_UNLIKELY(msg->iov_count != 1 || msg->msg_iov->count != 1))
		return -FI_E2BIG;

	count_copy = msg->iov_count;

	ret = fi_ibv_msg_ep_atomic_readwritevalid(ep_fid, msg->datatype, msg->op,
		       &count_copy);
	if (ret)
		return ret;

	switch (msg->op) {
	case FI_ATOMIC_READ:
		wr.opcode = IBV_WR_RDMA_READ;
		wr.wr.rdma.remote_addr = msg->rma_iov->addr;
		wr.wr.rdma.rkey = (uint32_t) (uintptr_t) msg->rma_iov->key;
		break;
	case FI_SUM:
		wr.opcode = IBV_WR_ATOMIC_FETCH_AND_ADD;
		wr.wr.atomic.remote_addr = msg->rma_iov->addr;
		wr.wr.atomic.compare_add = (uintptr_t) msg->addr;
		wr.wr.atomic.swap = 0;
		wr.wr.atomic.rkey = (uint32_t) (uintptr_t) msg->rma_iov->key;
		break;
	default:
		return -FI_ENOSYS;
	}

	if (flags & FI_REMOTE_CQ_DATA)
		wr.imm_data = htonl((uint32_t) msg->data);

	return fi_ibv_send_buf(ep, &wr, resultv->addr,
			       sizeof(uint64_t), result_desc[0]);
}

static ssize_t
fi_ibv_msg_ep_atomic_compwrite(struct fid_ep *ep_fid, const void *buf, size_t count,
			void *desc, const void *compare,
			void *compare_desc, void *result,
			void *result_desc,
			fi_addr_t dest_addr, uint64_t addr, uint64_t key,
			enum fi_datatype datatype,
			enum fi_op op, void *context)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)context,
		.opcode = IBV_WR_ATOMIC_CMP_AND_SWP,
		.wr.atomic.remote_addr = addr,
		.wr.atomic.compare_add = (uintptr_t)compare,
		.wr.atomic.swap = (uintptr_t)buf,
		.wr.atomic.rkey = (uint32_t)(uintptr_t)key,
		.send_flags = VERBS_COMP(ep) | IBV_SEND_FENCE,
	};
	size_t count_copy;
	int ret;

	if (OFI_UNLIKELY(count != 1))
		return -FI_E2BIG;

	count_copy = count;

	ret = fi_ibv_msg_ep_atomic_compwritevalid(ep_fid, datatype, op, &count_copy);
	if (ret)
		return ret;

	return fi_ibv_send_buf(ep, &wr, result, sizeof(uint64_t), result_desc);
}

static ssize_t
fi_ibv_msg_ep_atomic_compwritev(struct fid_ep *ep, const struct fi_ioc *iov,
				void **desc, size_t count,
				const struct fi_ioc *comparev,
				void **compare_desc, size_t compare_count,
				struct fi_ioc *resultv, void **result_desc,
				size_t result_count,
				fi_addr_t dest_addr, uint64_t addr, uint64_t key,
				enum fi_datatype datatype,
				enum fi_op op, void *context)
{
	if (OFI_UNLIKELY(iov->count != 1))
		return -FI_E2BIG;

	return fi_ibv_msg_ep_atomic_compwrite(ep, iov->addr, count, desc[0],
				comparev->addr, compare_desc[0], resultv->addr,
				result_desc[0], dest_addr, addr, key,
                        	datatype, op, context);
}

static ssize_t
fi_ibv_msg_ep_atomic_compwritemsg(struct fid_ep *ep_fid,
				const struct fi_msg_atomic *msg,
				const struct fi_ioc *comparev,
				void **compare_desc, size_t compare_count,
				struct fi_ioc *resultv,
				void **result_desc, size_t result_count,
				uint64_t flags)
{
	struct fi_ibv_msg_ep *ep =
		container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	struct ibv_send_wr wr = {
		.wr_id = (uintptr_t)msg->context,
		.opcode = IBV_WR_ATOMIC_CMP_AND_SWP,
		.wr.atomic.remote_addr = msg->rma_iov->addr,
		.wr.atomic.compare_add = (uintptr_t)comparev->addr,
		.wr.atomic.swap = (uintptr_t)msg->addr,
		.wr.atomic.rkey = (uint32_t)(uintptr_t)msg->rma_iov->key,
		.send_flags = VERBS_COMP_FLAGS(ep, flags) | IBV_SEND_FENCE,
	};
	size_t count_copy;
	int ret;

	if (OFI_UNLIKELY(msg->iov_count != 1 || msg->msg_iov->count != 1))
		return -FI_E2BIG;

	count_copy = msg->iov_count;

	ret = fi_ibv_msg_ep_atomic_compwritevalid(ep_fid, msg->datatype, msg->op,
		       &count_copy);
	if (ret)
		return ret;

	if (flags & FI_REMOTE_CQ_DATA)
		wr.imm_data = htonl((uint32_t) msg->data);

	return fi_ibv_send_buf(ep, &wr, resultv->addr, sizeof(uint64_t),
			result_desc[0]);
}

struct fi_ops_atomic fi_ibv_msg_ep_atomic_ops = {
	.size		= sizeof(struct fi_ops_atomic),
	.write		= fi_ibv_msg_ep_atomic_write,
	.writev		= fi_ibv_msg_ep_atomic_writev,
	.writemsg	= fi_ibv_msg_ep_atomic_writemsg,
	.inject		= fi_no_atomic_inject,
	.readwrite	= fi_ibv_msg_ep_atomic_readwrite,
	.readwritev	= fi_ibv_msg_ep_atomic_readwritev,
	.readwritemsg	= fi_ibv_msg_ep_atomic_readwritemsg,
	.compwrite	= fi_ibv_msg_ep_atomic_compwrite,
	.compwritev	= fi_ibv_msg_ep_atomic_compwritev,
	.compwritemsg	= fi_ibv_msg_ep_atomic_compwritemsg,
	.writevalid	= fi_ibv_msg_ep_atomic_writevalid,
	.readwritevalid	= fi_ibv_msg_ep_atomic_readwritevalid,
	.compwritevalid = fi_ibv_msg_ep_atomic_compwritevalid
};
