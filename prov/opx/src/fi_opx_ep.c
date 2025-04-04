/*
 * Copyright (C) 2016 by Argonne National Laboratory.
 * Copyright (C) 2021-2025 Cornelis Networks.
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
#include "rdma/fabric.h"

#include <ofi.h>

#include "rdma/opx/fi_opx_domain.h"
#include "rdma/opx/fi_opx_endpoint.h"
#include "rdma/opx/fi_opx_eq.h"
#include "rdma/opx/fi_opx.h"
#include "rdma/opx/fi_opx_rma.h"
#include "rdma/opx/fi_opx_hfi1.h"
#include "rdma/opx/fi_opx_hfi1_sdma.h"
#include "rdma/opx/fi_opx_match.h"

#include <ofi_enosys.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <sys/utsname.h>

#include "rdma/opx/fi_opx_fabric.h"

#define FI_OPX_EP_RX_UEPKT_BLOCKSIZE (256)
#define FI_OPX_VER_CHECK_BUF_LEN     (512)
#define OPX_EP_RX_CTX_BLOCKSIZE	     (2048)
#define OPX_MODINFO_PATH	     "/sbin/modinfo"
#define OPX_MODINFO_DRV_VERS	     OPX_MODINFO_PATH " hfi1 -F version"
#define OPX_MODINFO_SRC_VERS	     OPX_MODINFO_PATH " hfi1 -F srcversion"

#define OPX_TID_ENABLE_ON  1
#define OPX_TID_ENABLE_OFF 0

enum ofi_reliability_kind fi_opx_select_reliability(struct fi_opx_ep *opx_ep)
{
#if defined(OFI_RELIABILITY_CONFIG_STATIC_NONE)
	if (opx_ep->type == FI_EP_RDM) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Endpoint type not supported (%u)\n", opx_ep->type);
		abort();
	} else {
		return OFI_RELIABILITY_KIND_NONE;
	}

#elif defined(OFI_RELIABILITY_CONFIG_STATIC_OFFLOAD)
	if (opx_ep->type == FI_EP_DGRAM) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Endpoint type not supported (%u)\n", opx_ep->type);
		abort();
	} else if (opx_domain->reliability_kind != OFI_RELIABILITY_KIND_OFFLOAD) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Endpoint reliability does not match domain reliability\n");
		abort();
	} else {
		return OFI_RELIABILITY_KIND_OFFLOAD;
	}

#elif defined(OFI_RELIABILITY_CONFIG_STATIC_ONLOAD)
	if (opx_ep->type == FI_EP_DGRAM) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Endpoint type not supported (%u)\n", opx_ep->type);
		abort();
	} else if (opx_domain->reliability_kind != OFI_RELIABILITY_KIND_ONLOAD) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Endpoint reliability does not match domain reliability\n");
		abort();
	} else {
		return OFI_RELIABILITY_KIND_OFFLOAD;
	}

#else
	switch (opx_ep->type) {
	case FI_EP_RDM: {
		struct fi_opx_domain *opx_domain = opx_ep->domain;
		return opx_domain->reliability_kind;
	} break;
	case FI_EP_DGRAM:
		return OFI_RELIABILITY_KIND_NONE;
		break;
	default:
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Endpoint type not supported (%u)\n", opx_ep->type);
		abort();
		break;
	}
#endif
}

ssize_t fi_opx_ep_tx_connect(struct fi_opx_ep *opx_ep, size_t count, union fi_opx_addr *peers,
			     struct fi_opx_extended_addr *peers_ext);

__OPX_FORCE_INLINE__
enum ofi_reliability_app_kind fi_opx_select_app_reliability(struct fi_opx_ep *opx_ep)
{
	return ((opx_ep->common_info && opx_ep->common_info->src_addr &&
		 ((union fi_opx_addr *) (opx_ep->common_info->src_addr))->hfi1_unit != opx_default_addr.hfi1_unit) ?
			OFI_RELIABILITY_APP_KIND_DAOS :
			OFI_RELIABILITY_APP_KIND_MPI);
}

static int fi_opx_close_stx_nofree(struct fi_opx_stx *opx_stx)
{
	int ret;

	ret = fi_opx_ref_finalize(&opx_stx->ref_cnt, "shared context");
	if (ret) {
		return ret;
	}

	fi_opx_reliability_client_fini(&opx_stx->reliability_state);

	ret = fi_opx_ref_dec(&opx_stx->domain->ref_cnt, "domain");
	if (ret) {
		return ret;
	}

	return 0;
}

static int fi_opx_close_stx(fid_t fid)
{
	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "close stx\n");

	int ret;
	ret = fi_opx_fid_check(fid, FI_CLASS_STX_CTX, "shared context");
	if (ret) {
		return ret;
	}

	struct fi_opx_stx *opx_stx = container_of(fid, struct fi_opx_stx, stx_fid);

	ret = fi_opx_close_stx_nofree(opx_stx);
	if (ret) {
		return ret;
	}

	free(opx_stx);
	// opx_stx (the object passed in as fid) is now unusable

	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "stx closed\n");
	return 0;
}

int fi_opx_bind_ep_stx(struct fid_ep *ep, struct fid_stx *stx, uint64_t flags)
{
	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "bind stx to ep\n");

	if (!ep || !stx) {
		goto err;
	}

	struct fi_opx_ep  *opx_ep  = container_of(ep, struct fi_opx_ep, ep_fid);
	struct fi_opx_stx *opx_stx = container_of(stx, struct fi_opx_stx, stx_fid);

	opx_ep->tx->stx = opx_stx;

	fi_opx_ref_inc(&opx_stx->ref_cnt, "shared context");

	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "stx bound to ep\n");
	return 0;

err:
	return -errno;
}

static struct fi_ops fi_opx_stx_ops = {.size	 = sizeof(struct fi_ops),
				       .close	 = fi_opx_close_stx,
				       .bind	 = fi_no_bind,
				       .control	 = fi_no_control,
				       .ops_open = fi_no_ops_open};

static struct fi_ops_ep fi_opx_stx_ep_ops = {.size   = sizeof(struct fi_ops_ep),
					     .cancel = fi_no_cancel,
					     .getopt = fi_no_getopt,
					     .setopt = fi_no_setopt,
					     .tx_ctx = fi_no_tx_ctx,
					     .rx_ctx = fi_no_rx_ctx};

void fi_opx_ep_tx_model_init(struct fi_opx_hfi1_context *hfi, struct fi_opx_hfi1_txe_scb_9B *inject_9B,
			     struct fi_opx_hfi1_txe_scb_9B *send_9B, struct fi_opx_hfi1_txe_scb_9B *send_mp_9B,
			     struct fi_opx_hfi1_txe_scb_9B *rendezvous_9B)
{
	/*
	 * fi_send*() model - eager
	 */
	/* Setup the 9B models whether or not they'll be used */
	enum opx_hfi1_type __attribute__((unused)) hfi1_type =
		(OPX_HFI1_TYPE & OPX_HFI1_WFR) ? OPX_HFI1_WFR : OPX_HFI1_JKR_9B;
	/* PBC data */
	memset(send_9B, 0, sizeof(*send_9B));

	/* Eager model */
	send_9B->qw0 = OPX_PBC_LEN(0, hfi1_type) /* length_dws */ | OPX_PBC_VL(hfi->vl, hfi1_type) |
		       OPX_PBC_SC(hfi->sc, hfi1_type) | OPX_PBC_L2TYPE(OPX_PBC_JKR_L2TYPE_9B, hfi1_type) |
		       OPX_PBC_L2COMPRESSED(0, hfi1_type) | OPX_PBC_PORTIDX(hfi->hfi_port, hfi1_type) |
		       OPX_PBC_SCTXT(hfi->send_ctxt, hfi1_type);

	/* LRH header */
	send_9B->hdr.lrh_9B.flags =
		htons(FI_OPX_HFI1_LRH_BTH | ((hfi->sl & FI_OPX_HFI1_LRH_SL_MASK) << FI_OPX_HFI1_LRH_SL_SHIFT) |
		      ((hfi->sc & FI_OPX_HFI1_LRH_SC_MASK) << FI_OPX_HFI1_LRH_SC_SHIFT));

	send_9B->hdr.lrh_9B.dlid   = 0; /* set at runtime */
	send_9B->hdr.lrh_9B.pktlen = 0; /* set at runtime */
	send_9B->hdr.lrh_9B.slid   = __cpu24_to_be16((opx_lid_t) hfi->lid);

	/* BTH header */
	send_9B->hdr.bth.opcode = 0;
	send_9B->hdr.bth.bth_1	= 0;
	send_9B->hdr.bth.pkey	= htons(hfi->pkey);
	send_9B->hdr.bth.ecn	= (uint8_t) ((OPX_BTH_RC2_VAL(hfi1_type, OPX_HFI1_EAGER)) |
					     OPX_BTH_CSPEC(OPX_BTH_CSPEC_DEFAULT, hfi1_type));
	send_9B->hdr.bth.qp	= hfi->bthqp;
	send_9B->hdr.bth.unused = 0;
	send_9B->hdr.bth.rx	= 0; /* set at runtime */

	send_9B->hdr.reliability.psn	   = 0;
	send_9B->hdr.reliability.origin_rx = hfi->info.rxe.id;

	/* KDETH header */
	send_9B->hdr.kdeth.offset_ver_tid = FI_OPX_HFI1_KDETH_VERSION << FI_OPX_HFI1_KDETH_VERSION_SHIFT; /* no flags */
	send_9B->hdr.kdeth.jkey		  = hfi->jkey;
	send_9B->hdr.kdeth.hcrc		  = 0;
	send_9B->hdr.kdeth.unused	  = 0;

	/* OFI header */
	send_9B->hdr.match.ofi_data = 0; /* set at runtime */
	send_9B->hdr.match.ofi_tag  = 0; /* set at runtime */

	OPX_DEBUG_PRINT_HDR((&(send_9B->hdr)), hfi1_type);

	/* MP Eager model */
	*send_mp_9B		= *send_9B;
	send_mp_9B->hdr.bth.ecn = (uint8_t) ((OPX_BTH_RC2_VAL(hfi1_type, OPX_HFI1_MP_EAGER)) |
					     OPX_BTH_CSPEC(OPX_BTH_CSPEC_DEFAULT, hfi1_type));

	OPX_DEBUG_PRINT_HDR((&(send_mp_9B->hdr)), hfi1_type);
	/*
	 * fi_send*() model - rendezvous
	 */
	*rendezvous_9B		   = *send_9B;
	rendezvous_9B->hdr.bth.ecn = (uint8_t) ((OPX_BTH_RC2_VAL(hfi1_type, OPX_HFI1_RZV_CTRL)) |
						OPX_BTH_CSPEC(OPX_BTH_CSPEC_DEFAULT, hfi1_type));

	OPX_DEBUG_PRINT_HDR((&(rendezvous_9B->hdr)), hfi1_type);

	/* clone from send model, then adjust */
	*inject_9B = *send_9B;

	/*
	 * fi_inject() model
	 */
	const uint32_t inject_pbc_dws = 2 + /* pbc */
					2 + /* lhr */
					3 + /* bth */
					9;  /* kdeth; from "RcvHdrSize[i].HdrSize" CSR */

	inject_9B->qw0 = OPX_PBC_LEN(inject_pbc_dws, hfi1_type) /* length_dws */ | OPX_PBC_VL(hfi->vl, hfi1_type) |
			 OPX_PBC_SC(hfi->sc, hfi1_type) | OPX_PBC_L2TYPE(OPX_PBC_JKR_L2TYPE_9B, hfi1_type) |
			 OPX_PBC_L2COMPRESSED(0, hfi1_type) | OPX_PBC_PORTIDX(hfi->hfi_port, hfi1_type) |
			 OPX_PBC_SCTXT(hfi->send_ctxt, hfi1_type);

	inject_9B->hdr.lrh_9B.pktlen =
		htons(inject_pbc_dws - 2 +
		      1); /* (BE: LRH DW) does not include pbc (8 bytes), but does include icrc (4 bytes) */

	/* specified at runtime */
	inject_9B->hdr.inject.message_length  = 0;
	inject_9B->hdr.inject.app_data_u64[0] = 0;
	inject_9B->hdr.inject.app_data_u64[1] = 0;
	inject_9B->hdr.bth.ecn		      = (uint8_t) ((OPX_BTH_RC2_VAL(hfi1_type, OPX_HFI1_INJECT)) |
						   OPX_BTH_CSPEC(OPX_BTH_CSPEC_DEFAULT, hfi1_type));

	OPX_DEBUG_PRINT_HDR((&(inject_9B->hdr)), hfi1_type);
}

void fi_opx_ep_tx_model_init_16B(struct fi_opx_hfi1_context *hfi, struct fi_opx_hfi1_txe_scb_16B *inject_16B,
				 struct fi_opx_hfi1_txe_scb_16B *send_16B, struct fi_opx_hfi1_txe_scb_16B *send_mp_16B,
				 struct fi_opx_hfi1_txe_scb_16B *rendezvous_16B)
{
	/*
	 * fi_send*() model - eager
	 */
	/* Setup the 16B models whether or not they'll be used */
	enum opx_hfi1_type __attribute__((unused)) hfi1_type = OPX_HFI1_JKR;

	/* PBC data */
	memset(send_16B, 0, sizeof(*send_16B));
	memset(send_mp_16B, 0, sizeof(*send_mp_16B));
	memset(inject_16B, 0, sizeof(*inject_16B));
	memset(rendezvous_16B, 0, sizeof(*rendezvous_16B));

	/* Eager model */
	send_16B->qw0 = OPX_PBC_LEN(0, hfi1_type) /* length_dws */ | OPX_PBC_VL(hfi->vl, hfi1_type) |
			OPX_PBC_SC(hfi->sc, hfi1_type) | OPX_PBC_L2TYPE(OPX_PBC_JKR_L2TYPE_16B, hfi1_type) |
			OPX_PBC_L2COMPRESSED(0, hfi1_type) | OPX_PBC_PORTIDX(hfi->hfi_port, hfi1_type) |
			OPX_PBC_SCTXT(hfi->send_ctxt, hfi1_type) | OPX_PBC_JKR_INSERT_NON9B_ICRC;

	/* LRH header */
	/* static assert here because these are in different headers */
	static_assert(OPX_BTH_RX_SHIFT >= OPX_LRH_JKR_ENTROPY_SHIFT_16B,
		      "OPX_BTH_RX_SHIFT must be >= OPX_LRH_JKR_ENTROPY_SHIFT_16B!\n");

	send_16B->hdr.lrh_16B.qw[0] = 0UL;
	send_16B->hdr.lrh_16B.qw[1] = 0UL;

	send_16B->hdr.lrh_16B.sc      = hfi->sc;
	send_16B->hdr.lrh_16B.entropy = hfi->ctrl->ctxt_info.send_ctxt;
	send_16B->hdr.lrh_16B.lt      = 0; // need to add env variable to change
	send_16B->hdr.lrh_16B.l2      = OPX_PBC_JKR_L2TYPE_16B;
	send_16B->hdr.lrh_16B.l4      = 9;
	send_16B->hdr.lrh_16B.rc      = OPX_LRH_JKR_16B_RC(OPX_HFI1_EAGER);
	send_16B->hdr.lrh_16B.cspec   = OPX_BTH_CSPEC_DEFAULT; /*NOT BTH CSPEC*/
	send_16B->hdr.lrh_16B.pkey    = hfi->pkey;

	send_16B->hdr.lrh_16B.slid   = hfi->lid & 0xFFFFF;
	send_16B->hdr.lrh_16B.slid20 = (hfi->lid) >> 20;

	/* BTH header */
	send_16B->hdr.bth.opcode = 0;
	send_16B->hdr.bth.bth_1	 = 0;
	send_16B->hdr.bth.pkey	 = htons(hfi->pkey);
	send_16B->hdr.bth.ecn	 = (uint8_t) ((OPX_BTH_RC2_VAL(hfi1_type, OPX_HFI1_EAGER)) |
					      OPX_BTH_CSPEC(OPX_BTH_CSPEC_DEFAULT, hfi1_type));
	send_16B->hdr.bth.qp	 = hfi->bthqp;
	send_16B->hdr.bth.unused = 0;
	send_16B->hdr.bth.rx	 = 0; /* set at runtime */

	send_16B->hdr.reliability.psn	    = 0;
	send_16B->hdr.reliability.origin_rx = hfi->info.rxe.id;

	/* KDETH header */
	send_16B->hdr.kdeth.offset_ver_tid = FI_OPX_HFI1_KDETH_VERSION
					     << FI_OPX_HFI1_KDETH_VERSION_SHIFT; /* no flags */
	send_16B->hdr.kdeth.jkey   = hfi->jkey;
	send_16B->hdr.kdeth.hcrc   = 0;
	send_16B->hdr.kdeth.unused = 0;

	/* OFI header */
	send_16B->hdr.match.ofi_data = 0; /* set at runtime */
	send_16B->hdr.match.ofi_tag  = 0; /* set at runtime */

	OPX_DEBUG_PRINT_HDR((&(send_16B->hdr)), hfi1_type);

	/* MP Eager model */
	*send_mp_16B		    = *send_16B;
	send_mp_16B->hdr.lrh_16B.rc = OPX_LRH_JKR_16B_RC(OPX_HFI1_MP_EAGER);
	send_mp_16B->hdr.bth.ecn    = (uint8_t) ((OPX_BTH_RC2_VAL(hfi1_type, OPX_HFI1_MP_EAGER)) |
						 OPX_BTH_CSPEC(OPX_BTH_CSPEC_DEFAULT, hfi1_type));

	OPX_DEBUG_PRINT_HDR((&(send_mp_16B->hdr)), hfi1_type);

	/*
	 * fi_send*() model - rendezvous
	 */
	*rendezvous_16B		       = *send_16B;
	rendezvous_16B->hdr.lrh_16B.rc = OPX_LRH_JKR_16B_RC(OPX_HFI1_RZV_CTRL);
	rendezvous_16B->hdr.bth.ecn    = (uint8_t) ((OPX_BTH_RC2_VAL(hfi1_type, OPX_HFI1_RZV_CTRL)) |
						    OPX_BTH_CSPEC(OPX_BTH_CSPEC_DEFAULT, hfi1_type));

	OPX_DEBUG_PRINT_HDR((&(rendezvous_16B->hdr)), hfi1_type);

	/*
	 * fi_inject() model
	 */

	/* clone from send model, then adjust */
	*inject_16B = *send_16B;

	const uint64_t pbc_dws = 2 + /* pbc */
				 4 + /* lrh uncompressed */
				 3 + /* bth */
				 9 + /* kdeth; from "RcvHdrSize[i].HdrSize" CSR */
				 2;  /* ICRC/tail */

	inject_16B->qw0 = OPX_PBC_LEN(pbc_dws, hfi1_type) /* length_dws */ | OPX_PBC_VL(hfi->vl, hfi1_type) |
			  OPX_PBC_SC(hfi->sc, hfi1_type) | OPX_PBC_L2TYPE(OPX_PBC_JKR_L2TYPE_16B, hfi1_type) |
			  OPX_PBC_L2COMPRESSED(0, hfi1_type) | OPX_PBC_PORTIDX(hfi->hfi_port, hfi1_type) |
			  OPX_PBC_SCTXT(hfi->send_ctxt, hfi1_type) | OPX_PBC_JKR_INSERT_NON9B_ICRC;

	/* (LRH QW) does not include pbc (8 bytes) */
	const uint32_t packetLength = (pbc_dws - 2) * 4;
	const uint32_t lrh_qws	    = (packetLength >> 3) + ((packetLength & 0x07u) != 0);

	inject_16B->hdr.lrh_16B.pktlen = lrh_qws;

	/* specified at runtime */
	inject_16B->hdr.inject.message_length  = 0;
	inject_16B->hdr.inject.app_data_u64[0] = 0;

	inject_16B->hdr.lrh_16B.rc = OPX_LRH_JKR_16B_RC(OPX_HFI1_INJECT);
	inject_16B->hdr.bth.ecn	   = (uint8_t) ((OPX_BTH_RC2_VAL(hfi1_type, OPX_HFI1_INJECT)) |
						OPX_BTH_CSPEC(OPX_BTH_CSPEC_DEFAULT, hfi1_type));

	OPX_DEBUG_PRINT_HDR((&(inject_16B->hdr)), hfi1_type);
}

int fi_opx_stx_init(struct fi_opx_domain *opx_domain, struct fi_tx_attr *attr, struct fi_opx_stx *opx_stx,
		    void *context)
{
	opx_stx->stx_fid.fid.fclass  = FI_CLASS_STX_CTX;
	opx_stx->stx_fid.fid.context = context;
	opx_stx->stx_fid.fid.ops     = &fi_opx_stx_ops;
	opx_stx->stx_fid.ops	     = &fi_opx_stx_ep_ops;

	opx_stx->domain = opx_domain;

	if (fi_opx_global.default_tx_attr == NULL) {
		if (fi_opx_alloc_default_tx_attr(&fi_opx_global.default_tx_attr)) {
			FI_DBG(fi_opx_global.prov, FI_LOG_DOMAIN,
			       "alloc function could not allocate block of memory\n");
			return -FI_ENOMEM;
		}
	}

	opx_stx->attr = attr ? *attr : *fi_opx_global.default_tx_attr;

	/*
	 * open the hfi1 context, determines JKR or WFR
	 */
	opx_stx->hfi = fi_opx_hfi1_context_open(NULL, opx_domain->unique_job_key);
	if (!opx_stx->hfi) {
		return FI_EBUSY;
	}
	FI_INFO(fi_opx_global.prov, FI_LOG_EP_DATA,
		"Opened hfi %p, HFI type %#X/%#X, unit %#X, port %#X, ref_cnt %#lX, rcv ctxt %#X, send ctxt %#X, \n",
		opx_stx->hfi, opx_stx->hfi->hfi1_type, OPX_HFI1_TYPE, opx_stx->hfi->hfi_unit, opx_stx->hfi->hfi_port,
		opx_stx->hfi->ref_cnt, opx_stx->hfi->ctrl->ctxt_info.ctxt, opx_stx->hfi->ctrl->ctxt_info.send_ctxt);

	/*
	 * initialize the reliability service
	 */
	fi_opx_reliability_client_init(&opx_stx->reliability_state, &opx_stx->reliability_service,
				       opx_stx->hfi->info.rxe.id, /* rx */
				       fi_opx_ep_rx_reliability_process_packet);

	/*
	 * initialize the models
	 */
	struct fi_opx_hfi1_txe_scb_9B dummy; /* no MP eager model*/
	fi_opx_ep_tx_model_init(opx_stx->hfi, &opx_stx->tx.inject, &opx_stx->tx.send, &dummy, &opx_stx->tx.rzv);

	struct fi_opx_hfi1_txe_scb_16B dummy_16B; /* no MP eager model*/
	fi_opx_ep_tx_model_init_16B(opx_stx->hfi, &opx_stx->tx.inject_16B, &opx_stx->tx.send_16B, &dummy_16B,
				    &opx_stx->tx.rzv_16B);

	fi_opx_ref_inc(&opx_domain->ref_cnt, "domain");
	fi_opx_ref_init(&opx_stx->ref_cnt, "shared transmit context");

	return FI_SUCCESS;
}

int fi_opx_stx_context(struct fid_domain *domain, struct fi_tx_attr *attr, struct fid_stx **stx, void *context)
{
	int ret;
	errno				 = 0;
	struct fi_opx_stx    *opx_stx	 = NULL;
	struct fi_opx_domain *opx_domain = container_of(domain, struct fi_opx_domain, domain_fid);

	if (!domain || !stx) {
		errno = FI_EINVAL;
		return -errno;
	}

	ret = fi_opx_fid_check(&domain->fid, FI_CLASS_DOMAIN, "domain");
	if (ret) {
		return ret;
	}

	opx_stx = calloc(1, sizeof *opx_stx);
	if (!opx_stx) {
		errno = FI_ENOMEM;
		goto err;
	}

	if (fi_opx_stx_init(opx_domain, attr, opx_stx, context)) {
		errno = FI_EOTHER;
		goto err;
	}

	*stx = &opx_stx->stx_fid;
	return FI_SUCCESS;

err:
	if (opx_stx) {
		free(opx_stx);
		opx_stx = NULL;
	}
	return -errno;
}

static void fi_opx_unbind_cq_ep(struct fi_opx_cq *cq, struct fi_opx_ep *ep)
{
	uint64_t ind;
	bool	 found = false;
	for (ind = 0; ind < cq->progress.ep_count; ind++) {
		if (!found) {
			found = ep == cq->progress.ep[ind];
		}
		if (found && ind < cq->progress.ep_count - 1) {
			cq->progress.ep[ind] = cq->progress.ep[ind + 1];
		}
	}
	if (found) {
		cq->progress.ep_count--;
	}

	found = false;
	for (ind = 0; ind < cq->ep_bind_count; ind++) {
		if (!found) {
			found = ep == cq->ep[ind];
		}
		if (found && ind < cq->ep_bind_count - 1) {
			cq->ep[ind] = cq->ep[ind + 1];
		}
	}
	if (found) {
		cq->ep_bind_count--;
	}
}

__OPX_FORCE_INLINE__
int opx_ep_free_match_queue_list_contexts(struct slist *list)
{
	int count = 0;

	while (!slist_empty(list)) {
		struct opx_context *context = (struct opx_context *) slist_remove_head(list);
		OPX_BUF_FREE(context);
		++count;
	}

	return count;
}

__OPX_FORCE_INLINE__
void opx_ep_free_match_queued_contexts(struct fi_opx_ep *opx_ep)
{
	int tag_count = opx_ep_free_match_queue_list_contexts(&opx_ep->rx->queue[0].mq);
	int msg_count = opx_ep_free_match_queue_list_contexts(&opx_ep->rx->queue[1].mq);

	FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_FABRIC,
	       "Freed %d contexts from tag match queue, %d contexts from msg match queue\n", tag_count, msg_count);
}

static int fi_opx_close_ep(fid_t fid)
{
	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "close ep\n");
	if (!fid) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_FABRIC, "NULL ep object");
		errno = FI_EINVAL;
		return -errno;
	}

	if (fid->fclass != FI_CLASS_EP && fid->fclass != FI_CLASS_TX_CTX && fid->fclass != FI_CLASS_RX_CTX) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_FABRIC,
		       "wrong type of object. expected (FI_CLASS_EP), got (%zu)\n", fid->fclass);
		errno = FI_EINVAL;
		return -errno;
	}

	int		  ret;
	struct fi_opx_ep *opx_ep = container_of(fid, struct fi_opx_ep, ep_fid);

	if (fi_opx_global.progress == FI_PROGRESS_AUTO) {
		if (opx_ep->init_rx_cq) {
			fi_opx_lock(&opx_ep->init_rx_cq->lock);
		}
		if (opx_ep->init_tx_cq && opx_ep->init_tx_cq != opx_ep->init_rx_cq) {
			fi_opx_lock(&opx_ep->init_tx_cq->lock);
		}
		fi_opx_lock(&opx_ep->lock);
	}
	FI_OPX_DEBUG_COUNTERS_PRINT(opx_ep->debug_counters);

	if (opx_ep->reliability && opx_ep->reliability->state.kind == OFI_RELIABILITY_KIND_ONLOAD) {
		struct fi_opx_reliability_service *service   = opx_ep->reliability->state.service;
		union fi_opx_timer_state	  *timer     = &service->tx.timer;
		union fi_opx_timer_stamp	  *timestamp = &service->tx.timestamp;
		union fi_opx_timer_stamp	   start;
		uint64_t			   compare = fi_opx_timer_now(&start, timer);
		uint64_t next = fi_opx_timer_next_event_usec(timer, &start, FI_OPX_TIMER_NEXT_EVENT_USEC_DEFAULT);

		while ((compare < next) && fi_opx_reliability_client_active(&opx_ep->reliability->state)) {
			if (OFI_UNLIKELY(compare > service->usec_next)) {
				fi_reliability_service_ping_remote(&opx_ep->ep_fid, service);
				service->usec_next = fi_opx_timer_next_event_usec(timer, timestamp, service->usec_max);
			}
			fi_opx_ep_rx_poll(&opx_ep->ep_fid, 0, OPX_RELIABILITY, FI_OPX_HDRQ_MASK_RUNTIME, OPX_HFI1_TYPE);
			compare = fi_opx_timer_now(timestamp, timer);
		}
	}

	if (opx_ep->reliability) {
		fi_opx_reliability_client_fini(&opx_ep->reliability->state);
	}

	if (opx_ep->tx &&
	    ((opx_ep->tx->caps & FI_LOCAL_COMM) || ((opx_ep->tx->caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) == 0))) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA,
		       "Cleaning up endpoint's tx shared memory (%p)\n", &opx_ep->tx->shm);
		dlist_remove_first_match(&shm_tx_list, opx_shm_match, (void *) &opx_ep->tx->shm);
		opx_shm_tx_fini(&opx_ep->tx->shm);
	}

	if (opx_ep->rx &&
	    ((opx_ep->rx->caps & FI_LOCAL_COMM) || ((opx_ep->rx->caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) == 0))) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA,
		       "Cleaning up endpoint's rx shared memory (%p)\n", &opx_ep->rx->shm);
		dlist_remove_first_match(&shm_rx_list, opx_shm_match, (void *) &opx_ep->rx->shm);
		opx_shm_rx_fini(&opx_ep->rx->shm);
	}

	/* Purge the tid cache of leftover entries for this ep
	   before decrementing the domain (->tid_domain) */
	assert(opx_ep->domain->tid_domain == opx_ep->tid_domain);
	opx_tid_cache_purge_ep(opx_ep->tid_domain->tid_cache, opx_ep);

	if (opx_ep->domain) {
		ret = fi_opx_ref_dec(&opx_ep->domain->ref_cnt, "domain");
		if (ret) {
			errno = -ret;
			goto err_unlock;
		}
	}

	/* av is only valid/required if tx capability is enabled */
	if (opx_ep->av) {
		ret = fi_opx_ref_dec(&opx_ep->av->ref_cnt, "address vector");
		if (ret) {
			errno = -ret;
			goto err_unlock;
		}
	}

	if (opx_ep->tx && (opx_ep->tx->cq && (fid->fclass == FI_CLASS_EP || fid->fclass == FI_CLASS_TX_CTX))) {
		ret = fi_opx_ref_dec(&opx_ep->tx->cq->ref_cnt, "completion queue");
		if (ret) {
			errno = -ret;
			goto err_unlock;
		}
	}
	if (opx_ep->rx && (opx_ep->rx->cq && (fid->fclass == FI_CLASS_EP || fid->fclass == FI_CLASS_RX_CTX))) {
		opx_ep_free_match_queued_contexts(opx_ep);
		ret = fi_opx_ref_dec(&opx_ep->rx->cq->ref_cnt, "completion queue");
		if (ret) {
			errno = -ret;
			goto err_unlock;
		}
	}
	// Placeholder functions to be uncommented when they do more than return 0
	/*
	fi_opx_finalize_cm_ops(&opx_ep->ep_fid.fid);
	fi_opx_finalize_msg_ops(&opx_ep->ep_fid);
	fi_opx_finalize_rma_ops(&opx_ep->ep_fid);
	fi_opx_finalize_tagged_ops(&opx_ep->ep_fid);
	fi_opx_finalize_atomic_ops(&opx_ep->ep_fid);
	*/
	if (opx_ep->common_info) {
		fi_freeinfo(opx_ep->common_info);
		opx_ep->common_info = NULL;
	}
	if (opx_ep->tx_info) {
		fi_freeinfo(opx_ep->tx_info);
		opx_ep->tx_info = NULL;
	}
	if (opx_ep->rx_info) {
		fi_freeinfo(opx_ep->rx_info);
		opx_ep->rx_info = NULL;
	}

	if (opx_ep->tx) {
		ret = fi_opx_ref_dec(&opx_ep->tx->ref_cnt, "tx");
		if (ret) { // Error
			errno = -ret;
			goto err_unlock;
		}
		if (opx_ep->tx->cq && (opx_ep->tx->cq->ref_cnt == 0)) {
			if (opx_ep->tx->work_pending_pool) {
				ofi_bufpool_destroy(opx_ep->tx->work_pending_pool);
			}
			if (opx_ep->tx->rma_payload_pool) {
				ofi_bufpool_destroy(opx_ep->tx->rma_payload_pool);
			}
			if (opx_ep->tx->rma_request_pool) {
				ofi_bufpool_destroy(opx_ep->tx->rma_request_pool);
			}
		}
		if (opx_ep->tx->ref_cnt == 0) {
			if (opx_ep->tx->sdma_work_pool) {
				ofi_bufpool_destroy(opx_ep->tx->sdma_work_pool);
			}
			if (opx_ep->tx->sdma_request_pool) {
				ofi_bufpool_destroy(opx_ep->tx->sdma_request_pool);
			}
			free(opx_ep->tx->mem);
		}
		opx_ep->tx = NULL;
	}
	if (opx_ep->rx) {
		ret = fi_opx_ref_dec(&opx_ep->rx->ref_cnt, "rx");
		if (ret) { // Error
			errno = -ret;
			goto err_unlock;
		}
		if (opx_ep->rx->ref_cnt == 0) {
			if (opx_ep->rx->ue_packet_pool) {
				ofi_bufpool_destroy(opx_ep->rx->ue_packet_pool);
				opx_ep->rx->ue_packet_pool = NULL;
			}
			if (opx_ep->rx->match_ue_tag_hash) {
				fi_opx_match_ue_hash_free(&opx_ep->rx->match_ue_tag_hash);
			}
			if (opx_ep->rx->ctx_pool) {
				ofi_bufpool_destroy(opx_ep->rx->ctx_pool);
				opx_ep->rx->ctx_pool = NULL;
			}
			free(opx_ep->rx->mem);
		}
		opx_ep->rx = NULL;
	}
	if (opx_ep->reliability) {
		ret = fi_opx_ref_dec(&opx_ep->reliability->ref_cnt, "reliability");
		if (ret) { // Error
			errno = -ret;
			goto err_unlock;
		}
		if (opx_ep->reliability->ref_cnt == 0) {
			opx_ep->reliability->service.active = 0;
			fi_opx_reliability_service_fini(&opx_ep->reliability->service);
			free(opx_ep->reliability->mem);
		}
		opx_ep->reliability = NULL;
	}

	if (opx_ep->rma_counter_pool) {
		ofi_bufpool_destroy(opx_ep->rma_counter_pool);
	}

	if (opx_ep->rzv_completion_pool) {
		ofi_bufpool_destroy(opx_ep->rzv_completion_pool);
	}

	if (fi_opx_global.daos_hfi_rank_hashmap) {
		struct fi_opx_daos_av_rank *cur_av_rank = NULL;
		struct fi_opx_daos_av_rank *tmp_av_rank = NULL;

		HASH_ITER(hh, opx_ep->daos_info.av_rank_hashmap, cur_av_rank, tmp_av_rank)
		{
			if (cur_av_rank) {
				HASH_DEL(opx_ep->daos_info.av_rank_hashmap, cur_av_rank);
				free(cur_av_rank);
				cur_av_rank = NULL;
			}
		}
	}

	if (fi_opx_global.progress == FI_PROGRESS_AUTO) {
		if (opx_ep->init_rx_cq) {
			fi_opx_unbind_cq_ep(opx_ep->init_rx_cq, opx_ep);
		}
		if (opx_ep->init_tx_cq && opx_ep->init_tx_cq != opx_ep->init_rx_cq) {
			fi_opx_unbind_cq_ep(opx_ep->init_tx_cq, opx_ep);
		}
		fi_opx_unlock(&opx_ep->lock);
	}

	ofi_spin_destroy(&opx_ep->lock);

	if (fi_opx_global.progress == FI_PROGRESS_AUTO) {
		if (opx_ep->init_rx_cq) {
			fi_opx_unlock(&opx_ep->init_rx_cq->lock);
		}
		if (opx_ep->init_tx_cq && opx_ep->init_tx_cq != opx_ep->init_rx_cq) {
			fi_opx_unlock(&opx_ep->init_tx_cq->lock);
		}
	}

	if (fi_opx_global.default_domain_attr != NULL) {
		if (fi_opx_global.default_domain_attr->name != NULL) {
			free(fi_opx_global.default_domain_attr->name);
			fi_opx_global.default_domain_attr->name = NULL;
		}
		free(fi_opx_global.default_domain_attr);
		fi_opx_global.default_domain_attr = NULL;
	}

	if (fi_opx_global.default_ep_attr != NULL) {
		free(fi_opx_global.default_ep_attr);
		fi_opx_global.default_ep_attr = NULL;
	}

	if (fi_opx_global.default_tx_attr != NULL) {
		free(fi_opx_global.default_tx_attr);
		fi_opx_global.default_tx_attr = NULL;
	}

	if (fi_opx_global.default_rx_attr != NULL) {
		free(fi_opx_global.default_rx_attr);
		fi_opx_global.default_rx_attr = NULL;
	}

#ifdef FLIGHT_RECORDER_ENABLE
	if (opx_ep->fr) {
		free(opx_ep->fr);
		opx_ep->fr = NULL;
	}
#endif

	// free memory allocated for fi_opx_hfi1_context struct in fi_opx_hfi1_context_open function in fi_opx_hfi1.c
	if (opx_ep->hfi) {
		ret = fi_opx_ref_dec(&opx_ep->hfi->ref_cnt, "HFI context");
		if (ret) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "HFI context in use\n");
			return ret; // Error
		}
		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "HFI context not in use\n");
		/* Close HFI1 Direct Verbs lib/context */
		opx_hfi1_rdma_context_close(opx_ep->hfi->ibv_context);

		if (opx_ep->hfi->ref_cnt == 0) {
			// free memory allocated for _hfi_ctrl struct in opx_hfi_userinit_internal function in
			// opa_proto.c
			if (opx_ep->hfi->ctrl) {
				free(opx_ep->hfi->ctrl);
				opx_ep->hfi->ctrl = NULL;
			}
			free(opx_ep->hfi);
		}
		opx_ep->hfi = NULL;
	}

	if (opx_ep->hmem_copy_buf) {
#if HAVE_CUDA
		cudaFreeHost(opx_ep->hmem_copy_buf);
#else
		free(opx_ep->hmem_copy_buf);
#endif
		opx_ep->hmem_copy_buf = NULL;
	}
	void *mem = opx_ep->mem;
	free(mem);
	// opx_ep (the object passed in as fid) is now unusable

	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "ep closed\n");

	return 0;

err_unlock:
	if (fi_opx_global.progress == FI_PROGRESS_AUTO) {
		if (opx_ep->init_rx_cq) {
			fi_opx_unlock(&opx_ep->init_rx_cq->lock);
		}
		if (opx_ep->init_tx_cq && opx_ep->init_tx_cq != opx_ep->init_rx_cq) {
			fi_opx_unlock(&opx_ep->init_tx_cq->lock);
		}
		fi_opx_unlock(&opx_ep->lock);
	}
	return -errno;
}

static int fi_opx_bind_ep(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	if (!bfid) {
		return 0;
	}

	int		  ret	 = 0;
	struct fi_opx_ep *opx_ep = container_of(fid, struct fi_opx_ep, ep_fid);

	switch (bfid->fclass) {
	case FI_CLASS_CNTR:
		ret = fi_opx_bind_ep_cntr(&opx_ep->ep_fid, container_of(bfid, struct fid_cntr, fid), flags);
		if (ret) {
			goto err;
		}
		break;
	case FI_CLASS_CQ:
		ret = fi_opx_bind_ep_cq(&opx_ep->ep_fid, container_of(bfid, struct fid_cq, fid), flags);
		if (ret) {
			goto err;
		}
		break;
	case FI_CLASS_AV:
		ret = fi_opx_bind_ep_av(&opx_ep->ep_fid, container_of(bfid, struct fid_av, fid), flags);
		if (ret) {
			goto err;
		}
		break;
	case FI_CLASS_MR:
		ret = fi_opx_bind_ep_mr(&opx_ep->ep_fid, container_of(bfid, struct fid_mr, fid), flags);
		if (ret) {
			goto err;
		}
		break;
	default:
		errno = FI_ENOSYS;
		goto err;
	}
	return ret;
err:
	return -errno;
}

static int fi_opx_check_ep(struct fi_opx_ep *opx_ep)
{
	switch (opx_ep->ep_fid.fid.fclass) {
	case FI_CLASS_EP:
		if (!opx_ep->av) {
			FI_DBG(fi_opx_global.prov, FI_LOG_EP_DATA, "no AV supplied");
			goto err;
		}
		break;
	case FI_CLASS_RX_CTX:
	case FI_CLASS_TX_CTX:
		if (!opx_ep->sep) {
			FI_DBG(fi_opx_global.prov, FI_LOG_EP_DATA, "no scalable endpoint supplied");
			goto err;
		}
		opx_ep->av = opx_ep->sep->av;
		if (!opx_ep->sep->av) {
			FI_DBG(fi_opx_global.prov, FI_LOG_EP_DATA, "no AV supplied on scalable endpoint");
			goto err;
		}
		break;
	default:
		FI_DBG(fi_opx_global.prov, FI_LOG_EP_DATA, "Invalid EP class %lu\n", opx_ep->ep_fid.fid.fclass);
		goto err;
	}

	if (!opx_ep->domain) {
		FI_DBG(fi_opx_global.prov, FI_LOG_EP_DATA, "no domain supplied\n");
		goto err;
	}

	return 0;
err:
	errno = FI_EINVAL;
	return -errno;
}

static int fi_opx_ep_tx_init(struct fi_opx_ep *opx_ep, struct fi_opx_domain *opx_domain)
{
	OPX_LOG(FI_LOG_INFO, FI_LOG_EP_DATA, "==== TX init.  Calculating optimal Tx send thresholds\n");

	assert(opx_ep);
	assert(opx_domain);

	struct fi_opx_hfi1_context *hfi = opx_ep->hfi;

	/*
	 * The 'state' fields will change after every tx operation and
	 * need to have a consistent view of the buffers shared with the OPA
	 * HFI. Therefore we share them between the EPs and the reliability
	 * service to keep them in sync.
	 */
	opx_ep->tx->pio_state = &hfi->state.pio;

	/* initialize the models */
	fi_opx_ep_tx_model_init(hfi, &opx_ep->tx->inject_9B, &opx_ep->tx->send_9B, &opx_ep->tx->send_mp_9B,
				&opx_ep->tx->rzv_9B);

	fi_opx_ep_tx_model_init_16B(hfi, &opx_ep->tx->inject_16B, &opx_ep->tx->send_16B, &opx_ep->tx->send_mp_16B,
				    &opx_ep->tx->rzv_16B);

	opx_ep->tx->inject_9B.hdr.reliability.unused = 0;
	opx_ep->tx->rzv_9B.hdr.reliability.unused    = 0;

	opx_ep->tx->rzv_9B.hdr.rendezvous.origin_rx  = hfi->info.rxe.id;
	opx_ep->tx->rzv_16B.hdr.rendezvous.origin_rx = hfi->info.rxe.id;

	// these 3 lines should move to ep init ?
	opx_ep->threading = (uint32_t) opx_domain->threading;
	opx_ep->av_type	  = (uint32_t) opx_ep->av->type;
	opx_ep->mr_mode	  = (uint32_t) opx_domain->mr_mode;

	/* the 'state' fields will change after every tx operation - and may be
	 * shared between multiple ofi tx contexts */

	/* the 'info' fields do not change; the values can be safely copied */
	opx_ep->tx->pio_scb_sop_first = hfi->info.pio.scb_sop_first;
	opx_ep->tx->pio_scb_first     = hfi->info.pio.scb_first;
	opx_ep->tx->pio_credits_addr  = hfi->info.pio.credits_addr;

	// Retrieve the parameter for RZV min message length
	int	l_rzv_min_payload_bytes;
	ssize_t rc = fi_param_get_int(fi_opx_global.prov, "rzv_min_payload_bytes", &l_rzv_min_payload_bytes);
	if (rc != FI_SUCCESS) {
		l_rzv_min_payload_bytes = OPX_RZV_MIN_PAYLOAD_BYTES_DEFAULT;
		OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA,
				   "FI_OPX_RZV_MIN_PAYLOAD_BYTES not set.  Using default setting of %d\n",
				   l_rzv_min_payload_bytes);
	} else if (l_rzv_min_payload_bytes < OPX_RZV_MIN_PAYLOAD_BYTES_MIN ||
		   l_rzv_min_payload_bytes > OPX_RZV_MIN_PAYLOAD_BYTES_MAX) {
		l_rzv_min_payload_bytes = OPX_RZV_MIN_PAYLOAD_BYTES_DEFAULT;
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
			"Error: FI_OPX_RZV_MIN_PAYLOAD_BYTES was set but is outside min/max thresholds (%d-%d).  Using default setting of %d\n",
			OPX_RZV_MIN_PAYLOAD_BYTES_MIN, OPX_RZV_MIN_PAYLOAD_BYTES_MAX, l_rzv_min_payload_bytes);
	} else {
		OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA, "FI_OPX_RZV_MIN_PAYLOAD_BYTES was specified.  Set to %d\n",
				   l_rzv_min_payload_bytes);
	}
	opx_ep->tx->rzv_min_payload_bytes = l_rzv_min_payload_bytes;

	/* Now that we know how many PIO Tx send credits we have, calculate the threshold to switch from EAGER send to
	 * RTS/CTS With max credits, there should be enough PIO Eager buffer to send 1 full-size message and 1 credit
	 * leftover for min reliablity.
	 */
	uint64_t l_pio_max_eager_tx_bytes =
		MIN(FI_OPX_HFI1_PACKET_MTU,
		    ((hfi->state.pio.credits_total - FI_OPX_HFI1_TX_RELIABILITY_RESERVED_CREDITS) * 64));

	assert(l_pio_max_eager_tx_bytes < ((2 << 15) - 1)); // Make sure the value won't wrap a uint16_t
	assert(l_pio_max_eager_tx_bytes != 0);
	assert((l_pio_max_eager_tx_bytes & 0x3f) == 0); // Make sure the value is 64 bit aligned
	opx_ep->tx->pio_max_eager_tx_bytes = l_pio_max_eager_tx_bytes;

	OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA, "Credits_total is %d, so set pio_max_eager_tx_bytes to %d \n",
			   hfi->state.pio.credits_total, opx_ep->tx->pio_max_eager_tx_bytes);

	/* Similar logic to l_pio_max_eager_tx_bytes, calculate l_pio_flow_eager_tx_bytes to be an 'optimal' value for
	 * PIO credit count that respects the HFI credit return threshold.  The threshold is default 33%, so multiply
	 * credits_total by .66.  The idea is to not wait for an overly long time on credit-constrained systems to get
	 * almost all the PIO send credits back, rather wait to get the optimal number of credits determined by the
	 * return threshold.
	 * TODO: multiply by user_credit_return_threshold from the hfi1 driver parms.  Default is 33
	 */
	uint64_t l_pio_flow_eager_tx_bytes = MIN(
		FI_OPX_HFI1_PACKET_MTU,
		((uint16_t) ((hfi->state.pio.credits_total - FI_OPX_HFI1_TX_RELIABILITY_RESERVED_CREDITS) * .66) * 64));

	assert((l_pio_flow_eager_tx_bytes & 0x3f) == 0);     // Make sure the value is 64 bit aligned
	assert(l_pio_flow_eager_tx_bytes < ((2 << 15) - 1)); // Make sure the value won't wrap a uint16_t
	assert(l_pio_flow_eager_tx_bytes != 0);		     // Can't be 0
	assert(l_pio_flow_eager_tx_bytes <=
	       l_pio_max_eager_tx_bytes); // On credit constrained systems, max is bigger than flow

	opx_ep->tx->pio_flow_eager_tx_bytes = l_pio_flow_eager_tx_bytes;

	OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA, "Set pio_flow_eager_tx_bytes to %d \n", opx_ep->tx->pio_flow_eager_tx_bytes);

	// Set the multi-packet eager max message length
	int l_mp_eager_disable;
	if (fi_param_get_bool(fi_opx_global.prov, "mp_eager_disable", &l_mp_eager_disable) != FI_SUCCESS) {
		l_mp_eager_disable = OPX_MP_EGR_DISABLE_DEFAULT;
		OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA, "FI_OPX_MP_EAGER_DISABLE not set.  Using default setting of %d\n",
				   l_mp_eager_disable);
	} else {
		OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA, "FI_OPX_MP_EAGER_DISABLE was specified.  Set to %d\n",
				   l_mp_eager_disable);
	}

	if (l_mp_eager_disable == OPX_MP_EGR_DISABLE_SET) {
		opx_ep->tx->mp_eager_max_payload_bytes = 0;
	} else {
		opx_ep->tx->mp_eager_max_payload_bytes = l_rzv_min_payload_bytes - 1;
	}
	OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA, "Using MP eager threshold of %d\n", opx_ep->tx->mp_eager_max_payload_bytes);
	OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA, "Multi-packet eager chunk-size is %d.\n", FI_OPX_MP_EGR_CHUNK_SIZE);

	/* Set SDMA bounce buffer threshold.  Any messages larger than this value in bytes will not be copied to
	 * replay bounce buffers.  Instead, hold the sender's large message buffer until we get all ACKs back from the
	 * Rx side of the message.  Since no copy of the message is made, it will need to be used to handle NAKs.
	 */
	int l_sdma_bounce_buf_threshold;
	rc = fi_param_get_int(fi_opx_global.prov, "sdma_bounce_buf_threshold", &l_sdma_bounce_buf_threshold);
	if (rc != FI_SUCCESS) {
		rc = fi_param_get_int(fi_opx_global.prov, "delivery_completion_threshold",
				      &l_sdma_bounce_buf_threshold);
	}
	if (rc != FI_SUCCESS) {
		opx_ep->tx->sdma_bounce_buf_threshold = OPX_SDMA_BOUNCE_BUF_THRESHOLD;
		OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA,
				   "FI_OPX_SDMA_BOUNCE_BUF_THRESHOLD not set.  Using default setting of %d\n",
				   opx_ep->tx->sdma_bounce_buf_threshold);
	} else if (l_sdma_bounce_buf_threshold < OPX_SDMA_BOUNCE_BUF_MIN ||
		   l_sdma_bounce_buf_threshold > (OPX_SDMA_BOUNCE_BUF_MAX)) {
		opx_ep->tx->sdma_bounce_buf_threshold = OPX_SDMA_BOUNCE_BUF_THRESHOLD;
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
			"Error: FI_OPX_SDMA_BOUNCE_BUF_THRESHOLD was set but is outside of min/max thresholds (%d-%d).  Using default setting of %d\n",
			OPX_SDMA_BOUNCE_BUF_MIN, OPX_SDMA_BOUNCE_BUF_MAX, opx_ep->tx->sdma_bounce_buf_threshold);
	} else {
		opx_ep->tx->sdma_bounce_buf_threshold = l_sdma_bounce_buf_threshold;
		OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA, "FI_OPX_SDMA_BOUNCE_BUF_THRESHOLD was specified.  Set to %d\n",
				   opx_ep->tx->sdma_bounce_buf_threshold);
	}

	opx_ep->tx->force_credit_return = 0;

	if ((opx_ep->tx->caps & FI_LOCAL_COMM) || ((opx_ep->tx->caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) == 0)) {
		opx_shm_tx_init(&opx_ep->tx->shm, fi_opx_global.prov, opx_ep->hfi->daos_info.rank,
				opx_ep->hfi->daos_info.rank_inst);
	}

	int sdma_disable;
	if (fi_param_get_bool(fi_opx_global.prov, "sdma_disable", &sdma_disable) == FI_SUCCESS) {
		opx_ep->tx->use_sdma = !sdma_disable;
		OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA, "sdma_disable parm specified as %s.\n",
				   sdma_disable ? "TRUE" : "FALSE");
	} else {
		OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA, "FI_OPX_SDMA_DISABLE not specified; using SDMA\n");
		opx_ep->tx->use_sdma = 1;
	}

	// Set the SDMA minimum message length
	int l_sdma_min_payload_bytes;
	rc = fi_param_get_int(fi_opx_global.prov, "sdma_min_payload_bytes", &l_sdma_min_payload_bytes);
	if (rc != FI_SUCCESS) {
		opx_ep->tx->sdma_min_payload_bytes = FI_OPX_SDMA_MIN_PAYLOAD_BYTES_DEFAULT;
		OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA,
				   "FI_OPX_SDMA_MIN_PAYLOAD_BYTES not set.  Using default setting of %d\n",
				   opx_ep->tx->sdma_min_payload_bytes);
	} else if (l_sdma_min_payload_bytes < FI_OPX_SDMA_MIN_PAYLOAD_BYTES_MIN ||
		   l_sdma_min_payload_bytes > FI_OPX_SDMA_MIN_PAYLOAD_BYTES_MAX) {
		opx_ep->tx->sdma_min_payload_bytes = FI_OPX_SDMA_MIN_PAYLOAD_BYTES_DEFAULT;
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
			"Error: FI_OPX_SDMA_MIN_PAYLOAD_BYTES was set but is outside min/max thresholds (%d-%d).  Using default setting of %d\n",
			FI_OPX_SDMA_MIN_PAYLOAD_BYTES_MIN, FI_OPX_SDMA_MIN_PAYLOAD_BYTES_MAX,
			FI_OPX_SDMA_MIN_PAYLOAD_BYTES_DEFAULT);
	} else {
		opx_ep->tx->sdma_min_payload_bytes = l_sdma_min_payload_bytes;
		OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA, "FI_OPX_SDMA_MIN_PAYLOAD_BYTES was specified.  Set to %d\n",
				   opx_ep->tx->sdma_min_payload_bytes);
	}

	int l_tid_min_payload_bytes;
	rc = fi_param_get_int(fi_opx_global.prov, "tid_min_payload_bytes", &l_tid_min_payload_bytes);
	if (rc != FI_SUCCESS) {
		opx_ep->tx->tid_min_payload_bytes = OPX_TID_MIN_PAYLOAD_BYTES_DEFAULT;
		OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA,
				   "FI_OPX_TID_MIN_PAYLOAD_BYTES not set. Using default setting of %d\n",
				   opx_ep->tx->tid_min_payload_bytes);
	} else if (l_tid_min_payload_bytes < OPX_TID_MIN_PAYLOAD_BYTES_MIN) {
		opx_ep->tx->tid_min_payload_bytes = OPX_TID_MIN_PAYLOAD_BYTES_DEFAULT;
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
			"Error: FI_OPX_TID_MIN_PAYLOAD_BYTES was set but is less than minimum allowed (%lu). Using default setting of %d\n",
			OPX_TID_MIN_PAYLOAD_BYTES_MIN, OPX_TID_MIN_PAYLOAD_BYTES_DEFAULT);
	} else {
		opx_ep->tx->tid_min_payload_bytes = l_tid_min_payload_bytes;
		OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA, "FI_OPX_TID_MIN_PAYLOAD_BYTES was specified. Set to %d\n",
				   opx_ep->tx->tid_min_payload_bytes);
	}

	slist_init(&opx_ep->tx->work_pending[OPX_WORK_TYPE_SHM]);
	slist_init(&opx_ep->tx->work_pending[OPX_WORK_TYPE_PIO]);
	slist_init(&opx_ep->tx->work_pending[OPX_WORK_TYPE_SDMA]);
	slist_init(&opx_ep->tx->work_pending[OPX_WORK_TYPE_TID_SETUP]);
	slist_init(&opx_ep->tx->work_pending_completion);
	slist_init(&opx_ep->tx->sdma_request_queue.list);
	opx_ep->tx->sdma_request_queue.num_reqs	   = 0;
	opx_ep->tx->sdma_request_queue.num_iovs	   = 0;
	opx_ep->tx->sdma_request_queue.max_iovs	   = OPX_SDMA_HFI_MAX_IOVS_PER_WRITE * OPX_SDMA_MAX_WRITEVS_PER_CYCLE;
	opx_ep->tx->sdma_request_queue.slots_avail = hfi->info.sdma.available_counter;
	slist_init(&opx_ep->tx->sdma_pending_queue);
	ofi_bufpool_create(&opx_ep->tx->work_pending_pool, sizeof(union fi_opx_hfi1_deferred_work), L2_CACHE_LINE_SIZE,
			   UINT_MAX, 2048, 0);

	ofi_bufpool_create(&opx_ep->tx->rma_payload_pool, sizeof(union fi_opx_hfi1_packet_payload), 0, UINT_MAX, 16, 0);

	ofi_bufpool_create(&opx_ep->tx->rma_request_pool, sizeof(struct fi_opx_rma_request), 0, UINT_MAX, 16, 0);

	if (opx_ep->tx->use_sdma) {
		ofi_bufpool_create(&opx_ep->tx->sdma_work_pool, sizeof(struct fi_opx_hfi1_sdma_work_entry), 64,
				   FI_OPX_HFI1_SDMA_MAX_WE, FI_OPX_HFI1_SDMA_MAX_WE, 0);
		ofi_bufpool_create(&opx_ep->tx->sdma_request_pool, sizeof(struct opx_sdma_request), 64, UINT_MAX,
				   FI_OPX_HFI1_SDMA_MAX_WE, 0);
	} else {
		opx_ep->tx->sdma_work_pool    = NULL;
		opx_ep->tx->sdma_request_pool = NULL;
	}
	OPX_LOG(FI_LOG_INFO, FI_LOG_EP_DATA, "==== TX init finished\n");
	return 0;
}

static int fi_opx_ep_rx_init(struct fi_opx_ep *opx_ep)
{
	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "rx init\n");

	opx_ep->rx->ue_packet_pool = NULL;
	if (ofi_bufpool_create(&opx_ep->rx->ue_packet_pool, sizeof(struct fi_opx_hfi1_ue_packet), 64, UINT_MAX,
			       FI_OPX_EP_RX_UEPKT_BLOCKSIZE, 0)) {
		goto err;
	}

	if (fi_opx_match_ue_hash_init(&opx_ep->rx->match_ue_tag_hash)) {
		goto err;
	}

	opx_ep->rx->ctx_pool = NULL;
	if (ofi_bufpool_create(&opx_ep->rx->ctx_pool, sizeof(struct opx_context), 64, UINT_MAX, OPX_EP_RX_CTX_BLOCKSIZE,
			       0)) {
		goto err;
	}
	struct fi_opx_domain *opx_domain = opx_ep->domain;

	/*
	 * open the hfi1 context
	 */
	struct fi_opx_hfi1_context *hfi1 = opx_ep->hfi;
	init_hfi1_rxe_state(hfi1, &opx_ep->rx->state);

	/*
	 * COPY the rx static information from the hfi context structure.
	 * This is to improve cache layout.
	 */
	opx_ep->rx->hdrq.rhf_base	   = hfi1->info.rxe.hdrq.rhf_base;
	opx_ep->rx->hdrq.rhe_base	   = hfi1->info.rxe.hdrq.rhe_base;
	opx_ep->rx->hdrq.head_register	   = hfi1->info.rxe.hdrq.head_register;
	opx_ep->rx->egrq.base_addr	   = hfi1->info.rxe.egrq.base_addr;
	opx_ep->rx->egrq.elemsz		   = hfi1->info.rxe.egrq.elemsz;
	opx_ep->rx->egrq.last_egrbfr_index = 0;
	opx_ep->rx->egrq.head_register	   = hfi1->info.rxe.egrq.head_register;

	opx_ep->rx->self.raw64b		 = 0;
	opx_ep->rx->self.lid		 = hfi1->lid;
	opx_ep->rx->self.hfi1_subctxt_rx = hfi1->info.rxe.id;
	opx_ep->rx->self.hfi1_unit	 = (uint8_t) hfi1->hfi_unit;

	/* Initialize hash table used to lookup info on any HFI units on the node */
	fi_opx_global.hfi_local_info.hfi_unit = (uint8_t) hfi1->hfi_unit;
	fi_opx_global.hfi_local_info.lid      = hfi1->lid;

	fi_opx_init_hfi_lookup();

	/*
	 * initialize tx for acks, etc
	 */
	{ /* 9B */
		/* rendezvous CTS packet model */

		/* Setup the 9B models whether or not they'll be used */
		enum opx_hfi1_type __attribute__((unused)) hfi1_type =
			(OPX_HFI1_TYPE & OPX_HFI1_WFR) ? OPX_HFI1_WFR : OPX_HFI1_JKR_9B;

		memset(&opx_ep->rx->tx.cts_9B, 0, sizeof(opx_ep->rx->tx.cts_9B));
		/* PBC data */
		opx_ep->rx->tx.cts_9B.qw0 =
			OPX_PBC_LEN(0, hfi1_type) /* length_dws */ | OPX_PBC_VL(hfi1->vl, hfi1_type) |
			OPX_PBC_SC(hfi1->sc, hfi1_type) | OPX_PBC_L2TYPE(OPX_PBC_JKR_L2TYPE_9B, hfi1_type) |
			OPX_PBC_L2COMPRESSED(0, hfi1_type) | OPX_PBC_PORTIDX(hfi1->hfi_port, hfi1_type) |
			OPX_PBC_SCTXT(hfi1->send_ctxt, hfi1_type);

		/* LRH header */
		opx_ep->rx->tx.cts_9B.hdr.lrh_9B.flags =
			htons(FI_OPX_HFI1_LRH_BTH | ((hfi1->sl & FI_OPX_HFI1_LRH_SL_MASK) << FI_OPX_HFI1_LRH_SL_SHIFT) |
			      ((hfi1->sc & FI_OPX_HFI1_LRH_SC_MASK) << FI_OPX_HFI1_LRH_SC_SHIFT));

		opx_ep->rx->tx.cts_9B.hdr.lrh_9B.dlid	= 0; /* set at runtime */
		opx_ep->rx->tx.cts_9B.hdr.lrh_9B.pktlen = 0; /* set at runtime */
		opx_ep->rx->tx.cts_9B.hdr.lrh_9B.slid	= htons(hfi1->lid);

		/* BTH header */
		opx_ep->rx->tx.cts_9B.hdr.bth.opcode = FI_OPX_HFI_BTH_OPCODE_RZV_CTS;
		opx_ep->rx->tx.cts_9B.hdr.bth.bth_1  = 0;
		opx_ep->rx->tx.cts_9B.hdr.bth.pkey   = htons(hfi1->pkey);
		opx_ep->rx->tx.cts_9B.hdr.bth.ecn    = (uint8_t) ((OPX_BTH_RC2_VAL(hfi1_type, OPX_HFI1_RZV_CTRL)) |
								  OPX_BTH_CSPEC(OPX_BTH_CSPEC_DEFAULT, hfi1_type));
		opx_ep->rx->tx.cts_9B.hdr.bth.qp     = hfi1->bthqp;
		opx_ep->rx->tx.cts_9B.hdr.bth.unused = 0;
		opx_ep->rx->tx.cts_9B.hdr.bth.rx     = 0; /* set at runtime */

		opx_ep->rx->tx.cts_9B.hdr.reliability.psn	= 0;
		opx_ep->rx->tx.cts_9B.hdr.reliability.origin_rx = hfi1->info.rxe.id;

		/* KDETH header */
		opx_ep->rx->tx.cts_9B.hdr.kdeth.offset_ver_tid = FI_OPX_HFI1_KDETH_VERSION
								 << FI_OPX_HFI1_KDETH_VERSION_SHIFT; /* no flags */
		opx_ep->rx->tx.cts_9B.hdr.kdeth.jkey   = hfi1->jkey;
		opx_ep->rx->tx.cts_9B.hdr.kdeth.hcrc   = 0;
		opx_ep->rx->tx.cts_9B.hdr.kdeth.unused = 0;

		/* OFI header */
		opx_ep->rx->tx.cts_9B.hdr.cts.origin_rx	    = hfi1->info.rxe.id;
		opx_ep->rx->tx.cts_9B.hdr.cts.target.opcode = FI_OPX_HFI_DPUT_OPCODE_RZV;

		OPX_DEBUG_PRINT_HDR((&(opx_ep->rx->tx.cts_9B.hdr)), hfi1_type);

		/* RMA RTS packet model */
		opx_ep->rx->tx.rma_rts_9B			= opx_ep->rx->tx.cts_9B;
		opx_ep->rx->tx.rma_rts_9B.hdr.bth.opcode	= FI_OPX_HFI_BTH_OPCODE_RMA_RTS;
		opx_ep->rx->tx.rma_rts_9B.hdr.cts.target.opcode = FI_OPX_HFI_DPUT_OPCODE_PUT_CQ;

		OPX_DEBUG_PRINT_HDR((&(opx_ep->rx->tx.rma_rts_9B.hdr)), hfi1_type);

		/* DPUT packet model */

		/* tagged model */
		opx_ep->rx->tx.dput_9B				  = opx_ep->rx->tx.cts_9B;
		opx_ep->rx->tx.dput_9B.hdr.reliability.origin_rx  = 0;
		opx_ep->rx->tx.dput_9B.hdr.dput.target.origin_rx  = hfi1->info.rxe.id;
		opx_ep->rx->tx.dput_9B.hdr.dput.target.dt	  = 0;
		opx_ep->rx->tx.dput_9B.hdr.dput.target.op	  = 0;
		opx_ep->rx->tx.dput_9B.hdr.dput.target.last_bytes = 0;
		opx_ep->rx->tx.dput_9B.hdr.dput.target.bytes	  = 0;
		opx_ep->rx->tx.dput_9B.hdr.dput.origin_rx	  = hfi1->info.rxe.id;
		opx_ep->rx->tx.dput_9B.hdr.bth.opcode		  = FI_OPX_HFI_BTH_OPCODE_RZV_DATA;
		opx_ep->rx->tx.dput_9B.hdr.bth.ecn = (uint8_t) ((OPX_BTH_RC2_VAL(hfi1_type, OPX_HFI1_DPUT)) |
								OPX_BTH_CSPEC(OPX_BTH_CSPEC_DEFAULT, hfi1_type));

		OPX_DEBUG_PRINT_HDR((&(opx_ep->rx->tx.dput_9B.hdr)), hfi1_type);

		/* rendezvous DPUT packet model */

		/* tagged model */
		opx_ep->rx->tx.rzv_dput_9B			      = opx_ep->rx->tx.cts_9B;
		opx_ep->rx->tx.rzv_dput_9B.hdr.reliability.origin_rx  = 0;
		opx_ep->rx->tx.rzv_dput_9B.hdr.dput.target.origin_rx  = hfi1->info.rxe.id;
		opx_ep->rx->tx.rzv_dput_9B.hdr.dput.target.dt	      = 0;
		opx_ep->rx->tx.rzv_dput_9B.hdr.dput.target.op	      = 0;
		opx_ep->rx->tx.rzv_dput_9B.hdr.dput.target.last_bytes = 0;
		opx_ep->rx->tx.rzv_dput_9B.hdr.dput.target.bytes      = 0;
		opx_ep->rx->tx.rzv_dput_9B.hdr.dput.origin_rx	      = hfi1->info.rxe.id;
		opx_ep->rx->tx.rzv_dput_9B.hdr.bth.opcode	      = FI_OPX_HFI_BTH_OPCODE_RZV_DATA;
		opx_ep->rx->tx.rzv_dput_9B.hdr.bth.ecn = (uint8_t) ((OPX_BTH_RC2_VAL(hfi1_type, OPX_HFI1_RZV_DATA)) |
								    OPX_BTH_CSPEC(OPX_BTH_CSPEC_DEFAULT, hfi1_type));

		OPX_DEBUG_PRINT_HDR((&(opx_ep->rx->tx.rzv_dput_9B.hdr)), hfi1_type);
	}

	{ /* 16B */
		/* rendezvous CTS packet model for 16B*/
		/* Setup the 16B models whether or not they'll be used */

		uint64_t hfi1_type = OPX_HFI1_JKR;

		memset(&opx_ep->rx->tx.cts_16B, 0, sizeof(opx_ep->rx->tx.cts_16B));
		/* PBC data */
		opx_ep->rx->tx.cts_16B.qw0 =
			OPX_PBC_LEN(0, hfi1_type) /* length_dws */ | OPX_PBC_VL(hfi1->vl, hfi1_type) |
			OPX_PBC_SC(hfi1->sc, hfi1_type) | OPX_PBC_L2TYPE(OPX_PBC_JKR_L2TYPE_16B, hfi1_type) |
			OPX_PBC_L2COMPRESSED(0, hfi1_type) | OPX_PBC_PORTIDX(hfi1->hfi_port, hfi1_type) |
			OPX_PBC_SCTXT(hfi1->send_ctxt, hfi1_type) | OPX_PBC_JKR_INSERT_NON9B_ICRC;

		/* LRH header */
		opx_ep->rx->tx.cts_16B.hdr.lrh_16B.qw[0] = 0;
		opx_ep->rx->tx.cts_16B.hdr.lrh_16B.qw[1] = 0;

		opx_ep->rx->tx.cts_16B.hdr.lrh_16B.sc	   = hfi1->sc;
		opx_ep->rx->tx.cts_16B.hdr.lrh_16B.entropy = hfi1->ctrl->ctxt_info.send_ctxt;
		opx_ep->rx->tx.cts_16B.hdr.lrh_16B.lt	   = 0; // need to add env variable to change
		opx_ep->rx->tx.cts_16B.hdr.lrh_16B.l2	   = OPX_PBC_JKR_L2TYPE_16B;
		opx_ep->rx->tx.cts_16B.hdr.lrh_16B.l4	   = 9;
		opx_ep->rx->tx.cts_16B.hdr.lrh_16B.rc	   = OPX_LRH_JKR_16B_RC(OPX_HFI1_RZV_CTRL);
		opx_ep->rx->tx.cts_16B.hdr.lrh_16B.cspec   = OPX_BTH_CSPEC_DEFAULT; /*NOT BTH CSPEC*/
		opx_ep->rx->tx.cts_16B.hdr.lrh_16B.pkey	   = hfi1->pkey;

		opx_ep->rx->tx.cts_16B.hdr.lrh_16B.slid	  = hfi1->lid & 0xFFFFF;
		opx_ep->rx->tx.cts_16B.hdr.lrh_16B.slid20 = (hfi1->lid) >> 20;

		/* BTH header */
		opx_ep->rx->tx.cts_16B.hdr.bth.opcode = FI_OPX_HFI_BTH_OPCODE_RZV_CTS;
		opx_ep->rx->tx.cts_16B.hdr.bth.bth_1  = 0;
		opx_ep->rx->tx.cts_16B.hdr.bth.pkey   = htons(hfi1->pkey);
		opx_ep->rx->tx.cts_16B.hdr.bth.ecn    = (uint8_t) ((OPX_BTH_RC2_VAL(hfi1_type, OPX_HFI1_RZV_CTRL)) |
								   OPX_BTH_CSPEC(OPX_BTH_CSPEC_DEFAULT, hfi1_type));
		opx_ep->rx->tx.cts_16B.hdr.bth.qp     = hfi1->bthqp;
		opx_ep->rx->tx.cts_16B.hdr.bth.unused = 0;
		opx_ep->rx->tx.cts_16B.hdr.bth.rx     = 0; /* set at runtime */

		opx_ep->rx->tx.cts_16B.hdr.reliability.psn	 = 0;
		opx_ep->rx->tx.cts_16B.hdr.reliability.origin_rx = hfi1->info.rxe.id;

		/* KDETH header */
		opx_ep->rx->tx.cts_16B.hdr.kdeth.offset_ver_tid = FI_OPX_HFI1_KDETH_VERSION
								  << FI_OPX_HFI1_KDETH_VERSION_SHIFT; /* no flags */
		opx_ep->rx->tx.cts_16B.hdr.kdeth.jkey	= hfi1->jkey;
		opx_ep->rx->tx.cts_16B.hdr.kdeth.hcrc	= 0;
		opx_ep->rx->tx.cts_16B.hdr.kdeth.unused = 0;

		/* OFI header */
		opx_ep->rx->tx.cts_16B.hdr.cts.origin_rx     = hfi1->info.rxe.id;
		opx_ep->rx->tx.cts_16B.hdr.cts.target.opcode = FI_OPX_HFI_DPUT_OPCODE_RZV;

		OPX_DEBUG_PRINT_HDR((&(opx_ep->rx->tx.cts_16B.hdr)), hfi1_type);

		/* RMA RTS packet model for 16B*/
		opx_ep->rx->tx.rma_rts_16B			 = opx_ep->rx->tx.cts_16B;
		opx_ep->rx->tx.rma_rts_16B.hdr.bth.opcode	 = FI_OPX_HFI_BTH_OPCODE_RMA_RTS;
		opx_ep->rx->tx.rma_rts_16B.hdr.cts.target.opcode = FI_OPX_HFI_DPUT_OPCODE_PUT_CQ;

		OPX_DEBUG_PRINT_HDR((&(opx_ep->rx->tx.rma_rts_16B.hdr)), hfi1_type);

		/* DPUT packet model */

		/* tagged model */
		opx_ep->rx->tx.dput_16B				   = opx_ep->rx->tx.cts_16B;
		opx_ep->rx->tx.dput_16B.hdr.reliability.origin_rx  = 0;
		opx_ep->rx->tx.dput_16B.hdr.dput.target.origin_rx  = hfi1->info.rxe.id;
		opx_ep->rx->tx.dput_16B.hdr.dput.target.dt	   = 0;
		opx_ep->rx->tx.dput_16B.hdr.dput.target.op	   = 0;
		opx_ep->rx->tx.dput_16B.hdr.dput.target.last_bytes = 0;
		opx_ep->rx->tx.dput_16B.hdr.dput.target.bytes	   = 0;
		opx_ep->rx->tx.dput_16B.hdr.dput.origin_rx	   = hfi1->info.rxe.id;
		opx_ep->rx->tx.dput_16B.hdr.bth.opcode		   = FI_OPX_HFI_BTH_OPCODE_RZV_DATA;
		opx_ep->rx->tx.dput_16B.hdr.lrh_16B.rc		   = OPX_LRH_JKR_16B_RC(OPX_HFI1_DPUT);
		opx_ep->rx->tx.dput_16B.hdr.bth.ecn = (uint8_t) ((OPX_BTH_RC2_VAL(hfi1_type, OPX_HFI1_DPUT)) |
								 OPX_BTH_CSPEC(OPX_BTH_CSPEC_DEFAULT, hfi1_type));

		OPX_DEBUG_PRINT_HDR((&(opx_ep->rx->tx.dput_16B.hdr)), hfi1_type);

		/* rendezvous DPUT packet model */

		/* tagged model */
		opx_ep->rx->tx.rzv_dput_16B			       = opx_ep->rx->tx.cts_16B;
		opx_ep->rx->tx.rzv_dput_16B.hdr.reliability.origin_rx  = 0;
		opx_ep->rx->tx.rzv_dput_16B.hdr.dput.target.origin_rx  = hfi1->info.rxe.id;
		opx_ep->rx->tx.rzv_dput_16B.hdr.dput.target.dt	       = 0;
		opx_ep->rx->tx.rzv_dput_16B.hdr.dput.target.op	       = 0;
		opx_ep->rx->tx.rzv_dput_16B.hdr.dput.target.last_bytes = 0;
		opx_ep->rx->tx.rzv_dput_16B.hdr.dput.target.bytes      = 0;
		opx_ep->rx->tx.rzv_dput_16B.hdr.dput.origin_rx	       = hfi1->info.rxe.id;
		opx_ep->rx->tx.rzv_dput_16B.hdr.bth.opcode	       = FI_OPX_HFI_BTH_OPCODE_RZV_DATA;
		opx_ep->rx->tx.rzv_dput_16B.hdr.lrh_16B.rc	       = OPX_LRH_JKR_16B_RC(OPX_HFI1_RZV_DATA);
		opx_ep->rx->tx.rzv_dput_16B.hdr.bth.ecn = (uint8_t) ((OPX_BTH_RC2_VAL(hfi1_type, OPX_HFI1_RZV_DATA)) |
								     OPX_BTH_CSPEC(OPX_BTH_CSPEC_DEFAULT, hfi1_type));

		OPX_DEBUG_PRINT_HDR((&(opx_ep->rx->tx.rzv_dput_16B.hdr)), hfi1_type);
	}

	if ((opx_ep->rx->caps & FI_LOCAL_COMM) || ((opx_ep->rx->caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) == 0)) {
		char buffer[128];

		uint32_t hfi_unit = hfi1->hfi_unit;
		unsigned rx_index = hfi1->info.rxe.id;
		int	 inst	  = 0;

		/* HFI Rank Support:  Rank and PID included in the SHM file name */
		if (opx_ep->daos_info.hfi_rank_enabled) {
			rx_index = opx_shm_daos_rank_index(hfi1->daos_info.rank, hfi1->daos_info.rank_inst);
			inst	 = hfi1->daos_info.rank_inst;
		}

		snprintf(buffer, sizeof(buffer), "%s-%02x.%d", opx_domain->unique_job_key_str, hfi_unit, inst);
		ssize_t rc = opx_shm_rx_init(&opx_ep->rx->shm, fi_opx_global.prov, (const char *) buffer, rx_index,
					     FI_OPX_SHM_FIFO_SIZE, FI_OPX_SHM_PACKET_SIZE);
		if (OFI_UNLIKELY(rc != FI_SUCCESS)) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Shared memory initialization failed.\n");
			goto err;
		}
	}

	/* Now that endpoint is complete enough to have context information from the hfi,
	** update the function pointers in the cq for the rx polling loop
	*/
	fi_opx_cq_finalize_ops((struct fid_ep *) opx_ep);

	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "rx init'd\n");
	return 0;
err:
	if (opx_ep->rx->ue_packet_pool) {
		ofi_bufpool_destroy(opx_ep->rx->ue_packet_pool);
		opx_ep->rx->ue_packet_pool = NULL;
	}

	fi_opx_match_ue_hash_free(&opx_ep->rx->match_ue_tag_hash);

	if (opx_ep->rx->ctx_pool) {
		ofi_bufpool_destroy(opx_ep->rx->ctx_pool);
		opx_ep->rx->ctx_pool = NULL;
	}

	return -FI_ENOMEM;
}

static int fi_opx_apply_info_and_init_ops(struct fi_opx_ep *opx_ep)
{
	// Info checks
	struct fi_info *info;
	switch (opx_ep->ep_fid.fid.fclass) {
	case FI_CLASS_TX_CTX:
		info = opx_ep->tx_info;
		break;
	case FI_CLASS_RX_CTX:
		info = opx_ep->rx_info;
		break;
	default:
		info = opx_ep->common_info;

		break;
	}

	opx_ep->tx->caps |= info->tx_attr ? info->tx_attr->caps : info->caps;
	opx_ep->tx->mode |= info->tx_attr ? info->tx_attr->mode : 0;
	opx_ep->tx->op_flags |= (info->tx_attr ? info->tx_attr->op_flags : 0) |
				(opx_ep->tx_cq_bflags & FI_SELECTIVE_COMPLETION ? 0 : FI_COMPLETION);

	opx_ep->rx->caps |= info->rx_attr ? info->rx_attr->caps : info->caps;
	opx_ep->rx->mode |= info->rx_attr ? info->rx_attr->mode : 0;
	opx_ep->rx->op_flags |= (info->rx_attr ? info->rx_attr->op_flags : 0) |
				(opx_ep->rx_cq_bflags & FI_SELECTIVE_COMPLETION ? 0 : FI_COMPLETION);

	// Init oprations per endpoint
	int ret;
	ret = fi_opx_init_cm_ops(&opx_ep->ep_fid.fid, info);
	if (ret) {
		goto err;
	}

	ret = fi_opx_init_msg_ops(&opx_ep->ep_fid, info);
	if (ret) {
		goto err;
	}

	ret = fi_opx_init_rma_ops(&opx_ep->ep_fid, info);
	if (ret) {
		goto err;
	}

	ret = fi_opx_init_tagged_ops(&opx_ep->ep_fid, info);
	if (ret) {
		goto err;
	}

	ret = fi_opx_init_atomic_ops(&opx_ep->ep_fid, info);
	if (ret) {
		goto err;
	}
	return 0;
err:
	// Placeholder functions to be uncommented when they do more than return 0
	/*
	fi_opx_finalize_cm_ops(&opx_ep->ep_fid.fid);
	fi_opx_finalize_msg_ops(&opx_ep->ep_fid);
	fi_opx_finalize_rma_ops(&opx_ep->ep_fid);
	fi_opx_finalize_tagged_ops(&opx_ep->ep_fid);
	fi_opx_finalize_atomic_ops(&opx_ep->ep_fid);
	*/
	return -1;
}

static void fi_opx_update_counter(struct fi_opx_cntr *opx_cntr)
{
	if (opx_cntr == NULL) {
		return;
	}

	for (int i = 0; i < opx_cntr->ep_bind_count; i++) {
		opx_cntr->progress.ep[i] = opx_cntr->ep[i];
	}
	opx_cntr->progress.ep_count = opx_cntr->ep_bind_count;
}

static void fi_opx_apply_bind_flags(struct fi_opx_ep *opx_ep)
{
	if (opx_ep->tx_cq_bflags & FI_TRANSMIT) {
		fi_opx_ref_inc(&opx_ep->init_tx_cq->ref_cnt, "tx completion queue");
		opx_ep->tx->cq		     = opx_ep->init_tx_cq;
		opx_ep->tx->cq_completed_ptr = &opx_ep->init_tx_cq->completed;
		opx_ep->tx->cq_pending_ptr   = &opx_ep->init_tx_cq->pending;
		opx_ep->tx->cq_err_ptr	     = &opx_ep->init_tx_cq->err;
		/* See NOTE_SELECTIVE_COMPLETION for more information */
		opx_ep->tx->cq_bind_flags = opx_ep->tx_cq_bflags;

		const uint64_t selective_completion = FI_SELECTIVE_COMPLETION | FI_TRANSMIT | FI_COMPLETION;

		const uint64_t cq_flags = opx_ep->tx->op_flags | opx_ep->tx_cq_bflags;

		opx_ep->tx->do_cq_completion = ((cq_flags & selective_completion) == selective_completion) ||
					       ((cq_flags & (FI_SELECTIVE_COMPLETION | FI_TRANSMIT)) == FI_TRANSMIT);
	}
	if (opx_ep->rx_cq_bflags & FI_RECV) {
		fi_opx_ref_inc(&opx_ep->init_rx_cq->ref_cnt, "rx completion queue");
		opx_ep->rx->cq		     = opx_ep->init_rx_cq;
		opx_ep->rx->cq_completed_ptr = &opx_ep->init_rx_cq->completed;
		opx_ep->rx->cq_pending_ptr   = &opx_ep->init_rx_cq->pending;
		opx_ep->rx->cq_err_ptr	     = &opx_ep->init_rx_cq->err;
	}
	if ((ofi_recv_allowed(opx_ep->rx->caps) || ofi_rma_target_allowed(opx_ep->rx->caps)) && opx_ep->init_rx_cq) {
		if (opx_ep->rx->cq->progress.ep_count == 0) {
			opx_ep->rx->cq->ep_comm_caps = opx_ep->rx->caps & (FI_LOCAL_COMM | FI_REMOTE_COMM);
		} else {
			if (opx_ep->init_rx_cq->ep_comm_caps != (opx_ep->rx->caps & (FI_LOCAL_COMM | FI_REMOTE_COMM))) {
				opx_ep->init_rx_cq->ep_comm_caps = 0;
			}
		}
	}

	fi_opx_update_counter(opx_ep->init_read_cntr);
	fi_opx_update_counter(opx_ep->init_write_cntr);
	fi_opx_update_counter(opx_ep->init_send_cntr);
	fi_opx_update_counter(opx_ep->init_recv_cntr);

	if (opx_ep->tx->cq && !opx_ep->is_tx_cq_bound) {
		opx_ep->tx->cq->progress.ep[(opx_ep->tx->cq->progress.ep_count)++] = opx_ep;
		opx_ep->is_tx_cq_bound						   = true;
	}

	if (opx_ep->rx->cq && !opx_ep->is_rx_cq_bound) {
		// if rx and tx are sharing a cq, only bind it once.
		if (opx_ep->rx->cq != opx_ep->tx->cq) {
			opx_ep->rx->cq->progress.ep[(opx_ep->rx->cq->progress.ep_count)++] = opx_ep;
		}
		opx_ep->is_rx_cq_bound = true;
	}
}

static int fi_opx_open_command_queues(struct fi_opx_ep *opx_ep)
{
	struct fi_opx_domain *opx_domain;

	if (!opx_ep) {
		errno = FI_EINVAL;
		return -errno;
	}
	opx_domain = opx_ep->domain;

	// For scalable endpoints, if we're the first (rx or tx) side, initialize, otherwise
	// use the data structure built by the other side.  When we open a device driver
	// we get both an rx and tx, so we want to share, and the common model is to create
	// scalable endpoints with a 1-1 relationship, so we'll share the tx/rx to avoid
	// creating 2x endpoints
	bool do_init = true;
	if (opx_ep->ep_fid.fid.fclass == FI_CLASS_RX_CTX || opx_ep->ep_fid.fid.fclass == FI_CLASS_TX_CTX) {
		if (opx_ep->sep->hfi1[opx_ep->sep_index]) {
			do_init		    = false;
			opx_ep->hfi	    = opx_ep->sep->hfi1[opx_ep->sep_index];
			opx_ep->reliability = opx_ep->sep->reliability[opx_ep->sep_index];
			opx_ep->tx	    = opx_ep->sep->tx[opx_ep->sep_index];
			opx_ep->rx	    = opx_ep->sep->rx[opx_ep->sep_index];

			fi_opx_ref_inc(&opx_ep->reliability->ref_cnt, "reliability service");
			fi_opx_ref_inc(&opx_ep->tx->ref_cnt, "tx");
			fi_opx_ref_inc(&opx_ep->rx->ref_cnt, "rx");
			fi_opx_ref_inc(&opx_ep->hfi->ref_cnt, "HFI context");
		}
	}

	if (do_init) {
		if (opx_ep->hfi != NULL) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "hfi context already initialized\n");
			abort();
		}

		/*
		 * open the hfi1 context, determines JKR or WFR
		 */
		opx_ep->hfi = fi_opx_hfi1_context_open(&opx_ep->ep_fid, opx_domain->unique_job_key);
		if (!opx_ep->hfi) {
			errno = FI_EBUSY;
			return -errno;
		}
		fi_opx_ref_inc(&opx_ep->hfi->ref_cnt, "HFI context");

		/* The global was set early (userinit), may be changed now on mixed networks */
		int mixed_network = 0;
		if (fi_param_get_int(fi_opx_global.prov, "mixed_network", &mixed_network) == FI_SUCCESS) {
			if (fi_opx_global.hfi_local_info.type == OPX_HFI1_JKR) {
				if (mixed_network == 1) {
					fi_opx_global.hfi_local_info.type = OPX_HFI1_JKR_9B;
					opx_ep->hfi->hfi1_type		  = OPX_HFI1_JKR_9B;
					FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
						     "Mixed network: Set HFI type to %s.\n",
						     OPX_HFI_TYPE_STRING(fi_opx_global.hfi_local_info.type));
				} else if (mixed_network == 0) {
					FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
						     "Not mixed network: Set HFI type to %s.\n",
						     OPX_HFI_TYPE_STRING(fi_opx_global.hfi_local_info.type));
				} else {
					FI_WARN(fi_opx_global.prov, FI_LOG_AV,
						"Unsupported value (%d) for FI_OPX_MIXED_NETWORK, using default HFI type %s.\n",
						mixed_network, OPX_HFI_TYPE_STRING(fi_opx_global.hfi_local_info.type));
				}
			}
		}

		FI_INFO(fi_opx_global.prov, FI_LOG_EP_DATA,
			"Opened hfi %p, HFI type %s, unit %#X, port %#X, ref_cnt %#lX, rcv ctxt %#X, send ctxt %#X, \n",
			opx_ep->hfi, OPX_HFI_TYPE_STRING(OPX_HFI1_TYPE), opx_ep->hfi->hfi_unit, opx_ep->hfi->hfi_port,
			opx_ep->hfi->ref_cnt, opx_ep->hfi->ctrl->ctxt_info.ctxt,
			opx_ep->hfi->ctrl->ctxt_info.send_ctxt);

		if (OPX_HFI1_TYPE & OPX_HFI1_JKR || OPX_HFI1_TYPE & OPX_HFI1_JKR_9B) {
			OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA, "*****HFI type is JKR (CN5000)\n");
		} else {
			OPX_LOG_OBSERVABLE(FI_LOG_EP_DATA, "*****HFI type is WFR (Omni-path)\n");
		}

		/* Set route_control after hfi1 type is selected and before any models are initialized
		 * Note that "out of order" route control will be disabled if tid is enabled*
		 */
		opx_set_route_control_value(opx_ep->use_expected_tid_rzv);

		void *mem = NULL;
		mem	  = malloc(sizeof(struct fi_opx_ep_reliability) + FI_OPX_CACHE_LINE_SIZE);
		if (!mem) {
			FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA, "no memory for endpoint");
			errno = FI_ENOMEM;
			goto err;
		}
		opx_ep->reliability = (struct fi_opx_ep_reliability *) (((uintptr_t) mem + FI_OPX_CACHE_LINE_SIZE) &
									~(FI_OPX_CACHE_LINE_SIZE - 1));
		memset(opx_ep->reliability, 0, sizeof(struct fi_opx_ep_reliability));
		opx_ep->reliability->mem = mem;
		fi_opx_ref_inc(&opx_ep->reliability->ref_cnt, "reliability service");

		opx_ep->reliability->state.kind = fi_opx_select_reliability(opx_ep);

		if (OFI_RELIABILITY_KIND_OFFLOAD == opx_ep->reliability->state.kind) {
			opx_ep->reliability->rx = opx_domain->reliability_rx_offload;
			/* initialize reliability client */
			fi_opx_reliability_client_init(&opx_ep->reliability->state,
						       &opx_domain->reliability_service_offload,
						       opx_ep->hfi->info.rxe.id, /* rx */
						       fi_opx_ep_rx_reliability_process_packet);
		} else if (OFI_RELIABILITY_KIND_ONLOAD == opx_ep->reliability->state.kind) {
			fi_opx_reliability_service_init(&opx_ep->reliability->service, opx_domain->unique_job_key,
							opx_ep->hfi, OFI_RELIABILITY_KIND_ONLOAD);
			fi_opx_reliability_model_init_16B(&opx_ep->reliability->service, opx_ep->hfi);
			opx_ep->reliability->rx = opx_ep->hfi->info.rxe.id;
			fi_opx_reliability_client_init(&opx_ep->reliability->state, &opx_ep->reliability->service,
						       opx_ep->hfi->info.rxe.id, /* rx */
						       fi_opx_ep_rx_reliability_process_packet);
		}

		if (opx_ep->reliability->state.kind == OFI_RELIABILITY_KIND_ONLOAD &&
		    fi_opx_select_app_reliability(opx_ep) == OFI_RELIABILITY_APP_KIND_DAOS) {
			opx_ep->daos_info.do_resynch_remote_ep = true;
			opx_ep->daos_info.hfi_rank_enabled     = (opx_ep->hfi->daos_info.rank != -1);
			opx_ep->daos_info.av_rank_hashmap      = NULL;
		} else {
			opx_ep->daos_info.do_resynch_remote_ep = false;
			opx_ep->daos_info.hfi_rank_enabled     = false;
			opx_ep->daos_info.av_rank_hashmap      = NULL;
		}

		// Allocate both the tx and the rx side of the endpoint
		mem = malloc(sizeof(struct fi_opx_ep_tx) + FI_OPX_CACHE_LINE_SIZE);
		if (!mem) {
			FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA, "no memory for tx");
			errno = FI_ENOMEM;
			goto err;
		}
		opx_ep->tx = (struct fi_opx_ep_tx *) (((uintptr_t) mem + FI_OPX_CACHE_LINE_SIZE) &
						      ~(FI_OPX_CACHE_LINE_SIZE - 1));
		memset(opx_ep->tx, 0, sizeof(struct fi_opx_ep_tx));
		opx_ep->tx->mem = mem;
		fi_opx_ref_inc(&opx_ep->tx->ref_cnt, "tx context");

		mem = malloc(sizeof(struct fi_opx_ep_rx) + FI_OPX_CACHE_LINE_SIZE);
		if (!mem) {
			FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA, "no memory for rx");
			errno = FI_ENOMEM;
			goto err;
		}
		opx_ep->rx = (struct fi_opx_ep_rx *) (((uintptr_t) mem + FI_OPX_CACHE_LINE_SIZE) &
						      ~(FI_OPX_CACHE_LINE_SIZE - 1));
		memset(opx_ep->rx, 0, sizeof(struct fi_opx_ep_rx));
		opx_ep->rx->mem = mem;
		fi_opx_ref_inc(&opx_ep->rx->ref_cnt, "rx context");

		// If we are a scalable endpoint, track the RX/TX in the SEP so when the other side is fetched
		// we can point it to the existing side
		if ((opx_ep->ep_fid.fid.fclass == FI_CLASS_RX_CTX) || (opx_ep->ep_fid.fid.fclass == FI_CLASS_TX_CTX)) {
			opx_ep->sep->hfi1[opx_ep->sep_index]	    = opx_ep->hfi;
			opx_ep->sep->reliability[opx_ep->sep_index] = opx_ep->reliability;
			opx_ep->sep->tx[opx_ep->sep_index]	    = opx_ep->tx;
			opx_ep->sep->rx[opx_ep->sep_index]	    = opx_ep->rx;
		}

		// Check data structure alignments
		uintptr_t alignment_check = (uintptr_t) opx_ep;
		if ((alignment_check & 0x03Full) != 0) {
			fprintf(stderr, "%s:%s():%d bad structure alignment !\n", __FILE__, __func__, __LINE__);
			abort();
		}

		alignment_check = (uintptr_t) &opx_ep->tx->pio_state;
		if ((alignment_check & 0x03Full) != 0) {
			fprintf(stderr, "%s:%s():%d bad structure alignment !\n", __FILE__, __func__, __LINE__);
			abort();
		}

		alignment_check = (uintptr_t) &opx_ep->tx->send_9B;
		if ((alignment_check & 0x03Full) != 0) {
			fprintf(stderr, "%s:%s():%d bad structure alignment !\n", __FILE__, __func__, __LINE__);
			abort();
		}

		alignment_check = (uintptr_t) &opx_ep->rx->cq_pending_ptr;
		if ((alignment_check & 0x03Full) != 0) {
			fprintf(stderr, "%s:%s():%d bad structure alignment !\n", __FILE__, __func__, __LINE__);
			abort();
		}
		// Initialize the tx/rx
		opx_ep->rx->cq		     = NULL;
		opx_ep->rx->cq_pending_ptr   = NULL;
		opx_ep->rx->cq_completed_ptr = NULL;
		opx_ep->rx->cq_err_ptr	     = NULL;

		/* Early arrival queues (queue[0] == FI_TAGGED, queue[1] == FI_MSG) */
		opx_ep->rx->queue[0].ue.head	 = NULL;
		opx_ep->rx->queue[0].ue.tail	 = NULL;
		opx_ep->rx->queue[1].ue.head	 = NULL;
		opx_ep->rx->queue[1].ue.tail	 = NULL;
		opx_ep->rx->mp_egr_queue.ue.head = NULL;
		opx_ep->rx->mp_egr_queue.ue.tail = NULL;

		/* Context match queues (queue[0] == FI_TAGGED, queue[1] == FI_MSG) */
		slist_init(&opx_ep->rx->queue[0].mq);
		slist_init(&opx_ep->rx->queue[1].mq);
		slist_init(&opx_ep->rx->mp_egr_queue.mq);

		opx_ep->tx->cq		     = NULL;
		opx_ep->tx->cq_pending_ptr   = NULL;
		opx_ep->tx->cq_completed_ptr = NULL;
		opx_ep->tx->cq_err_ptr	     = NULL;

		opx_ep->tx->cq		     = NULL;
		opx_ep->tx->cq_bind_flags    = 0;
		opx_ep->tx->do_cq_completion = 0;

		if (opx_ep->ep_fid.fid.fclass == FI_CLASS_TX_CTX || opx_ep->ep_fid.fid.fclass == FI_CLASS_RX_CTX) {
			struct fi_opx_av *opx_av    = opx_ep->sep->av;
			const unsigned	  ep_tx_max = sizeof(opx_av->ep_tx) / sizeof(struct fi_opx_ep *);
			if (opx_av->ep_tx_count < ep_tx_max) {
				opx_av->ep_tx[opx_av->ep_tx_count++] = opx_ep;
			} else {
				FI_WARN(fi_opx_global.prov, FI_LOG_AV, "Too many ep tx contexts (max = %u)\n",
					ep_tx_max);
				abort();
			}
		}
#ifdef OPX_HMEM
#if HAVE_CUDA
		opx_ep->hmem_copy_buf = NULL;
		cudaError_t cuda_rc = cudaHostAlloc((void **) &opx_ep->hmem_copy_buf, OPX_MP_EGR_MAX_PAYLOAD_BYTES_MAX,
						    cudaHostAllocDefault);
		if (cuda_rc != cudaSuccess) {
			FI_WARN(fi_opx_global.prov, FI_LOG_CORE,
				"Failed allocating HMEM bounce buf with cudaHostAlloc(), returned cudaError %d.\n",
				cuda_rc);
			errno = FI_ENOMEM;
			goto err;
		}
		assert(opx_ep->hmem_copy_buf);
#else
		opx_ep->hmem_copy_buf = malloc(OPX_MP_EGR_MAX_PAYLOAD_BYTES_MAX);
		if (opx_ep->hmem_copy_buf == NULL) {
			FI_WARN(fi_opx_global.prov, FI_LOG_CORE, "Failed allocating HMEM bounce buf with malloc().\n");
			errno = FI_ENOMEM;
			goto err;
		}
#endif
#else
		opx_ep->hmem_copy_buf = NULL;
#endif
		if (opx_ep->use_expected_tid_rzv == 1 && (opx_ep->hfi->runtime_flags & HFI1_CAP_TID_UNMAP)) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
				"Expected receive (TID) cannot be enabled. HFI TID_UNMAP capability is turned on\n");
			opx_ep->use_expected_tid_rzv = 0;
		}
	}

	// Apply the saved info objects from the fi_getinfo call
	if (-1 == fi_opx_apply_info_and_init_ops(opx_ep)) {
		FI_WARN(fi_opx_global.prov, FI_LOG_CORE, "fi_opx_apply_info_and_init_ops failed.\n");
		errno = FI_EPERM;
		goto err;
	}

	/* Lock before enqueing on cq */
	fi_opx_lock(&opx_ep->lock);
	// Apply the bind flags that were captured during object bind
	fi_opx_apply_bind_flags(opx_ep);

	FI_INFO(fi_opx_global.prov, FI_LOG_EP_DATA, "HFI1 PIO credits: %u\n", opx_ep->hfi->state.pio.credits_total);
	bool rx_is_init = false;
	if (ofi_recv_allowed(opx_ep->rx->caps) || ofi_rma_target_allowed(opx_ep->rx->caps)) {
		/* verify there is a completion queue associated with the rx context */
		if (!opx_ep->rx->cq) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
				"No completion queue bound to receive context, using TX cq for reliability handling\n");
			opx_ep->rx->cq = opx_ep->tx->cq;
		}

		if (0 != fi_opx_ep_rx_init(opx_ep)) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Error during rx context initialization\n");
			errno = FI_ENOENT;
			goto unlock;
		} else {
			rx_is_init = true;
		}
	}

	bool tx_is_init = false;
	if (ofi_send_allowed(opx_ep->tx->caps) || ofi_rma_initiate_allowed(opx_ep->tx->caps)) {
		/* verify there is a completion queue associated with the tx context */
		if (!opx_ep->tx->cq) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "No completion queue bound to send context\n");
			errno = FI_ENOENT;
			goto unlock;
		}

		if (fi_opx_ep_tx_init(opx_ep, opx_domain)) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Too many tx contexts\n");
			errno = FI_ENOENT;
			goto unlock;
		} else {
			tx_is_init = true;
		}
	}

	if (!rx_is_init && (opx_ep->ep_fid.fid.fclass == FI_CLASS_RX_CTX || opx_ep->ep_fid.fid.fclass == FI_CLASS_EP)) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA,
		       "Force enabling RX contexts for communication despite caps not being set\n");
		if (0 != fi_opx_ep_rx_init(opx_ep)) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Error during rx context initialization\n");
			errno = FI_ENOENT;
			goto unlock;
		}
	}

	if (!tx_is_init && (opx_ep->ep_fid.fid.fclass == FI_CLASS_TX_CTX || opx_ep->ep_fid.fid.fclass == FI_CLASS_EP)) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA,
		       "Force enabling TX contexts for communication despite caps not being set\n");
		if (fi_opx_ep_tx_init(opx_ep, opx_domain)) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Too many tx contexts\n");
			errno = FI_ENOENT;
			goto unlock;
		}
	}

	/* Unlock */
	fi_opx_unlock(&opx_ep->lock);
	return 0;
unlock:
	/* Unlock */
	fi_opx_unlock(&opx_ep->lock);
err:
	// Placeholder functions to be uncommented when they do more than return 0
	/*
	fi_opx_finalize_cm_ops(&opx_ep->ep_fid.fid);
	fi_opx_finalize_msg_ops(&opx_ep->ep_fid);
	fi_opx_finalize_rma_ops(&opx_ep->ep_fid);
	fi_opx_finalize_tagged_ops(&opx_ep->ep_fid);
	fi_opx_finalize_atomic_ops(&opx_ep->ep_fid);
	*/
	return -1;
}

static int fi_opx_enable_ep(struct fid_ep *ep)
{
	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "enable ep\n");

	int		  ret;
	struct fi_opx_ep *opx_ep = container_of(ep, struct fi_opx_ep, ep_fid);
	ret			 = fi_opx_check_ep(opx_ep);
	if (ret) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "ep enable failed\n");
		return -errno;
	}

	ret = fi_opx_open_command_queues(opx_ep);
	if (ret) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "failed to assign command queues\n");
		return -errno;
	}

	ret = fi_opx_enable_msg_ops(ep);
	if (ret) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "failed to enable msg ops\n");
		return -errno;
	}

	ret = fi_opx_enable_rma_ops(ep);
	if (ret) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "failed to enable rma ops\n");
		return -errno;
	}

	ret = fi_opx_enable_atomic_ops(ep);
	if (ret) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "failed to enable rma ops\n");
		return -errno;
	}

	ret = fi_opx_enable_tagged_ops(ep);
	if (ret) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "failed to enable rma ops\n");
		return -errno;
	}

	/* connect any inserted table (av) addresses */
	if (opx_ep->av->table_addr) {
		ssize_t rc = fi_opx_ep_tx_connect(opx_ep, opx_ep->av->addr_count, opx_ep->av->table_addr, NULL);

		if (OFI_UNLIKELY(rc)) {
			errno = FI_EAGAIN;
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "failed to connect to av addresses\n");
			return -errno;
		}
	}

	opx_ep->state = FI_OPX_EP_INITITALIZED_ENABLED;

	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "ep enabled\n");
	return 0;
}

static int fi_opx_control_ep(fid_t fid, int command, void *arg)
{
	struct fid_ep *ep;
	ep = container_of(fid, struct fid_ep, fid);

	switch (command) {
	case FI_ENABLE:
		return fi_opx_enable_ep(ep);
	default:
		return -FI_ENOSYS;
	}

	return 0;
}

static int fi_opx_getopt_ep(fid_t fid, int level, int optname, void *optval, size_t *optlen)
{
	struct fi_opx_ep *opx_ep = container_of(fid, struct fi_opx_ep, ep_fid);

	if (level != FI_OPT_ENDPOINT) {
		return -FI_ENOPROTOOPT;
	}

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:
		*(size_t *) optval = opx_ep->rx->min_multi_recv;
		*optlen		   = sizeof(size_t);
		break;
	case FI_OPT_CM_DATA_SIZE:
		*(size_t *) optval = 0;
		*optlen		   = sizeof(size_t);
		break;
	default:
		return -FI_ENOPROTOOPT;
	}

	return 0;
}

static int fi_opx_setopt_ep(fid_t fid, int level, int optname, const void *optval, size_t optlen)
{
	struct fi_opx_ep *opx_ep = container_of(fid, struct fi_opx_ep, ep_fid);

	if (level != FI_OPT_ENDPOINT) {
		return -FI_ENOPROTOOPT;
	}

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:
		opx_ep->rx->min_multi_recv = *(size_t *) optval;
		break;
	case FI_OPT_CUDA_API_PERMITTED:
		if (!hmem_ops[FI_HMEM_CUDA].initialized) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_CTRL,
				"Cannot set CUDA API permitted when"
				"CUDA library or CUDA device is not available\n");
			return -FI_EINVAL;
		}
		/* our HMEM support does not make calls to CUDA API,
		 * therefore we can accept any option for FI_OPT_CUDA_API_PERMITTED.
		 */
		return FI_SUCCESS;
	default:
		return -FI_ENOPROTOOPT;
	}

	return 0;
}

int fi_opx_ep_rx_cancel(struct fi_opx_ep_rx *rx, const uint64_t static_flags, const uintptr_t cancel_context,
			const int lock_required)
{
	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "(begin)\n");

	assert(!lock_required);
	const uint64_t kind = (static_flags & FI_TAGGED) ? 0 : 1;

	/*
	 * search the match queue for this context
	 */

	struct opx_context *prev = NULL;
	struct opx_context *item = (struct opx_context *) rx->queue[kind].mq.head;
	while (item) {
		const uintptr_t compare_context = (uintptr_t) item->err_entry.op_context;

		if (cancel_context == compare_context) {
			if (prev) {
				prev->next = item->next;
			} else {
				rx->queue[kind].mq.head = (struct slist_entry *) item->next;
			}

			if (!item->next) {
				rx->queue[kind].mq.tail = (struct slist_entry *) prev;
			}

			item->byte_counter	      = 0;
			item->next		      = NULL;
			item->err_entry.flags	      = item->flags;
			item->err_entry.len	      = 0;
			item->err_entry.buf	      = 0;
			item->err_entry.data	      = 0;
			item->err_entry.tag	      = item->tag;
			item->err_entry.olen	      = 0;
			item->err_entry.err	      = FI_ECANCELED;
			item->err_entry.prov_errno    = 0;
			item->err_entry.err_data      = NULL;
			item->err_entry.err_data_size = 0;

			if (lock_required) {
				fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
				abort();
			}
			slist_insert_tail((struct slist_entry *) item, rx->cq_err_ptr);

			FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "(end) canceled\n");
			return FI_ECANCELED;
		}

		prev = item;
		item = item->next;
	}

	/* context not found in 'kind' match queue */
	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "(end) not found\n");
	return 0;
}

static ssize_t fi_opx_cancel(fid_t fid, void *context)
{
	struct fi_opx_ep *opx_ep = container_of(fid, struct fi_opx_ep, ep_fid);

	if (IS_PROGRESS_MANUAL(opx_ep->domain)) {
		const enum fi_threading threading = opx_ep->domain->threading;
		const int lock_required		  = fi_opx_threading_lock_required(threading, fi_opx_global.progress);

		fi_opx_lock_if_required(&opx_ep->lock, lock_required);
		if (opx_ep->rx->caps & FI_MSG) {
			fi_opx_ep_rx_cancel(opx_ep->rx, FI_MSG, (const uintptr_t) context, FI_OPX_LOCK_NOT_REQUIRED);
		}

		if (opx_ep->rx->caps & FI_TAGGED) {
			fi_opx_ep_rx_cancel(opx_ep->rx, FI_TAGGED, (const uintptr_t) context, FI_OPX_LOCK_NOT_REQUIRED);
		}
		fi_opx_unlock_if_required(&opx_ep->lock, lock_required);

	} else {
		abort();
	}

	return 0;
}

static struct fi_ops fi_opx_fi_ops = {.size	= sizeof(struct fi_ops),
				      .close	= fi_opx_close_ep,
				      .bind	= fi_opx_bind_ep,
				      .control	= fi_opx_control_ep,
				      .ops_open = fi_no_ops_open};

static struct fi_ops_ep fi_opx_ep_ops = {.size	       = sizeof(struct fi_ops_ep),
					 .cancel       = fi_opx_cancel,
					 .getopt       = fi_opx_getopt_ep,
					 .setopt       = fi_opx_setopt_ep,
					 .tx_ctx       = fi_no_tx_ctx,
					 .rx_ctx       = fi_no_rx_ctx,
					 .rx_size_left = fi_no_rx_size_left,
					 .tx_size_left = fi_no_tx_size_left};

int fi_opx_alloc_default_rx_attr(struct fi_rx_attr **rx_attr)
{
	struct fi_rx_attr *attr;

	attr = calloc(1, sizeof(*attr));
	if (!attr) {
		goto err;
	}

	attr->caps	= FI_OPX_DEFAULT_RX_CAPS;
	attr->mode	= FI_ASYNC_IOV;
	attr->op_flags	= 0;
	attr->msg_order = FI_OPX_DEFAULT_MSG_ORDER;
	attr->size	= SIZE_MAX; // FI_OPX_RX_SIZE;
	attr->iov_limit = FI_OPX_IOV_LIMIT;

	*rx_attr = attr;

	return 0;
err:
	errno = FI_EINVAL;
	return -errno;
}

int fi_opx_check_rx_attr(struct fi_rx_attr *rx_attr, uint64_t hinted_caps)
{
	if ((rx_attr) && ((rx_attr->caps | hinted_caps) != hinted_caps)) {
		FI_DBG_TRACE(
			fi_opx_global.prov, FI_LOG_EP_DATA,
			"info->rx_attr->caps = 0x%016lx, info->caps = 0x%016lx, (info->rx_attr->caps | info->caps) = 0x%016lx, ((info->rx_attr->caps | info->caps) ^ info->caps) = 0x%016lx\n",
			rx_attr->caps, hinted_caps, (rx_attr->caps | hinted_caps),
			((rx_attr->caps | hinted_caps) ^ hinted_caps));
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_FABRIC,
		       "The rx_attr capabilities (0x%016lx) must be a subset of those requested of the associated endpoint (0x%016lx)\n",
		       rx_attr->caps, hinted_caps);
		goto err;
	}
	return 0;
err:

	errno = FI_EINVAL;
	return -errno;
}

int fi_opx_alloc_default_tx_attr(struct fi_tx_attr **tx_attr)
{
	struct fi_tx_attr *attr;

	attr = calloc(1, sizeof(*attr));
	if (!attr) {
		goto err;
	}

	attr->caps	    = FI_OPX_DEFAULT_TX_CAPS;
	attr->mode	    = FI_ASYNC_IOV;
	attr->op_flags	    = FI_TRANSMIT_COMPLETE;
	attr->msg_order	    = FI_OPX_DEFAULT_MSG_ORDER;
	attr->inject_size   = FI_OPX_HFI1_PACKET_IMM;
	attr->size	    = SIZE_MAX;
	attr->iov_limit	    = FI_OPX_IOV_LIMIT;
	attr->rma_iov_limit = 1;

	*tx_attr = attr;

	return 0;
err:
	errno = FI_EINVAL;
	return -errno;
}

int fi_opx_check_tx_attr(struct fi_tx_attr *tx_attr, uint64_t hinted_caps)
{
	if (tx_attr->inject_size > FI_OPX_HFI1_PACKET_IMM) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA, "unavailable [bad inject_size (%lu)]\n",
		       tx_attr->inject_size);
		goto err;
	}

	if ((tx_attr->caps | hinted_caps) != hinted_caps) {
		FI_DBG_TRACE(
			fi_opx_global.prov, FI_LOG_EP_DATA,
			"info->tx_attr->caps = 0x%016lx, info->caps = 0x%016lx, (info->tx_attr->caps | info->caps) = 0x%016lx, ((info->tx_attr->caps | info->caps) ^ info->caps) = 0x%016lx\n",
			tx_attr->caps, hinted_caps, (tx_attr->caps | hinted_caps),
			((tx_attr->caps | hinted_caps) ^ hinted_caps));
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_FABRIC,
		       "The tx_attr capabilities (0x%016lx) must be a subset of those requested of the associated endpoint (0x%016lx)\n",
		       tx_attr->caps, hinted_caps);
		goto err;
	}

	return 0;
err:
	errno = FI_EINVAL;
	return -errno;
}

int fi_opx_alloc_default_ep_attr(struct fi_ep_attr **ep_attr)
{
	struct fi_ep_attr *attr;

	attr = calloc(1, sizeof(*attr));
	if (!attr) {
		goto err;
	}

	attr->type		 = FI_EP_RDM;
	attr->protocol		 = FI_PROTO_OPX;
	attr->protocol_version	 = FI_OPX_PROTOCOL_VERSION;
	attr->max_msg_size	 = FI_OPX_MAX_MSG_SIZE;
	attr->msg_prefix_size	 = 0;
	attr->max_order_raw_size = FI_OPX_MAX_ORDER_RAW_SIZE;
	attr->max_order_war_size = FI_OPX_MAX_ORDER_WAR_SIZE;
	attr->max_order_waw_size = FI_OPX_MAX_ORDER_WAW_SIZE;
	attr->mem_tag_format	 = FI_OPX_MEM_TAG_FORMAT;
	attr->tx_ctx_cnt	 = 1;
	attr->rx_ctx_cnt	 = 1;

	*ep_attr = attr;

	return 0;
err:
	errno = FI_EINVAL;
	return -errno;
}

int fi_opx_check_ep_attr(struct fi_ep_attr *check_attr)
{
	if (!check_attr) {
		goto err;
	}

	struct fi_ep_attr  my_attr = *check_attr;
	struct fi_ep_attr *attr	   = &my_attr;

	switch (attr->protocol) {
	case FI_PROTO_UNSPEC:
		attr->type     = FI_EP_RDM;
		attr->protocol = FI_PROTO_OPX;
		break;
	case FI_PROTO_OPX:
		break;
	default:
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA, "unavailable [bad protocol (%u)]\n",
		       attr->protocol);
		goto err;
	}
	if (attr->max_msg_size > FI_OPX_MAX_MSG_SIZE) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA, "unavailable [bad max_msg_size (%lu)]\n",
		       attr->max_msg_size);
		goto err;
	}
	if (attr->max_order_raw_size > FI_OPX_MAX_ORDER_RAW_SIZE) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA, "unavailable [bad max_order_raw_size (%lu)\n",
		       attr->max_order_raw_size);
		goto err;
	}
	if (attr->max_order_war_size > FI_OPX_MAX_ORDER_WAR_SIZE) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA, "unavailable [bad max_order_war_size (%lu)\n",
		       attr->max_order_war_size);
		goto err;
	}
	if (attr->max_order_waw_size > FI_OPX_MAX_ORDER_WAW_SIZE) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA, "unavailable [bad max_order_waw_size (%lu)\n",
		       attr->max_order_waw_size);
		goto err;
	}
	if (attr->mem_tag_format && attr->mem_tag_format & ~FI_OPX_MEM_TAG_FORMAT) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA, "unavailable [bad mem_tag_format (%lx)\n",
		       attr->mem_tag_format);
		goto err;
	}
	/* TODO: what msg orders do we not support? */

	return 0;
err:
	return -FI_EINVAL;
}

int opx_get_drv_ver(char *drv_ver)
{
	FILE *p;

	p = popen(OPX_MODINFO_DRV_VERS, "r");
	if (p == NULL) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "popen failed, unable to get hfi1 version\n");
		return -FI_EIO;
	}

	char *fgets_res = fgets(drv_ver, FI_OPX_VER_CHECK_BUF_LEN, p);
	pclose(p);

	if (fgets_res == NULL) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "fgets failed, unable to get hfi1 version\n");
		return -FI_EIO;
	}

	return FI_SUCCESS;
}

int opx_get_srcver_modinfo(char *srcver_modinfo)
{
	FILE *p;

	p = popen(OPX_MODINFO_SRC_VERS, "r");
	if (p == NULL) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "popen failed, unable to get hfi1 srcversion\n");
		return -FI_EIO;
	}

	char *fgets_res = fgets(srcver_modinfo, FI_OPX_VER_CHECK_BUF_LEN, p);
	pclose(p);

	if (fgets_res == NULL) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "fgets failed, unable to get hfi1 srcversion\n");
		return -FI_EIO;
	}

	return FI_SUCCESS;
}

int opx_get_srcver_sys(char *srcver_sys)
{
	FILE *p;
	p = popen("cat /sys/module/hfi1/srcversion | xargs", "r");
	if (p == NULL) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
			"popen failed, unable to get /sys/module/hfi1/srcversion\n");
		return -FI_EIO;
	}

	char *fgets_res = fgets(srcver_sys, FI_OPX_VER_CHECK_BUF_LEN, p);
	pclose(p);

	if (fgets_res == NULL) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
			"fgets failed, unable to get /sys/module/hfi1/srcversion\n");
		return -FI_EIO;
	}

	return FI_SUCCESS;
}

int opx_hfi_drv_version_check(char *min_version)
{
	char drv_ver[FI_OPX_VER_CHECK_BUF_LEN]	      = {0};
	char srcver_modinfo[FI_OPX_VER_CHECK_BUF_LEN] = {0};
	char srcver_sys[FI_OPX_VER_CHECK_BUF_LEN]     = {0};

	if (access(OPX_MODINFO_PATH, F_OK)) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "modinfo utility not in standard location of %s\n",
			OPX_MODINFO_PATH);
		return 0;
	};
	if (access(OPX_MODINFO_PATH, X_OK)) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "User does not have execute permissions on %s\n",
			OPX_MODINFO_PATH);
		return 0;
	};

	if (opx_get_drv_ver(drv_ver) != FI_SUCCESS) {
		return 0;
	}

	if (opx_get_srcver_modinfo(srcver_modinfo) != FI_SUCCESS) {
		return 0;
	}

	if (opx_get_srcver_sys(srcver_sys) != FI_SUCCESS) {
		return 0;
	}

	if (strcmp(srcver_modinfo, srcver_sys) != 0) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
			"hfi1 srcversion doesn't "
			"match system. srcver_modinfo = %s srcver_sys = %s\n",
			srcver_modinfo, srcver_sys);
		return 0;
	}

	if (strverscmp(drv_ver, min_version) < 0) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "hfi1 driver version %s is less than minimum required %s\n",
			drv_ver, min_version);
		return 0;
	}

	return 1;
}

int opx_is_tid_allowed()
{
	struct utsname uname_data;
	return (!uname(&uname_data) && (strverscmp(uname_data.release, "6.5") >= 0)) ||
	       opx_hfi_drv_version_check("10.14");
}

int fi_opx_endpoint_rx_tx(struct fid_domain *dom, struct fi_info *info, struct fid_ep **ep, void *context)
{
	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "(begin)\n");

	int		      ret;
	struct fi_opx_ep     *opx_ep	 = NULL;
	struct fi_opx_domain *opx_domain = NULL;

	if (!info || !dom) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "no info/domain supplied\n");
		errno = FI_EINVAL;
		goto err;
	}

	ret = fi_opx_fid_check(&dom->fid, FI_CLASS_DOMAIN, "domain");
	if (ret) {
		return ret;
	}

	ret = fi_opx_check_info(info);
	if (ret) {
		return ret;
	}

	void *mem = NULL;
	mem	  = malloc(sizeof(struct fi_opx_ep) + FI_OPX_CACHE_LINE_SIZE);
	if (!mem) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA, "no memory for endpoint");
		errno = FI_ENOMEM;
		goto err;
	}
	opx_ep = (struct fi_opx_ep *) (((uintptr_t) mem + FI_OPX_CACHE_LINE_SIZE) & ~(FI_OPX_CACHE_LINE_SIZE - 1));
	memset(opx_ep, 0, sizeof(struct fi_opx_ep));
	opx_ep->mem = mem;

#ifdef FLIGHT_RECORDER_ENABLE
	struct flight_recorder *fr = NULL;
	fr			   = malloc(sizeof(struct flight_recorder));
	if (!fr) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_EP_DATA, "No memory for flight recorder");
		errno = FI_ENOMEM;
		goto err;
	}
	memset(fr, 0, sizeof(struct flight_recorder));
	FLIGHT_RECORDER_INIT(fr);
	opx_ep->fr = fr;
#endif

	opx_ep->ep_fid.fid.fclass  = FI_CLASS_EP;
	opx_ep->ep_fid.fid.context = context;
	opx_ep->ep_fid.fid.ops	   = &fi_opx_fi_ops;
	opx_ep->ep_fid.ops	   = &fi_opx_ep_ops;

	opx_domain     = container_of(dom, struct fi_opx_domain, domain_fid);
	opx_ep->domain = opx_domain;
	opx_ep->type   = info->ep_attr->type;

	ofi_bufpool_create(&opx_ep->rma_counter_pool, sizeof(struct fi_opx_completion_counter), 0, UINT_MAX, 2048, 0);

	ofi_bufpool_create(&opx_ep->rzv_completion_pool, sizeof(struct fi_opx_rzv_completion), 0, UINT_MAX, 2048, 0);

	ofi_spin_init(&opx_ep->lock);

	fi_opx_ref_inc(&opx_domain->ref_cnt, "domain");

	opx_ep->common_info = fi_dupinfo(info);
	opx_ep->av_type	    = info->domain_attr->av_type; /* Use input av_type */

	/* just save an extra pointer dereference by storing
	   the TID domain directly in each endpoint */
	opx_ep->tid_domain = opx_ep->domain->tid_domain;

	/* enable/disable receive side (CTS) expected receive (TID) */
	int tid_disable_env;
	int tid_disable_specified =
		(fi_param_get_bool(fi_opx_global.prov, "tid_disable", &tid_disable_env) == FI_SUCCESS);
	if (tid_disable_specified) {
		if (tid_disable_env) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
				"FI_OPX_TID_DISABLE specified as TRUE, disabling TID.\n");
			opx_ep->use_expected_tid_rzv = OPX_TID_ENABLE_OFF;
		} else {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
				"FI_OPX_TID_DISABLE specified as FALSE (default option), enabling TID.\n");
			opx_ep->use_expected_tid_rzv = OPX_TID_ENABLE_ON;
		}
	} else {
		opx_ep->use_expected_tid_rzv = OPX_TID_ENABLE_ON;
	}

	int expected_receive_enable_env;
	if (fi_param_get_bool(fi_opx_global.prov, "expected_receive_enable", &expected_receive_enable_env) ==
	    FI_SUCCESS) {
		if (tid_disable_specified) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
				"FI_OPX_EXPECTED_RECEIVE_ENABLE is deprecated. Ignoring because replacement environment variable FI_OPX_TID_DISABLE was specified and takes precedence.\n");
		} else if (!expected_receive_enable_env) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
				"FI_OPX_EXPECTED_RECEIVE_ENABLE was specified as OFF, but is deprecated. Expected receive (TID) will be disabled, but please use FI_OPX_TID_DISABLE=1 in the future.\n");
			opx_ep->use_expected_tid_rzv = OPX_TID_ENABLE_OFF;
		} else {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
				"FI_OPX_EXPECTED_RECEIVE_ENABLE was specified as ON, but is deprecated. Expected receive (TID) is enabled by default. Ignoring.\n");
		}
	}

#ifndef OPX_DEV_OVERRIDE
	if (opx_ep->use_expected_tid_rzv == OPX_TID_ENABLE_ON && !opx_is_tid_allowed()) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
			"Expected receive (TID) cannot be enabled due to unsupported driver version. Upgrade Omnipath driver to enable this feature. Disabling TID.\n");
		opx_ep->use_expected_tid_rzv = OPX_TID_ENABLE_OFF;
	}
#endif

	FI_INFO(fi_opx_global.prov, FI_LOG_EP_DATA, "Expected receive (TID) is %s.\n",
		opx_ep->use_expected_tid_rzv ? "enabled" : "disabled");

#if defined(OPX_HMEM) && !defined(OPX_DEV_OVERRIDE)
	if (!opx_hfi_drv_version_check("10.14")) {
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
			"Error: FI_HMEM is enabled, but the installed HFI driver is not HMEM enabled!\n");
		errno = FI_EOPNOTSUPP;
		goto err;
	}
#endif

#if defined(OPX_HMEM) && HAVE_CUDA
	int use_gdrcopy;
	int gdrcopy_enabled = cuda_is_gdrcopy_enabled();

	if (fi_param_get_bool(NULL, "hmem_cuda_use_gdrcopy", &use_gdrcopy) != FI_SUCCESS) {
		FI_INFO(&fi_opx_provider, FI_LOG_FABRIC,
			"FI_HMEM_CUDA_USE_GDRCOPY either not specified or invalid. Using default value of 1\n");
		use_gdrcopy = 1; /* Set to the libfabric default of FI_HMEM_CUDA_USE_GDRCOPY=1 */
	}

	if (gdrcopy_enabled == 1) {
		if (use_gdrcopy == 1) {
			FI_INFO(&fi_opx_provider, FI_LOG_FABRIC,
				"GDRCopy has been requested and is available. If you wish to explicity disable GDRCopy, set FI_HMEM_CUDA_USE_GDRCOPY=0\n");
		}
	} else if (use_gdrcopy == 1) {
		FI_WARN(&fi_opx_provider, FI_LOG_FABRIC,
			"GDRCopy has been requested but is not available on this system, set FI_HMEM_CUDA_USE_GDRCOPY=0 and try again.\n");
		fprintf(stderr,
			"%s:%s():%d GDRCopy cannot be used, set FI_HMEM_CUDA_USE_GDRCOPY=0 and try again. Returning FI_EOPNOTSUPP. \n",
			__FILE__, __func__, __LINE__);
		errno = FI_EOPNOTSUPP;
		goto err;
	} else {
		/* gdrcopy_enabled = 0 and use_gdrcopy = 0 */
		FI_INFO(&fi_opx_provider, FI_LOG_FABRIC,
			"If GDRCopy is installed on this system, change FI_HMEM_CUDA_USE_GDRCOPY=0 to FI_HMEM_CUDA_USE_GDRCOPY=1 to enable GDRCopy. \n");
	}
#endif

	*ep = &opx_ep->ep_fid;

	FI_OPX_DEBUG_COUNTERS_INIT(opx_ep->debug_counters);
	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "(end)\n");
	return 0;
err:
	if (opx_domain) {
		ret = fi_opx_ref_dec(&opx_domain->ref_cnt, "domain");
		if (ret) {
			FI_DBG(fi_opx_global.prov, FI_LOG_EP_DATA, "%s:%d: Error: %d\n", __FILE__, __LINE__, ret);
		}
	}
	if (opx_ep) {
#ifdef FLIGHT_RECORDER_ENABLE
		if (opx_ep->fr) {
			free(opx_ep->fr);
			opx_ep->fr = NULL;
		}
#endif
		free(opx_ep->mem);
		opx_ep = NULL;
	}

	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "(end - error)\n");
	return -errno;
}

int fi_opx_endpoint(struct fid_domain *dom, struct fi_info *info, struct fid_ep **ep, void *context)
{
	return fi_opx_endpoint_rx_tx(dom, info, ep, context);
}

int fi_opx_ep_tx_check(struct fi_opx_ep_tx *tx, enum fi_av_type av_type)
{
#ifdef DEBUG
	if (!tx) {
		return -FI_EINVAL;
	}
	if (tx->state != FI_OPX_TX_ENABLED) {
		return -FI_EINVAL;
	}

	if (av_type == FI_AV_UNSPEC) {
		return -FI_EINVAL;
	}
	if (av_type == FI_AV_MAP && tx->av_type != FI_MAP) {
		return -FI_EINVAL;
	}
	if (av_type == FI_AV_TABLE && tx->av_type != FI_TABLE) {
		return -FI_EINVAL;
	}

	/* currently, only FI_AV_TABLE is supported */
	if (av_type == FI_AV_MAP) {
		return -FI_ENOSYS;
	}
	if (av_type != FI_AV_MAP) {
		return -FI_EINVAL;
	}
#endif
	return 0;
}

/* rx_op_flags is only checked for FI_PEEK | FI_CLAIM | FI_MULTI_RECV;
 * rx_op_flags is only used if FI_PEEK | FI_CLAIM;
 *
 * See `fi_opx_ep_rx_process_context()`
 */
__attribute__((noinline)) void
fi_opx_ep_rx_process_context_noinline(struct fi_opx_ep *opx_ep, const uint64_t static_flags,
				      struct opx_context *context, const uint64_t rx_op_flags, const uint64_t is_hmem,
				      const int lock_required, const enum fi_av_type av_type,
				      const enum ofi_reliability_kind reliability, const enum opx_hfi1_type hfi1_type)
{
	struct fid_ep *ep = &opx_ep->ep_fid;

	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "(begin)\n");

	const uint64_t kind = (static_flags & FI_TAGGED) ? FI_OPX_KIND_TAG : FI_OPX_KIND_MSG;

	if (rx_op_flags & FI_PEEK) {
		context->src_addr = fi_opx_ep_get_src_addr(opx_ep, av_type, context->src_addr);

		/*
		 * search the unexpected packet queue
		 */

		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "rx_op_flags & FI_PEEK searching unexpected queue\n");

		__attribute__((__unused__)) bool from_hash_queue = false;
		struct fi_opx_hfi1_ue_packet *uepkt = fi_opx_ep_find_matching_packet(opx_ep, context, kind, hfi1_type);

#ifndef FI_OPX_MATCH_HASH_DISABLE
		if (!uepkt && kind == FI_OPX_KIND_TAG) {
			from_hash_queue = true;
			uepkt		= fi_opx_match_find_uepkt(opx_ep->rx->match_ue_tag_hash, context,
								  FI_OPX_DEBUG_COUNTERS_GET_PTR(opx_ep));
		}
#endif

		/* Found a match */
		if (uepkt) {
			context->len	      = fi_opx_hfi1_packet_hdr_message_length(&uepkt->hdr);
			context->tag	      = uepkt->hdr.match.ofi_tag;
			context->data	      = uepkt->hdr.match.ofi_data;
			context->byte_counter = 0;

			if (rx_op_flags & FI_CLAIM) { /* both FI_PEEK and FI_CLAIM were specified */

				/* remove this item from the list, but don't free it.
				   It will be freed on a subsequent FI_CLAIM that's
				   not combined with FI_PEEK. */
				context->claim = uepkt;
#ifndef FI_OPX_MATCH_HASH_DISABLE
				if (!from_hash_queue) {
					fi_opx_hfi1_ue_packet_slist_pop_item(uepkt, &opx_ep->rx->queue[kind].ue);
				} else {
					fi_opx_match_ue_hash_pop(uepkt, opx_ep->rx->match_ue_tag_hash);
				}
#else
				fi_opx_hfi1_ue_packet_slist_pop_item(uepkt, &opx_ep->rx->queue[kind].ue);
#endif
			}

			fi_opx_enqueue_completed(opx_ep->rx->cq_completed_ptr, context, lock_required);

			return;
		}

		/*
		 * did not find a match for this "peek"; notify the application
		 * via completion queue error entry
		 */
		context->err_entry.flags	 = rx_op_flags;
		context->err_entry.len		 = 0;
		context->err_entry.buf		 = 0;
		context->err_entry.data		 = 0;
		context->err_entry.tag		 = 0;
		context->err_entry.olen		 = 0;
		context->err_entry.err		 = FI_ENOMSG;
		context->err_entry.prov_errno	 = 0;
		context->err_entry.err_data	 = NULL;
		context->err_entry.err_data_size = 0;
		context->byte_counter		 = 0;
		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "no match found on unexpected queue posting error\n");

		fi_opx_cq_enqueue_err(opx_ep->rx->cq, context, lock_required);

	} else if (rx_op_flags & FI_CLAIM) {
		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "rx_op_flags & FI_CLAIM complete receive operation\n");

		/* only FI_CLAIM was specified
		 *
		 * this occurs after a previous FI_PEEK + FI_CLAIM
		 * operation has removed an unexpected packet from
		 * the queue and saved a pointer to it in the context
		 *
		 * complete the receive for this "claimed" message ... */

		struct fi_opx_hfi1_ue_packet *claimed_pkt = context->claim;

		const unsigned is_intranode = claimed_pkt->is_intranode;

		opx_ep_complete_receive_operation(
			ep, &claimed_pkt->hdr, (union fi_opx_hfi1_packet_payload *) &claimed_pkt->payload,
			claimed_pkt->hdr.match.ofi_tag, context, claimed_pkt->hdr.bth.opcode, OPX_MULTI_RECV_FALSE,
			is_intranode, rx_op_flags & FI_OPX_CQ_CONTEXT_HMEM, lock_required, reliability, hfi1_type);

		/* ... and prepend the claimed uepkt to the ue free list.
		   claimed_pkt->next should have been set to NULL at the time we
		   stored it in context->claim */
		assert(claimed_pkt->next == NULL);

		OPX_BUF_FREE(claimed_pkt);

	} else if ((static_flags & FI_MSG) && (rx_op_flags & FI_MULTI_RECV)) {
		/* TODO: HMEM not supported for multi-receive */
		assert(!(rx_op_flags & FI_OPX_CQ_CONTEXT_HMEM));

		context->src_addr = fi_opx_ep_get_src_addr(opx_ep, av_type, context->src_addr);

		/*
		 * search the unexpected packet queue
		 */

		struct fi_opx_hfi1_ue_packet *uepkt = opx_ep->rx->queue[kind].ue.head;
		FI_OPX_DEBUG_COUNTERS_INC(opx_ep->debug_counters.match.default_searches);
		FI_OPX_DEBUG_COUNTERS_DECLARE_TMP(found_packet);

		const uint64_t		any_addr = (context->src_addr == FI_ADDR_UNSPEC);
		const union fi_opx_addr src_addr = {.fi = context->src_addr};

		while (uepkt != NULL) {
			const unsigned is_intranode = uepkt->is_intranode;

			if (fi_opx_ep_is_matching_packet(uepkt->tag, uepkt->lid, uepkt->rx, FI_OPX_MATCH_IGNORE_ALL,
							 FI_OPX_MATCH_TAG_ZERO, any_addr, src_addr, opx_ep,
							 uepkt->daos_info.rank, uepkt->daos_info.rank_inst,
							 is_intranode)) {
				FI_OPX_DEBUG_COUNTERS_INC(found_packet);
				FI_OPX_DEBUG_COUNTERS_INC(opx_ep->debug_counters.match.default_hits);

				/* verify that there is enough space available in
				 * the multi-receive buffer for the incoming data */

				const size_t recv_len = context->len;
				const size_t send_len = fi_opx_hfi1_packet_hdr_message_length(&uepkt->hdr);

				if (send_len > recv_len) {
					/* not enough space available in the multi-receive
					 * buffer; continue as if "a match was not found"
					 * and advance to the next ue header */
					uepkt = uepkt->next;

				} else {
					/* the 'context->len' field will be updated to the
					 * new multi-receive buffer free space as part of
					 * the receive completion */
					opx_ep_complete_receive_operation(
						ep, &uepkt->hdr, (union fi_opx_hfi1_packet_payload *) &uepkt->payload,
						uepkt->hdr.match.ofi_tag, context, uepkt->hdr.bth.opcode,
						OPX_MULTI_RECV_TRUE, OPX_HMEM_FALSE, is_intranode, lock_required,
						reliability, hfi1_type);

					/* remove this item from the ue list and prepend
					 * the (now) completed uepkt to the ue free list. */
					uepkt = fi_opx_hfi1_ue_packet_slist_remove_item(uepkt,
											&opx_ep->rx->queue[kind].ue);

					if (context->len < opx_ep->rx->min_multi_recv) {
						/* after processing this message there is not
						 * enough space available in the multi-receive
						 * buffer to receive the *next* message; break
						 * from the loop and post a 'FI_MULTI_RECV'
						 * event to the completion queue. */

						if (lock_required) {
							fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
							abort();
						}
						// reusing byte_counter as a pending flag
						// to ensure that any pending ops are completed (eg rendezvous
						// multi-receive)
						if (context->byte_counter == 0) {
							assert(context->next == NULL);
							slist_insert_tail((struct slist_entry *) context,
									  opx_ep->rx->cq_completed_ptr);
						}

						return;
					}
				}
			} else {
				FI_OPX_DEBUG_COUNTERS_INC(opx_ep->debug_counters.match.default_misses);
				uepkt = uepkt->next;
			}
		}

		FI_OPX_DEBUG_COUNTERS_INC_COND(!found_packet, opx_ep->debug_counters.match.default_not_found);

		/*
		 * no unexpected headers were matched; add this match
		 * information to the appropriate match queue
		 */
		slist_insert_tail((struct slist_entry *) context, &opx_ep->rx->queue[kind].mq);
	}

	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "(end)\n");
}

void fi_opx_ep_rx_process_header_tag(struct fid_ep *ep, const union opx_hfi1_packet_hdr *const hdr,
				     const uint8_t *const payload, const size_t payload_bytes, const uint8_t opcode,
				     const unsigned is_intranode, const int lock_required,
				     const enum ofi_reliability_kind reliability, const enum opx_hfi1_type hfi1_type,
				     opx_lid_t slid)
{
	fi_opx_ep_rx_process_header(ep, hdr, (const union fi_opx_hfi1_packet_payload *const) payload, payload_bytes,
				    FI_TAGGED, opcode, is_intranode, lock_required, reliability, hfi1_type, slid);
}

void fi_opx_ep_rx_process_header_msg(struct fid_ep *ep, const union opx_hfi1_packet_hdr *const hdr,
				     const uint8_t *const payload, const size_t payload_bytes, const uint8_t opcode,
				     const unsigned is_intranode, const int lock_required,
				     const enum ofi_reliability_kind reliability, const enum opx_hfi1_type hfi1_type,
				     opx_lid_t slid)
{
	fi_opx_ep_rx_process_header(ep, hdr, (const union fi_opx_hfi1_packet_payload *const) payload, payload_bytes,
				    FI_MSG, opcode, is_intranode, lock_required, reliability, hfi1_type, slid);
}

void fi_opx_ep_rx_reliability_process_packet(struct fid_ep *ep, const union opx_hfi1_packet_hdr *const hdr,
					     const uint8_t *const payload)
{
	OPX_LOG_PKT(FI_LOG_DEBUG, FI_LOG_EP_DATA, "================ received a packet from the reliability service\n");

	const uint8_t opcode = hdr->bth.opcode;

	/* reported in LRH as the number of 4-byte words in the packet; header + payload + icrc */
	uint16_t  lrh_pktlen_le;
	size_t	  total_bytes;
	size_t	  payload_bytes;
	opx_lid_t slid;

	/* Non-inlined functions should just use the runtime HFI1 type check, no optimizations */
	if (OPX_HFI1_TYPE & (OPX_HFI1_WFR | OPX_HFI1_JKR_9B)) {
		lrh_pktlen_le = ntohs(hdr->lrh_9B.pktlen);
		total_bytes   = (lrh_pktlen_le - 1) * 4; /* do not copy the trailing icrc */
		payload_bytes = total_bytes - sizeof(struct fi_opx_hfi1_stl_packet_hdr_9B);
		slid	      = (opx_lid_t) __be16_to_cpu24((__be16) hdr->lrh_9B.slid);
	} else {
		lrh_pktlen_le = hdr->lrh_16B.pktlen;
		total_bytes   = (lrh_pktlen_le - 1) * 8; /* do not copy the trailing icrc */
		payload_bytes = total_bytes - sizeof(struct fi_opx_hfi1_stl_packet_hdr_16B);
		slid	      = (opx_lid_t) __le24_to_cpu(((hdr->lrh_16B.slid20 << 20) | (hdr->lrh_16B.slid)));
	}

	if (OFI_LIKELY(opcode & FI_OPX_HFI_BTH_OPCODE_TAG_BIT)) {
		fi_opx_ep_rx_process_header(ep, hdr, (const union fi_opx_hfi1_packet_payload *const) payload,
					    payload_bytes, FI_TAGGED, opcode, OPX_INTRANODE_FALSE,
					    FI_OPX_LOCK_NOT_REQUIRED, OFI_RELIABILITY_KIND_ONLOAD, OPX_HFI1_TYPE, slid);
	} else {
		fi_opx_ep_rx_process_header(ep, hdr, (const union fi_opx_hfi1_packet_payload *const) payload,
					    payload_bytes, FI_MSG, opcode, OPX_INTRANODE_FALSE,
					    FI_OPX_LOCK_NOT_REQUIRED, OFI_RELIABILITY_KIND_ONLOAD, OPX_HFI1_TYPE, slid);
	}
}

__OPX_FORCE_INLINE__
struct fi_opx_hfi1_ue_packet *
fi_opx_ep_rx_append_ue(struct fi_opx_ep_rx *const rx, struct fi_opx_hfi1_ue_packet_slist *ue,
		       const union opx_hfi1_packet_hdr *const	     hdr,
		       const union fi_opx_hfi1_packet_payload *const payload, const size_t payload_bytes,
		       const unsigned is_intranode, const uint32_t rank, const uint32_t rank_inst, const opx_lid_t slid)
{
	struct fi_opx_hfi1_ue_packet *uepkt = ofi_buf_alloc(rx->ue_packet_pool);

	memcpy((void *) &(uepkt->hdr), (const void *) hdr, OPX_HEADER_SIZE);

	if (payload != NULL) {
		memcpy((void *) &uepkt->payload.byte[0], payload, payload_bytes);
	}

	uepkt->tag = hdr->match.ofi_tag;
	uepkt->lid = slid;
	uepkt->rx  = hdr->reliability.origin_rx;

#ifdef OPX_DAOS
	/* DAOS Persistent Address Support:
	 * Support: save rank information associated with this inbound packet.
	 * */
	uepkt->daos_info.rank	   = rank;
	uepkt->daos_info.rank_inst = rank_inst;
#else
	uepkt->daos_info.rank	   = 0xFFFFFFFF;
	uepkt->daos_info.rank_inst = 0xFFFFFFFF;
#endif
	uepkt->is_intranode = is_intranode;

	uepkt->next = NULL;
	uepkt->prev = NULL;

	fi_opx_hfi1_ue_packet_slist_insert_tail(uepkt, ue);

	return uepkt;
}

void fi_opx_ep_rx_append_ue_msg(struct fi_opx_ep_rx *const rx, const union opx_hfi1_packet_hdr *const hdr,
				const union fi_opx_hfi1_packet_payload *const payload, const size_t payload_bytes,
				const unsigned is_intranode, const uint32_t rank, const uint32_t rank_inst,
				const bool daos_enabled, struct fi_opx_debug_counters *debug_counters,
				const opx_lid_t slid)
{
	fi_opx_ep_rx_append_ue(rx, &rx->queue[FI_OPX_KIND_MSG].ue, hdr, payload, payload_bytes, is_intranode, rank,
			       rank_inst, slid);
	FI_OPX_DEBUG_COUNTERS_MAX_OF(debug_counters->match.default_max_length, rx->queue[FI_OPX_KIND_MSG].ue.length);
}

void fi_opx_ep_rx_append_ue_tag(struct fi_opx_ep_rx *const rx, const union opx_hfi1_packet_hdr *const hdr,
				const union fi_opx_hfi1_packet_payload *const payload, const size_t payload_bytes,
				const unsigned is_intranode, const uint32_t rank, const uint32_t rank_inst,
				const bool daos_enabled, struct fi_opx_debug_counters *debug_counters,
				const opx_lid_t slid)
{
#ifndef FI_OPX_MATCH_HASH_DISABLE
	if (!daos_enabled && (rx->match_ue_tag_hash->ue.head ||
			      rx->queue[FI_OPX_KIND_TAG].ue.length >= FI_OPX_MATCH_DEFAULT_UE_LIST_MAX_LENGTH)) {
		struct fi_opx_hfi1_ue_packet *uepkt = fi_opx_ep_rx_append_ue(
			rx, &rx->match_ue_tag_hash->ue, hdr, payload, payload_bytes, is_intranode, 0, 0, slid);
		fi_opx_match_ue_hash_append(uepkt, rx->match_ue_tag_hash, debug_counters);
	} else {
		fi_opx_ep_rx_append_ue(rx, &rx->queue[FI_OPX_KIND_TAG].ue, hdr, payload, payload_bytes, is_intranode,
				       rank, rank_inst, slid);
	}
#else
	fi_opx_ep_rx_append_ue(rx, &rx->queue[FI_OPX_KIND_TAG].ue, hdr, payload, payload_bytes, rank, rank_inst, slid);
#endif
	FI_OPX_DEBUG_COUNTERS_MAX_OF(debug_counters->match.default_max_length, rx->queue[FI_OPX_KIND_TAG].ue.length);
}

void fi_opx_ep_rx_append_ue_egr(struct fi_opx_ep_rx *const rx, const union opx_hfi1_packet_hdr *const hdr,
				const union fi_opx_hfi1_packet_payload *const payload, const size_t payload_bytes,
				const opx_lid_t slid)
{
	/* DAOS Persistent Address Support:
	 * No need to retain rank related data for packets appended to the
	 * MP Eager unexpected queue, because the mp_egr_id related data in
	 * the packet is referenced instead.
	 */
	fi_opx_ep_rx_append_ue(rx, &rx->mp_egr_queue.ue, hdr, payload, payload_bytes, OPX_INTRANODE_FALSE, 0, 0, slid);
}

static void fi_opx_update_daos_av_rank(struct fi_opx_ep *opx_ep, fi_addr_t addr)
{
	struct fi_opx_daos_av_rank_key key;
	struct fi_opx_daos_av_rank    *av_rank = NULL;

	key.rank      = opx_ep->daos_info.rank;
	key.rank_inst = opx_ep->daos_info.rank_inst;

	/* Check the AV hashmap for the rank. */
	HASH_FIND(hh, opx_ep->daos_info.av_rank_hashmap, &key, sizeof(key), av_rank);

	if (av_rank) {
		/* DAOS Persistent Address Support:
		 * Rank found in the AV hashmap.  Update fi_addr of the rank with new value.
		 */
		av_rank->updated++;
		av_rank->fi_addr = addr;

		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
			     "av_rank_hashmap rank %d rank_inst %d updated fi_addr 0x%08lx again: %d.\n", key.rank,
			     key.rank_inst, av_rank->fi_addr, av_rank->updated);
	} else {
		/* DAOS Persistent Address Support:
		 * Rank not found in the AV hashmap.  Need to search AV hashmap to update
		 * a stale rank entry using this fi_addr.  DAOS might have changed the
		 * rank associated with this fi_addr.
		 */
		int found = 0;

		if (opx_ep->daos_info.av_rank_hashmap) {
			struct fi_opx_daos_av_rank     *cur_av_rank = NULL;
			struct fi_opx_daos_av_rank     *tmp_av_rank = NULL;
			__attribute__((__unused__)) int i	    = 0;

			FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
				     "Update av_rank_hashmap - (rank:%d, fi_addr:%08lx)\n", opx_ep->daos_info.rank,
				     addr);

			HASH_ITER(hh, opx_ep->daos_info.av_rank_hashmap, cur_av_rank, tmp_av_rank)
			{
				if (cur_av_rank) {
					union fi_opx_addr cur_av_addr;
					cur_av_addr.fi = cur_av_rank->fi_addr;

					if (cur_av_addr.fi == addr) {
						found = 1;
						cur_av_rank->updated++;
						cur_av_rank->key.rank = opx_ep->daos_info.rank;
						FI_DBG_TRACE(
							fi_opx_global.prov, FI_LOG_EP_DATA,
							"Update av_rank_hashmap[%d] = rank:%d fi_addr:0x%08lx - updated again %d.\n",
							i, cur_av_rank->key.rank, cur_av_addr.fi, cur_av_rank->updated);
						break;
					} else {
						FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
							     "Update av_rank_hashmap[%d] = rank:%d fi_addr:0x%08lx\n",
							     i++, cur_av_rank->key.rank, cur_av_addr.fi);
					}
				}
			}
		}

		if (!found) {
			int rc __attribute__((unused));
			rc = posix_memalign((void **) &av_rank, 32, sizeof(*av_rank));
			assert(rc == 0);

			av_rank->key	 = key;
			av_rank->updated = 0;
			av_rank->fi_addr = addr;
			HASH_ADD(hh, opx_ep->daos_info.av_rank_hashmap, key, sizeof(av_rank->key), av_rank);

			FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
				     "av_rank_hashmap rank %d rank_inst %d fi_addr 0x%08lx entry created.\n", key.rank,
				     key.rank_inst, av_rank->fi_addr);
		}
	}

#ifdef OPX_DAOS_DEBUG
	union fi_opx_addr find_addr = {.fi = addr};
	(void) fi_opx_dump_daos_av_addr_rank(opx_ep, find_addr, "UPDATE");
#endif
}

ssize_t fi_opx_ep_tx_connect(struct fi_opx_ep *opx_ep, size_t count, union fi_opx_addr *peers,
			     struct fi_opx_extended_addr *peers_ext)
{
	int	n;
	ssize_t rc	     = FI_SUCCESS;
	opx_ep->rx->av_addr  = opx_ep->av->table_addr;
	opx_ep->tx->av_addr  = opx_ep->av->table_addr;
	opx_ep->rx->av_count = opx_ep->av->addr_count;
	opx_ep->tx->av_count = opx_ep->av->addr_count;
	for (n = 0; n < count; ++n) {
		FI_INFO(fi_opx_global.prov, FI_LOG_AV, "opx_ep %p, opx_ep->tx %p, peer %#lX\n", opx_ep, opx_ep->tx,
			peers[n].fi);
		/*
		 * DAOS Persistent Address Support:
		 * No Context Resource Management Framework is supported by OPX to enable
		 * acquiring a context with attributes that exactly match the specified
		 * source address.
		 *
		 * Therefore, the source address is treated as an ‘opaque’ ID, so preserve
		 * the rank data associated with the source address, which maps to the
		 * appropriate HFI and HFI port.
		 */
		if (peers_ext) {
			/* Set rank information to be used by ep */
			opx_ep->daos_info.rank	    = peers_ext[n].rank;
			opx_ep->daos_info.rank_inst = peers_ext[n].rank_inst;
			/* DAOS often starts and stops EPs using the same source address, so
			 * save rank information associated with this AV.
			 */
			fi_opx_update_daos_av_rank(opx_ep, peers[n].fi);

			FI_INFO(fi_opx_global.prov, FI_LOG_AV, "    DAOS: rank %d, rank_inst %d\n",
				opx_ep->daos_info.rank, opx_ep->daos_info.rank_inst);
		}

		rc = FI_OPX_FABRIC_TX_CONNECT(opx_ep, peers[n].fi);
		if (OFI_UNLIKELY(rc)) {
			break;
		}
	}

	return rc;
}

FI_OPX_MSG_SPECIALIZED_FUNC(OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY, OPX_HFI1_WFR)
FI_OPX_MSG_SPECIALIZED_FUNC(OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY, OPX_HFI1_JKR_9B)
FI_OPX_MSG_SPECIALIZED_FUNC(OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY, OPX_HFI1_JKR)

ssize_t fi_opx_send_FABRIC_DIRECT(struct fid_ep *ep, const void *buf, size_t len, void *desc, fi_addr_t dest_addr,
				  void *context)
{
	/* Non-inlined functions should just use the runtime HFI1 type check, no optimizations */
	if (OPX_HFI1_TYPE & OPX_HFI1_WFR) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(send, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_WFR)(ep, buf, len, desc, dest_addr, context);
	} else if (OPX_HFI1_TYPE & OPX_HFI1_JKR_9B) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(send, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_JKR_9B)(ep, buf, len, desc, dest_addr, context);
	} else if (OPX_HFI1_TYPE & OPX_HFI1_JKR) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(send, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_JKR)(ep, buf, len, desc, dest_addr, context);
	} else {
		/* should never get here */
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Fatal -FI_EPERM\n");
		abort();
	}
	return (ssize_t) -FI_EPERM;
}

ssize_t fi_opx_recv_FABRIC_DIRECT(struct fid_ep *ep, void *buf, size_t len, void *desc, fi_addr_t src_addr,
				  void *context)
{
	/* Non-inlined functions should just use the runtime HFI1 type check, no optimizations */
	if (OPX_HFI1_TYPE & OPX_HFI1_WFR) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(recv, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_WFR)(ep, buf, len, desc, src_addr, context);
	} else if (OPX_HFI1_TYPE & OPX_HFI1_JKR_9B) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(recv, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_JKR_9B)(ep, buf, len, desc, src_addr, context);
	} else if (OPX_HFI1_TYPE & OPX_HFI1_JKR) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(recv, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_JKR)(ep, buf, len, desc, src_addr, context);
	} else {
		/* should never get here */
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Fatal -FI_EPERM\n");
		abort();
	}
	return (ssize_t) -FI_EPERM;
}

ssize_t fi_opx_inject_FABRIC_DIRECT(struct fid_ep *ep, const void *buf, size_t len, fi_addr_t dest_addr)
{
	/* Non-inlined functions should just use the runtime HFI1 type check, no optimizations */
	if (OPX_HFI1_TYPE & OPX_HFI1_WFR) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(inject, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_WFR)(ep, buf, len, dest_addr);
	} else if (OPX_HFI1_TYPE & OPX_HFI1_JKR_9B) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(inject, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_JKR_9B)(ep, buf, len, dest_addr);
	} else if (OPX_HFI1_TYPE & OPX_HFI1_JKR) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(inject, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_JKR)(ep, buf, len, dest_addr);
	} else {
		/* should never get here */
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Fatal -FI_EPERM\n");
		abort();
	}
	return (ssize_t) -FI_EPERM;
}

ssize_t fi_opx_recvmsg_FABRIC_DIRECT(struct fid_ep *ep, const struct fi_msg *msg, uint64_t flags)
{
	/* Non-inlined functions should just use the runtime HFI1 type check, no optimizations */
	if (OPX_HFI1_TYPE & OPX_HFI1_WFR) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(recvmsg, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_WFR)(ep, msg, flags);
	} else if (OPX_HFI1_TYPE & OPX_HFI1_JKR_9B) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(recvmsg, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_JKR_9B)(ep, msg, flags);
	} else if (OPX_HFI1_TYPE & OPX_HFI1_JKR) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(recvmsg, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_JKR)(ep, msg, flags);
	} else {
		/* should never get here */
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Fatal -FI_EPERM\n");
		abort();
	}
	return (ssize_t) -FI_EPERM;
}

ssize_t fi_opx_senddata_FABRIC_DIRECT(struct fid_ep *ep, const void *buf, size_t len, void *desc, uint64_t data,
				      fi_addr_t dest_addr, void *context)
{
	/* Non-inlined functions should just use the runtime HFI1 type check, no optimizations */
	if (OPX_HFI1_TYPE & OPX_HFI1_WFR) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(senddata, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_WFR)(ep, buf, len, desc, data, dest_addr, context);
	} else if (OPX_HFI1_TYPE & OPX_HFI1_JKR_9B) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(senddata, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_JKR_9B)(ep, buf, len, desc, data, dest_addr, context);
	} else if (OPX_HFI1_TYPE & OPX_HFI1_JKR) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(senddata, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_JKR)(ep, buf, len, desc, data, dest_addr, context);
	} else {
		/* should never get here */
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Fatal -FI_EPERM\n");
		abort();
	}
	return (ssize_t) -FI_EPERM;
}

ssize_t fi_opx_injectdata_FABRIC_DIRECT(struct fid_ep *ep, const void *buf, size_t len, uint64_t data,
					fi_addr_t dest_addr)
{
	/* Non-inlined functions should just use the runtime HFI1 type check, no optimizations */
	if (OPX_HFI1_TYPE & OPX_HFI1_WFR) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(injectdata, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_WFR)(ep, buf, len, data, dest_addr);
	} else if (OPX_HFI1_TYPE & OPX_HFI1_JKR_9B) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(injectdata, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_JKR_9B)(ep, buf, len, data, dest_addr);
	} else if (OPX_HFI1_TYPE & OPX_HFI1_JKR) {
		return FI_OPX_MSG_SPECIALIZED_FUNC_NAME(injectdata, OPX_LOCK, OPX_AV, OPX_EP_CAPS, OPX_RELIABILITY,
							OPX_HFI1_JKR)(ep, buf, len, data, dest_addr);
	} else {
		/* should never get here */
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "Fatal -FI_EPERM\n");
		abort();
	}
	return (ssize_t) -FI_EPERM;
}
