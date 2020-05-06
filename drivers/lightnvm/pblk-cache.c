// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Javier Gonzalez <javier@cnexlabs.com>
 *                  Matias Bjorling <matias@cnexlabs.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * pblk-cache.c - pblk's write cache
 */

#include "pblk.h"

// 2233MOD
// Global FIFOs that contain information about duplicate pairs

// data address in DRAM
void* mru_addr[MRU_SIZE];
// first 4 bytes of data, as a sanity check
unsigned mru_data[MRU_SIZE];
// LBA of the request
sector_t mru_lba[MRU_SIZE];
// pair of duplicates 
struct colocation_pair copair[MRU_SIZE];
int mru_newest = -1;
int colocation_count = 0;
int colocation_checks = 0;
int copair_newest = 0;

// Returns -1 if no possible colocation (no duplicate)
// If colocation was possible(duplicate found), returns lba of original copy
int check_colocation(struct bio *bio, int nr_entries){
    int i;
    void* data = bio_data(bio);

    if (mru_newest == -1) {
        mru_addr[0] = data;
        mru_data[0] = *(unsigned*)data;
        mru_lba[0] = pblk_get_lba(bio);
        mru_newest = 0;
        return -1;
    }
    for(i = 0; i < MRU_SIZE; i++){
        if(data == mru_addr[i] && (*(unsigned*)data) == mru_data[i]) {
            colocation_checks+=nr_entries;
            copair[copair_newest].lba_orig = mru_lba[i];
            copair[copair_newest].lba_copy = pblk_get_lba(bio);
            copair[copair_newest].num_sectors = nr_entries;
            copair_newest = (copair_newest + 1) % MRU_SIZE;
            return mru_lba[i];
        }
    }
    mru_newest = (mru_newest + 1) % MRU_SIZE;
    mru_addr[mru_newest] = data;
    mru_data[mru_newest] = *(unsigned*)data;
    mru_lba[mru_newest] = pblk_get_lba(bio);
    return -1;
}


void pblk_write_to_cache(struct pblk *pblk, struct bio *bio,
				unsigned long flags)
{
	struct request_queue *q = pblk->dev->q;
	struct pblk_w_ctx w_ctx;
	sector_t lba = pblk_get_lba(bio);
	unsigned long start_time = jiffies;
	unsigned int bpos, pos;
	int nr_entries = pblk_get_secs(bio);
	int i, ret;
    int coloc_lba;

	generic_start_io_acct(q, REQ_OP_WRITE, bio_sectors(bio),
			      &pblk->disk->part0);

	/* Update the write buffer head (mem) with the entries that we can
	 * write. The write in itself cannot fail, so there is no need to
	 * rollback from here on.
	 */
retry:
	ret = pblk_rb_may_write_user(&pblk->rwb, bio, nr_entries, &bpos);
	switch (ret) {
	case NVM_IO_REQUEUE:
		io_schedule();
		goto retry;
	case NVM_IO_ERR:
		pblk_pipeline_stop(pblk);
		bio_io_error(bio);
		goto out;
	}

	pblk_ppa_set_empty(&w_ctx.ppa);
	w_ctx.flags = flags;
	if (bio->bi_opf & REQ_PREFLUSH) {
		w_ctx.flags |= PBLK_FLUSH_ENTRY;
		pblk_write_kick(pblk);
	}

	if (unlikely(!bio_has_data(bio)))
		goto out;

    // 2233MOD
    // Check for duplicates and put the LBA the current copy into w_ctx.coloc_lba
    coloc_lba = check_colocation(bio, nr_entries);
	for (i = 0; i < nr_entries; i++) {
		void *data = bio_data(bio);
		w_ctx.lba = lba + i;
        if(coloc_lba != -1)
            w_ctx.coloc_lba = coloc_lba + i;
        else
            w_ctx.coloc_lba = -1;

		pos = pblk_rb_wrap_pos(&pblk->rwb, bpos + i);
		pblk_rb_write_entry_user(&pblk->rwb, data, w_ctx, pos);

		bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);
	}

	atomic64_add(nr_entries, &pblk->user_wa);

#ifdef CONFIG_NVM_PBLK_DEBUG
	atomic_long_add(nr_entries, &pblk->inflight_writes);
	atomic_long_add(nr_entries, &pblk->req_writes);
#endif

	pblk_rl_inserted(&pblk->rl, nr_entries);

out:
	generic_end_io_acct(q, REQ_OP_WRITE, &pblk->disk->part0, start_time);
	pblk_write_should_kick(pblk);

	if (ret == NVM_IO_DONE)
		bio_endio(bio);
}

/*
 * On GC the incoming lbas are not necessarily sequential. Also, some of the
 * lbas might not be valid entries, which are marked as empty by the GC thread
 */
int pblk_write_gc_to_cache(struct pblk *pblk, struct pblk_gc_rq *gc_rq)
{
	struct pblk_w_ctx w_ctx;
	unsigned int bpos, pos;
	void *data = gc_rq->data;
	int i, valid_entries;

	/* Update the write buffer head (mem) with the entries that we can
	 * write. The write in itself cannot fail, so there is no need to
	 * rollback from here on.
	 */
retry:
	if (!pblk_rb_may_write_gc(&pblk->rwb, gc_rq->secs_to_gc, &bpos)) {
		io_schedule();
		goto retry;
	}

	w_ctx.flags = PBLK_IOTYPE_GC;
	pblk_ppa_set_empty(&w_ctx.ppa);

	for (i = 0, valid_entries = 0; i < gc_rq->nr_secs; i++) {
		if (gc_rq->lba_list[i] == ADDR_EMPTY)
			continue;

		w_ctx.lba = gc_rq->lba_list[i];

		pos = pblk_rb_wrap_pos(&pblk->rwb, bpos + valid_entries);
		pblk_rb_write_entry_gc(&pblk->rwb, data, w_ctx, gc_rq->line,
						gc_rq->paddr_list[i], pos);

		data += PBLK_EXPOSED_PAGE_SIZE;
		valid_entries++;
	}

	WARN_ONCE(gc_rq->secs_to_gc != valid_entries,
					"pblk: inconsistent GC write\n");

	atomic64_add(valid_entries, &pblk->gc_wa);

#ifdef CONFIG_NVM_PBLK_DEBUG
	atomic_long_add(valid_entries, &pblk->inflight_writes);
	atomic_long_add(valid_entries, &pblk->recov_gc_writes);
#endif

	pblk_write_should_kick(pblk);
	return NVM_IO_OK;
}
