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
 * pblk-map.c - pblk's lba-ppa mapping strategy
 *
 */

#include "pblk.h"

// 2233MOD
DEFINE_HASHTABLE(lba_lun_map, HASH_SIZE_BITS);

static int pblk_map_page_data(struct pblk *pblk, unsigned int sentry,
        struct ppa_addr *ppa_list,
        unsigned long *lun_bitmap,
        void *meta_list,
        unsigned int valid_secs)
{
    struct pblk_line *line = pblk_line_get_data(pblk);
    struct pblk_emeta *emeta;
    struct pblk_w_ctx *w_ctx;
    __le64 *lba_list;
    u64 paddr, paddr_first;
    int nr_secs = pblk->min_write_pgs;
    int i,j,k;
    bool colocation_found;

    if (!line)
        return -ENOSPC;

    if (pblk_line_is_full(line)) {
        //printk("we shouldn't be here 3...\n");
        struct pblk_line *prev_line = line;

        /* If we cannot allocate a new line, make sure to store metadata
         * on current line and then fail
         */
        line = pblk_line_replace_data(pblk);
        pblk_line_close_meta(pblk, prev_line);

        if (!line) {
            pblk_pipeline_stop(pblk);
            return -ENOSPC;
        }

    }

    emeta = line->emeta;
    lba_list = emeta_to_lbas(pblk, emeta->buf);

    paddr = pblk_alloc_page(pblk, line, nr_secs);
    paddr_first = paddr;
    colocation_found = false;
    //u64 paddr_list[nr_secs];
    
    // Loop through the vector to find colocations
    for (i = 0; i < nr_secs; i++, paddr++) {
        w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
        __le64 lba_cur = cpu_to_le64(w_ctx->lba);
        //paddr_list[i] = paddr;
        ppa_list[i] = addr_to_gen_ppa(pblk, paddr, line->id);

        if(i >= valid_secs) continue;

        // Loop through our custom FIFO
        for( j = 0; j < MRU_SIZE; j++){
            int idx = ( mru_newest + j )% MRU_SIZE;
            if(lba_cur >= copair[idx].lba_copy && lba_cur < copair[idx].lba_copy + copair[idx].num_sectors){
                // add offset to lba_orig
                sector_t lba_orig = copair[idx].lba_orig + (lba_cur - copair[idx].lba_copy);
                int bkt = hash_min(lba_orig,HASH_SIZE_BITS);
                struct lba_lun* ll_orig;

                // we found duplicate, now check if the PPAs have the same LUN, and record co-locations
                hlist_for_each_entry(ll_orig, &lba_lun_map[bkt], node){

                    if(ll_orig->lba == lba_orig){

                        if (ll_orig->ch == ppa_list[i].m.grp && ll_orig->lun == ppa_list[i].m.pu){
                            colocation_found = true;
                            colocation_count++;
                            printk("colocation encountered = %d / %d, i = %d!\n", colocation_count, colocation_checks, i);
                            hash_del(&ll_orig->node);
                            kfree(ll_orig);

                            /* The code below attempts to skip paddr by an amount unaligned to nr_secs, which will break
                             * other components of pblk and cause crashes */
                            /*
                            struct pblk_addrf *uaddrf = &pblk->uaddrf;
                            int rem, roundup;
                            div_u64_rem(line->cur_sec, uaddrf->sec_stripe, &rem);
                            roundup = uaddrf->sec_stripe - rem + 1;
                            printk("sec_stripe = %u, rem = %u, roundup = %u\n", uaddrf->sec_stripe, rem, roundup);
                            pblk_alloc_page(pblk,line, roundup );
                            
                            for( k = 0; k <= i; k++){
                              ppa_list[k] = addr_to_gen_ppa(pblk,paddr_list[k]+roundup, line->id);
                              printk("ppa_list [%d] <- %u\n", k, paddr_list[k] + roundup);
                            }
                            paddr_first = paddr_list[0]+roundup;
                            */

                            /* The code below attempts to skip paddr by nr_secs, it works in some benchmarks
                             * but will not work in others (e.g. IOZone and filebench) for some reason 
                             */
                            /*
                            paddr_first = pblk_alloc_page(pblk, line, nr_secs);
                            struct ppa_addr tmp_ppa;
                            tmp_ppa= addr_to_gen_ppa(pblk, paddr_first + i, line->id);
                            
                            if (ll_orig->ch == tmp_ppa.m.grp && ll_orig->lun == tmp_ppa.m.pu){
                                // this branch should never be taken if we allocated 8 new sectors to get a new LUN
                                colocation_count++;
                                printk("colocation encountered = %d / %d, i = %d!\n", colocation_count, colocation_checks, i);
                            } else {
                                printk("colocation avoided. encounetered = %d / %d, i = %d!\n", colocation_count, colocation_checks, i);
                            }
                            */
                        }
                    }
                } // end hlist_for_each_entry
            }
        } // end for j

        // Add (LBA, LUN) pair into hashmap
        // Todo: garbage collect the hashmap, as it infinitely expands
        struct lba_lun* ll = kmalloc(sizeof(struct lba_lun), GFP_KERNEL); 
        ll->lba = cpu_to_le64(w_ctx->lba);
        ll->ch = ppa_list[i].m.grp; 
        ll->lun = ppa_list[i].m.pu;
        hash_add(lba_lun_map, &ll->node, ll->lba);
    } // end for i

    paddr = paddr_first;

    for (i = 0; i < nr_secs; i++, paddr++) {
        struct pblk_sec_meta *meta = pblk_get_meta(pblk, meta_list, i);
        __le64 addr_empty = cpu_to_le64(ADDR_EMPTY);
        /* ppa to be sent to the device */
        ppa_list[i] = addr_to_gen_ppa(pblk, paddr, line->id);

        /* Write context for target bio completion on write buffer. Note
         * that the write buffer is protected by the sync backpointer,
         * and a single writer thread have access to each specific entry
         * at a time. Thus, it is safe to modify the context for the
         * entry we are setting up for submission without taking any
         * lock or memory barrier.
         */

        if (i < valid_secs) {
            kref_get(&line->ref);
            atomic_inc(&line->sec_to_update);
            w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
            w_ctx->ppa = ppa_list[i];
            meta->lba = cpu_to_le64(w_ctx->lba);
            lba_list[paddr] = cpu_to_le64(w_ctx->lba);

            if (lba_list[paddr] != addr_empty)
                line->nr_valid_lbas++;
            else{
                atomic64_inc(&pblk->pad_wa);
            }
        } else {
            lba_list[paddr] = addr_empty;
            meta->lba = addr_empty;
            __pblk_map_invalidate(pblk, line, paddr);
        }
    }

    pblk_down_rq(pblk, ppa_list[0], lun_bitmap);
    return 0;
}

int pblk_map_rq(struct pblk *pblk, struct nvm_rq *rqd, unsigned int sentry,
        unsigned long *lun_bitmap, unsigned int valid_secs,
        unsigned int off)
{
    void *meta_list = pblk_get_meta_for_writes(pblk, rqd);
    void *meta_buffer;
    struct ppa_addr *ppa_list = nvm_rq_to_ppa_list(rqd);
    unsigned int map_secs;
    int min = pblk->min_write_pgs;
    int i;
    int ret;

    for (i = off; i < rqd->nr_ppas; i += min) {
        map_secs = (i + min > valid_secs) ? (valid_secs % min) : min;
        meta_buffer = pblk_get_meta(pblk, meta_list, i);

        ret = pblk_map_page_data(pblk, sentry + i, &ppa_list[i],
                lun_bitmap, meta_buffer, map_secs);
        if (ret)
            return ret;
    }

    return 0;
}

/* only if erase_ppa is set, acquire erase semaphore */
int pblk_map_erase_rq(struct pblk *pblk, struct nvm_rq *rqd,
        unsigned int sentry, unsigned long *lun_bitmap,
        unsigned int valid_secs, struct ppa_addr *erase_ppa)
{
    struct nvm_tgt_dev *dev = pblk->dev;
    struct nvm_geo *geo = &dev->geo;
    struct pblk_line_meta *lm = &pblk->lm;
    void *meta_list = pblk_get_meta_for_writes(pblk, rqd);
    void *meta_buffer;
    struct ppa_addr *ppa_list = nvm_rq_to_ppa_list(rqd);
    struct pblk_line *e_line, *d_line;
    unsigned int map_secs;
    int min = pblk->min_write_pgs;
    int i, erase_lun;
    int ret;


    for (i = 0; i < rqd->nr_ppas; i += min) {
        map_secs = (i + min > valid_secs) ? (valid_secs % min) : min;
        meta_buffer = pblk_get_meta(pblk, meta_list, i);

        ret = pblk_map_page_data(pblk, sentry + i, &ppa_list[i],
                lun_bitmap, meta_buffer, map_secs);
        if (ret)
            return ret;

        erase_lun = pblk_ppa_to_pos(geo, ppa_list[i]);

        /* line can change after page map. We might also be writing the
         * last line.
         */
        e_line = pblk_line_get_erase(pblk);
        if (!e_line)
            return pblk_map_rq(pblk, rqd, sentry, lun_bitmap,
                    valid_secs, i + min);

        spin_lock(&e_line->lock);
        if (!test_bit(erase_lun, e_line->erase_bitmap)) {
            set_bit(erase_lun, e_line->erase_bitmap);
            atomic_dec(&e_line->left_eblks);

            *erase_ppa = ppa_list[i];
            erase_ppa->a.blk = e_line->id;
            erase_ppa->a.reserved = 0;

            spin_unlock(&e_line->lock);

            /* Avoid evaluating e_line->left_eblks */
            return pblk_map_rq(pblk, rqd, sentry, lun_bitmap,
                    valid_secs, i + min);
        }
        spin_unlock(&e_line->lock);
    }

    d_line = pblk_line_get_data(pblk);

    /* line can change after page map. We might also be writing the
     * last line.
     */
    e_line = pblk_line_get_erase(pblk);
    if (!e_line)
        return -ENOSPC;

    /* Erase blocks that are bad in this line but might not be in next */
    if (unlikely(pblk_ppa_empty(*erase_ppa)) &&
            bitmap_weight(d_line->blk_bitmap, lm->blk_per_line)) {
        int bit = -1;

retry:
        bit = find_next_bit(d_line->blk_bitmap,
                lm->blk_per_line, bit + 1);
        if (bit >= lm->blk_per_line)
            return 0;

        spin_lock(&e_line->lock);
        if (test_bit(bit, e_line->erase_bitmap)) {
            spin_unlock(&e_line->lock);
            goto retry;
        }
        spin_unlock(&e_line->lock);

        set_bit(bit, e_line->erase_bitmap);
        atomic_dec(&e_line->left_eblks);
        *erase_ppa = pblk->luns[bit].bppa; /* set ch and lun */
        erase_ppa->a.blk = e_line->id;
    }

    return 0;
}
