/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stddef.h>

#include <rte_jhash.h>
#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */

#include "ip_frag_common.h"

#define	PRIME_VALUE	0xeaad8405

#define	IP_FRAG_TBL_POS(tbl, sig)	\
	((tbl)->pkt + ((sig) & (tbl)->entry_mask))

#ifdef RTE_LIBRTE_IP_FRAG_TBL_STAT
#define	IP_FRAG_TBL_STAT_UPDATE(s, f, v)	((s)->f += (v))
#else
#define	IP_FRAG_TBL_STAT_UPDATE(s, f, v)	do {} while (0)
#endif /* IP_FRAG_TBL_STAT */

/* local frag table helper functions */
static inline void
ip_frag_tbl_del(struct rte_ip_frag_tbl *tbl, struct rte_ip_frag_death_row *dr,
	struct ip_frag_pkt *fp)
{
	ip_frag_free(fp, dr);
	ip_frag_key_invalidate(&fp->key);
	TAILQ_REMOVE(&tbl->lru, fp, lru);
	tbl->use_entries--;
	IP_FRAG_TBL_STAT_UPDATE(&tbl->stat, del_num, 1);
}

static inline void
ip_frag_tbl_add(struct rte_ip_frag_tbl *tbl,  struct ip_frag_pkt *fp,
	const struct ip_frag_key *key, uint64_t tms)
{
	fp->key = key[0];
	ip_frag_reset(fp, tms);
	TAILQ_INSERT_TAIL(&tbl->lru, fp, lru);
	tbl->use_entries++;
	IP_FRAG_TBL_STAT_UPDATE(&tbl->stat, add_num, 1);
}

static inline void
ip_frag_tbl_reuse(struct rte_ip_frag_tbl *tbl, struct rte_ip_frag_death_row *dr,
	struct ip_frag_pkt *fp, uint64_t tms)
{
	ip_frag_free(fp, dr);
	ip_frag_reset(fp, tms);
	TAILQ_REMOVE(&tbl->lru, fp, lru);
	TAILQ_INSERT_TAIL(&tbl->lru, fp, lru);
	IP_FRAG_TBL_STAT_UPDATE(&tbl->stat, reuse_num, 1);
}


static inline void
ipv4_frag_hash(const struct ip_frag_key *key, uint32_t *v1, uint32_t *v2)
{
	uint32_t v;
	const uint32_t *p;

	p = (const uint32_t *)&key->src_dst;

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
	v = rte_hash_crc_4byte(p[0], PRIME_VALUE);
	v = rte_hash_crc_4byte(p[1], v);
	v = rte_hash_crc_4byte(key->id, v);
#else

	v = rte_jhash_3words(p[0], p[1], key->id, PRIME_VALUE);
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */

	*v1 =  v;
	*v2 = (v << 7) + (v >> 14);
}

static inline void
ipv6_frag_hash(const struct ip_frag_key *key, uint32_t *v1, uint32_t *v2)
{
	uint32_t v;
	const uint32_t *p;

	p = (const uint32_t *) &key->src_dst;

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
	v = rte_hash_crc_4byte(p[0], PRIME_VALUE);
	v = rte_hash_crc_4byte(p[1], v);
	v = rte_hash_crc_4byte(p[2], v);
	v = rte_hash_crc_4byte(p[3], v);
	v = rte_hash_crc_4byte(p[4], v);
	v = rte_hash_crc_4byte(p[5], v);
	v = rte_hash_crc_4byte(p[6], v);
	v = rte_hash_crc_4byte(p[7], v);
	v = rte_hash_crc_4byte(key->id, v);
#else

	v = rte_jhash_3words(p[0], p[1], p[2], PRIME_VALUE);
	v = rte_jhash_3words(p[3], p[4], p[5], v);
	v = rte_jhash_3words(p[6], p[7], key->id, v);
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */

	*v1 =  v;
	*v2 = (v << 7) + (v >> 14);
}


/*
	函数通过判断：
	1.如果此分片是第一个分片，有如下逻辑：
		如果第一分片的位置即数组索引为1的位置已经有mbuf保存了，那么会释放此结构，并返回NULL；如果没有被占用，将分片保存到数组中。
	2.如果此分片是最后一个分片，有如下逻辑：
		如果最后一分片的位置即数组索引为0的位置已经有mbuf保存了，那么会释放此结构，并返回NULL；如果没有被占用，将分片保存到数组中。
	3.如果此分片是中间分片，有入戏按逻辑：
		将分片保存到数组相应索引中。
	
	判断是否接收完所有的分片，如果未接收完分片，返回NULL；如果接收完分片，进行重组。
	如果重组后，返回的mbuf为NULL，那么释放所有的资源；如果返回的mbuf不为空，那么将此节点的key重置为未使用，并返回重组后的mbuf。
	
*/
struct rte_mbuf *
ip_frag_process(struct ip_frag_pkt *fp, struct rte_ip_frag_death_row *dr,
	struct rte_mbuf *mb, uint16_t ofs, uint16_t len, uint16_t more_frags)
{
	uint32_t idx;

	//计算所有已经到达分片的大小
	fp->frag_size += len;

	//是第一个分片
	if (ofs == 0) {
		idx = (fp->frags[IP_FIRST_FRAG_IDX].mb == NULL) ?
				IP_FIRST_FRAG_IDX : UINT32_MAX;

	//是最后一个分片
	} else if (more_frags == 0) {
		fp->total_size = ofs + len;
		idx = (fp->frags[IP_LAST_FRAG_IDX].mb == NULL) ?
				IP_LAST_FRAG_IDX : UINT32_MAX;

	//这是中间片段
	} else if ((idx = fp->last_idx) <
		sizeof (fp->frags) / sizeof (fp->frags[0])) {
		fp->last_idx++;
	}

	/*
	 * errorneous packet: either exceeed max allowed number of fragments,
	 * or duplicate first/last fragment encountered.
	 */
	 //错误：索引大于能够保存分片的缓存数组的大小
	if (idx >= sizeof (fp->frags) / sizeof (fp->frags[0])) {

		/* report an error. */
		if (fp->key.key_len == IPV4_KEYLEN)
			IP_FRAG_LOG(DEBUG, "%s:%d invalid fragmented packet:\n"
				"ipv4_frag_pkt: %p, key: <%" PRIx64 ", %#x>, "
				"total_size: %u, frag_size: %u, last_idx: %u\n"
				"first fragment: ofs: %u, len: %u\n"
				"last fragment: ofs: %u, len: %u\n\n",
				__func__, __LINE__,
				fp, fp->key.src_dst[0], fp->key.id,
				fp->total_size, fp->frag_size, fp->last_idx,
				fp->frags[IP_FIRST_FRAG_IDX].ofs,
				fp->frags[IP_FIRST_FRAG_IDX].len,
				fp->frags[IP_LAST_FRAG_IDX].ofs,
				fp->frags[IP_LAST_FRAG_IDX].len);
		else
			IP_FRAG_LOG(DEBUG, "%s:%d invalid fragmented packet:\n"
				"ipv4_frag_pkt: %p, key: <" IPv6_KEY_BYTES_FMT ", %#x>, "
				"total_size: %u, frag_size: %u, last_idx: %u\n"
				"first fragment: ofs: %u, len: %u\n"
				"last fragment: ofs: %u, len: %u\n\n",
				__func__, __LINE__,
				fp, IPv6_KEY_BYTES(fp->key.src_dst), fp->key.id,
				fp->total_size, fp->frag_size, fp->last_idx,
				fp->frags[IP_FIRST_FRAG_IDX].ofs,
				fp->frags[IP_FIRST_FRAG_IDX].len,
				fp->frags[IP_LAST_FRAG_IDX].ofs,
				fp->frags[IP_LAST_FRAG_IDX].len);

		/* free all fragments, invalidate the entry. */
		//释放所有分片，并将无效话节点
		ip_frag_free(fp, dr);
		ip_frag_key_invalidate(&fp->key);
		IP_FRAG_MBUF2DR(dr, mb);

		return NULL;
	}

	//赋值
	fp->frags[idx].ofs = ofs;
	fp->frags[idx].len = len;
	fp->frags[idx].mb = mb;

	mb = NULL;

	//不是所有的分片都到达，返回NULL
	if (likely (fp->frag_size < fp->total_size)) {
		return mb;

	//所有分片都叨叨，进行重组
	} else if (fp->frag_size == fp->total_size &&
			fp->frags[IP_FIRST_FRAG_IDX].mb != NULL) {
		if (fp->key.key_len == IPV4_KEYLEN)
			mb = ipv4_frag_reassemble(fp);
		else
			mb = ipv6_frag_reassemble(fp);
	}

	//如果mb为NULL，那么是重组错误，那么充值结构体fp，并将所有分片加入到释放空间中。
	if (mb == NULL) {

		/* report an error. */
		if (fp->key.key_len == IPV4_KEYLEN)
			IP_FRAG_LOG(DEBUG, "%s:%d invalid fragmented packet:\n"
				"ipv4_frag_pkt: %p, key: <%" PRIx64 ", %#x>, "
				"total_size: %u, frag_size: %u, last_idx: %u\n"
				"first fragment: ofs: %u, len: %u\n"
				"last fragment: ofs: %u, len: %u\n\n",
				__func__, __LINE__,
				fp, fp->key.src_dst[0], fp->key.id,
				fp->total_size, fp->frag_size, fp->last_idx,
				fp->frags[IP_FIRST_FRAG_IDX].ofs,
				fp->frags[IP_FIRST_FRAG_IDX].len,
				fp->frags[IP_LAST_FRAG_IDX].ofs,
				fp->frags[IP_LAST_FRAG_IDX].len);
		else
			IP_FRAG_LOG(DEBUG, "%s:%d invalid fragmented packet:\n"
				"ipv4_frag_pkt: %p, key: <" IPv6_KEY_BYTES_FMT ", %#x>, "
				"total_size: %u, frag_size: %u, last_idx: %u\n"
				"first fragment: ofs: %u, len: %u\n"
				"last fragment: ofs: %u, len: %u\n\n",
				__func__, __LINE__,
				fp, IPv6_KEY_BYTES(fp->key.src_dst), fp->key.id,
				fp->total_size, fp->frag_size, fp->last_idx,
				fp->frags[IP_FIRST_FRAG_IDX].ofs,
				fp->frags[IP_FIRST_FRAG_IDX].len,
				fp->frags[IP_LAST_FRAG_IDX].ofs,
				fp->frags[IP_LAST_FRAG_IDX].len);

		//释放资源
		ip_frag_free(fp, dr);
	}

	//充值key为未使用
	ip_frag_key_invalidate(&fp->key);
	return mb;
}


/*
 * Find an entry in the table for the corresponding fragment.
 * If such entry is not present, then allocate a new one.
 * If the entry is stale, then free and reuse it.
 */
struct ip_frag_pkt *
ip_frag_find(struct rte_ip_frag_tbl *tbl, struct rte_ip_frag_death_row *dr,
	const struct ip_frag_key *key, uint64_t tms)
{
	struct ip_frag_pkt *pkt, *free, *stale, *lru;
	uint64_t max_cycles;

	/*
	 * Actually the two line below are totally redundant.
	 * they are here, just to make gcc 4.6 happy.
	 */
	free = NULL;
	stale = NULL;
	max_cycles = tbl->max_cycles;

	IP_FRAG_TBL_STAT_UPDATE(&tbl->stat, find_num, 1);

	//通过key查找hash
	if ((pkt = ip_frag_lookup(tbl, key, tms, &free, &stale)) == NULL) {

		/*timed-out entry, free and invalidate it*/
		if (stale != NULL) {
			ip_frag_tbl_del(tbl, dr, stale);
			free = stale;

		/*
		 * we found a free entry, check if we can use it.
		 * If we run out of free entries in the table, then
		 * check if we have a timed out entry to delete.
		 */
		} else if (free != NULL &&
				tbl->max_entries <= tbl->use_entries) {
			lru = TAILQ_FIRST(&tbl->lru);
			if (max_cycles + lru->start < tms) {
				ip_frag_tbl_del(tbl, dr, lru);
			} else {
				free = NULL;
				IP_FRAG_TBL_STAT_UPDATE(&tbl->stat,
					fail_nospace, 1);
			}
		}

		/* found a free entry to reuse. */
		if (free != NULL) {
			ip_frag_tbl_add(tbl,  free, key, tms);
			pkt = free;
		}

	/*
	 * we found the flow, but it is already timed out,
	 * so free associated resources, reposition it in the LRU list,
	 * and reuse it.
	 */
	} else if (max_cycles + pkt->start < tms) {
		ip_frag_tbl_reuse(tbl, dr, pkt, tms);
	}

	IP_FRAG_TBL_STAT_UPDATE(&tbl->stat, fail_total, (pkt == NULL));

	tbl->last = pkt;
	return pkt;
}

struct ip_frag_pkt *
ip_frag_lookup(struct rte_ip_frag_tbl *tbl,
	const struct ip_frag_key *key, uint64_t tms,
	struct ip_frag_pkt **free, struct ip_frag_pkt **stale)
{
	struct ip_frag_pkt *p1, *p2;
	struct ip_frag_pkt *empty, *old;
	uint64_t max_cycles;
	uint32_t i, assoc, sig1, sig2;

	empty = NULL;
	old = NULL;

	max_cycles = tbl->max_cycles;
	assoc = tbl->bucket_entries;

	//如果有最后一个使用的元素，那么比较最后一个元素的key值是否相等。
	if (tbl->last != NULL && ip_frag_key_cmp(key, &tbl->last->key) == 0)
		return tbl->last;

	/* different hashing methods for IPv4 and IPv6 */
	if (key->key_len == IPV4_KEYLEN)
		ipv4_frag_hash(key, &sig1, &sig2);
	else
		ipv6_frag_hash(key, &sig1, &sig2);

	p1 = IP_FRAG_TBL_POS(tbl, sig1);
	p2 = IP_FRAG_TBL_POS(tbl, sig2);

	for (i = 0; i != assoc; i++) {
		if (p1->key.key_len == IPV4_KEYLEN)
			IP_FRAG_LOG(DEBUG, "%s:%d:\n"
					"tbl: %p, max_entries: %u, use_entries: %u\n"
					"ipv6_frag_pkt line0: %p, index: %u from %u\n"
			"key: <%" PRIx64 ", %#x>, start: %" PRIu64 "\n",
					__func__, __LINE__,
					tbl, tbl->max_entries, tbl->use_entries,
					p1, i, assoc,
			p1[i].key.src_dst[0], p1[i].key.id, p1[i].start);
		else
			IP_FRAG_LOG(DEBUG, "%s:%d:\n"
					"tbl: %p, max_entries: %u, use_entries: %u\n"
					"ipv6_frag_pkt line0: %p, index: %u from %u\n"
			"key: <" IPv6_KEY_BYTES_FMT ", %#x>, start: %" PRIu64 "\n",
					__func__, __LINE__,
					tbl, tbl->max_entries, tbl->use_entries,
					p1, i, assoc,
			IPv6_KEY_BYTES(p1[i].key.src_dst), p1[i].key.id, p1[i].start);

		if (ip_frag_key_cmp(key, &p1[i].key) == 0)//判断是否相等
			return p1 + i;
		else if (ip_frag_key_is_empty(&p1[i].key))//判断是否为空
			empty = (empty == NULL) ? (p1 + i) : empty;
		else if (max_cycles + p1[i].start < tms)//判断是否超时
			old = (old == NULL) ? (p1 + i) : old;

		if (p2->key.key_len == IPV4_KEYLEN)
			IP_FRAG_LOG(DEBUG, "%s:%d:\n"
					"tbl: %p, max_entries: %u, use_entries: %u\n"
					"ipv6_frag_pkt line1: %p, index: %u from %u\n"
			"key: <%" PRIx64 ", %#x>, start: %" PRIu64 "\n",
					__func__, __LINE__,
					tbl, tbl->max_entries, tbl->use_entries,
					p2, i, assoc,
			p2[i].key.src_dst[0], p2[i].key.id, p2[i].start);
		else
			IP_FRAG_LOG(DEBUG, "%s:%d:\n"
					"tbl: %p, max_entries: %u, use_entries: %u\n"
					"ipv6_frag_pkt line1: %p, index: %u from %u\n"
			"key: <" IPv6_KEY_BYTES_FMT ", %#x>, start: %" PRIu64 "\n",
					__func__, __LINE__,
					tbl, tbl->max_entries, tbl->use_entries,
					p2, i, assoc,
			IPv6_KEY_BYTES(p2[i].key.src_dst), p2[i].key.id, p2[i].start);

		if (ip_frag_key_cmp(key, &p2[i].key) == 0)//判断是否相等
			return p2 + i;
		else if (ip_frag_key_is_empty(&p2[i].key))//判断是否为空
			empty = (empty == NULL) ?( p2 + i) : empty;
		else if (max_cycles + p2[i].start < tms)//判断是否超时
			old = (old == NULL) ? (p2 + i) : old;
	}

	*free = empty;
	*stale = old;
	return NULL;
}
