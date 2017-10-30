一、IP分片
1.IP分片原理
		不同链路类型的链路规定了不同的传输最大数据帧的长度，称为MTU。当使用IP协议进行通讯时，IP报文长度超过MTU时，会进行分片，保证每个数据帧
	不大于MTU。
		IP头部和分片相关字段有三个：
			1）.一个是DF标识，标识是否允许分片，如果需要分片，但DF标识又设置为1（不允许分片），那么就会丢弃此数据包，并返回一个ICMP差错报文。
			2）.一个13位的偏移字段，其必须为8的整数倍，标识此分片数据的偏移量，第一个分片长度为0.
			3）.一个是MF标识。如果为0表示没有其他分片，如果为1表示后面还有其他分片。
		分片只有第一个分片有TCP头部信息
		由于TCP是可靠传输，如果一个分片丢失超时，将进行重传，由于IP协议没有重传机制，因此需要TCP来进行超时重传因此TCP要尽量保证不分片。TCP
	通过三次握手确认的MSS(MTU-TCP头部长度-IP头部长度)值来传输TCP数据，从而保证不分片。
		由于UDP是不可靠传输和超时机制，因此需要考虑分片问题。  
		分片可能带来的问题：
			1）带来性能问题
			2）分片丢失将导致重传所有分片问题
			3）分片攻击。黑客可能截获最后一个分片，导致接收端永远接收不到，将导致接收端等待，知道接收端发送ICMP重组超时差错报文。如果这种情况多，
			   将导致内存资源耗尽，无法进行正常业务处理。
			4）
2.rte_ipv4_fragment_packet函数用于IP分片。
int32_t rte_ipv4_fragment_packet(struct rte_mbuf *pkt_in,//用于分片的mbuf数据
		struct rte_mbuf **pkts_out,//用于存储分片后mbuf的缓冲区
		uint16_t nb_pkts_out,//缓冲区的大小
		uint16_t mtu_size,//MTU的长度
		struct rte_mempool *pool_direct,
		struct rte_mempool *pool_indirect)
{
	struct rte_mbuf *in_seg = NULL;
	struct ipv4_hdr *in_hdr;
	uint32_t out_pkt_pos, in_seg_data_pos;
	uint32_t more_in_segs;
	uint16_t fragment_offset, flag_offset, frag_size;

	frag_size = (uint16_t)(mtu_size - sizeof(struct ipv4_hdr));

	/* Fragment size should be a multiply of 8. */
	IP_FRAG_ASSERT((frag_size & IPV4_HDR_FO_MASK) == 0);

	//获取ipv4头部
	in_hdr = rte_pktmbuf_mtod(pkt_in, struct ipv4_hdr *);
	flag_offset = rte_cpu_to_be_16(in_hdr->fragment_offset);

	//判断分段标识是否被设置
	if (unlikely ((flag_offset & IPV4_HDR_DF_MASK) != 0))
		return -ENOTSUP;

	//判断剩余缓冲区是否能够存储所有的分段数据。其中frag_size表示每个报文能够存储数据的空间大小，nb_pkts_out表示缓冲区个数
	//(pkt_in->pkt_len - sizeof (struct ipv4_hdr))表示报文出去IPv4头部后剩余的报文长度
	if (unlikely(frag_size * nb_pkts_out <
	    (uint16_t)(pkt_in->pkt_len - sizeof (struct ipv4_hdr))))
		return -EINVAL;

	in_seg = pkt_in;
	in_seg_data_pos = sizeof(struct ipv4_hdr);
	out_pkt_pos = 0;
	fragment_offset = 0;

	more_in_segs = 1;
	while (likely(more_in_segs)) {
		struct rte_mbuf *out_pkt = NULL, *out_seg_prev = NULL;
		uint32_t more_out_segs;
		struct ipv4_hdr *out_hdr;

		/* Allocate direct buffer */
		out_pkt = rte_pktmbuf_alloc(pool_direct);
		if (unlikely(out_pkt == NULL)) {
			__free_fragments(pkts_out, out_pkt_pos);
			return -ENOMEM;
		}

		/* Reserve space for the IP header that will be built later */
		out_pkt->data_len = sizeof(struct ipv4_hdr);
		out_pkt->pkt_len = sizeof(struct ipv4_hdr);

		out_seg_prev = out_pkt;
		more_out_segs = 1;
		while (likely(more_out_segs && more_in_segs)) {
			struct rte_mbuf *out_seg = NULL;
			uint32_t len;

			/* Allocate indirect buffer */
			out_seg = rte_pktmbuf_alloc(pool_indirect);
			if (unlikely(out_seg == NULL)) {
				rte_pktmbuf_free(out_pkt);
				__free_fragments(pkts_out, out_pkt_pos);
				return -ENOMEM;
			}
			out_seg_prev->next = out_seg;
			out_seg_prev = out_seg;

			/* Prepare indirect buffer */
			rte_pktmbuf_attach(out_seg, in_seg);
			len = mtu_size - out_pkt->pkt_len;
			if (len > (in_seg->data_len - in_seg_data_pos)) {
				len = in_seg->data_len - in_seg_data_pos;
			}
			out_seg->data_off = in_seg->data_off + in_seg_data_pos;
			out_seg->data_len = (uint16_t)len;
			out_pkt->pkt_len = (uint16_t)(len +
			    out_pkt->pkt_len);
			out_pkt->nb_segs += 1;
			in_seg_data_pos += len;

			/* Current output packet (i.e. fragment) done ? */
			if (unlikely(out_pkt->pkt_len >= mtu_size))
				more_out_segs = 0;

			/* Current input segment done ? */
			if (unlikely(in_seg_data_pos == in_seg->data_len)) {
				in_seg = in_seg->next;
				in_seg_data_pos = 0;

				if (unlikely(in_seg == NULL))
					more_in_segs = 0;
			}
		}

		/* Build the IP header */
		out_hdr = rte_pktmbuf_mtod(out_pkt, struct ipv4_hdr *);

		__fill_ipv4hdr_frag(out_hdr, in_hdr,
		    (uint16_t)out_pkt->pkt_len,
		    flag_offset, fragment_offset, more_in_segs);

		fragment_offset = (uint16_t)(fragment_offset +
		    out_pkt->pkt_len - sizeof(struct ipv4_hdr));

		out_pkt->ol_flags |= PKT_TX_IP_CKSUM;
		out_pkt->l3_len = sizeof(struct ipv4_hdr);

		/* Write the fragment to the output list */
		pkts_out[out_pkt_pos] = out_pkt;
		out_pkt_pos ++;
	}

	return out_pkt_pos;
}

二、重组