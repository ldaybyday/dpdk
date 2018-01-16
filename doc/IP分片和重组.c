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
2.rte_ipv4_fragment_packet函数用于IP分片，其声明如下
		int32_t rte_ipv4_fragment_packet(struct rte_mbuf *pkt_in,//用于分片的mbuf数据
				struct rte_mbuf **pkts_out,//用于存储分片后mbuf的缓冲区
				uint16_t nb_pkts_out,//缓冲区的大小
				uint16_t mtu_size,//MTU的长度
				struct rte_mempool *pool_direct, //用于分配直接mbuf的内存池
				struct rte_mempool *pool_indirect)//用于分配间接mbuf的内存池
		此函数会为每一个分片分配一个直接mbuf和不定个数的间接mbuf组成一个mbuf链，每一个mbuf链用于保存一个mbuf分片数据。每一个直接mbuf的数据区只保存IPv4头部，间接m
	buf保存分片数据。
		调用此此函数时，需要将传入mbuf的ipv4头部的DF字段设置为0，表示允许分片。

二、重组
		dpdk重组通过hash表来存储收到的分片，并设置了老化时间。
		IPv4报文有一个16位的标识字段，每个分片的标识字段相同。MF表示还有其他分片，为0表示没有其他分片。DF为1表示不运行分片，DF为0表示运行分片.
	第一个分片和没分片的报文的偏移为0，后续分片此字段不为1.
		dpdk采用Cuckoo Hashing算法来实现。
		cuckoo hashing哈希函数会生成两个key值，先通过第一个key值找到篮子，看是否能够存储，如果不能存储那么久使用第二个key值。最终会分配一个新的或者找到的
	ip_frag_pkt结构体。如果此结构体超时，那么会将此结构体重新初始化，并释放原资源。
		
	结构体介绍：
		1.struct rte_ip_frag_tbl
		{
			uint64_t             max_cycles;      //老化时间
			uint32_t             entry_mask;      /**< hash value mask. */
			uint32_t             max_entries;     //允许最大条目个数
			uint32_t             use_entries;     //已经运用的条目个数
			uint32_t             bucket_entries;  //每个篮子条目个数
			uint32_t             nb_entries;      //分配的最大条目个数
			uint32_t             nb_buckets;      //篮子的个数
			struct ip_frag_pkt *last;         /**< last used entry. */
			struct ip_pkt_list lru;           /**< LRU list for table entries. */
			struct ip_frag_tbl_stat stat;     /**< statistics counters. */
			struct ip_frag_pkt pkt[0];        /**< hash table. */
		};
			作用：存储分片的hash结构体
		
		2.struct rte_ip_frag_death_row 
		{
			uint32_t cnt;         //个数
			struct rte_mbuf *row[IP_FRAG_DEATH_ROW_LEN * (IP_MAX_FRAG_NUM + 1)];//缓冲区
		};
			作用：用于存储老化了的mbuf,便于调用函数rte_ip_frag_free_death_row释放mbuf,其中为cnt为计数
		
		3.struct ip_frag_key 
		{
			uint64_t src_dst[4];      //ipv4的源地址第一个字节 
			uint32_t id;           // 用于保存IPV4标识字段，每发送一个报文，此字段加一
			uint32_t key_len;      /**< 长度 */
		};
			作用：分片hash表的key结构体
			
		4.struct ip_frag_pkt
		{
			TAILQ_ENTRY(ip_frag_pkt) lru;   /**< LRU list */
			struct ip_frag_key key;           //段的key
			uint64_t             start;       /**< creation timestamp */
			uint32_t             total_size;  /**< 期待到达的分片的总大小 */
			uint32_t             frag_size;   /**< 已经到达分片所有数据总大小 */
			uint32_t             last_idx;    /**< index of next entry to fill */
			struct ip_frag       frags[IP_MAX_FRAG_NUM]; /**< fragments */
		} __rte_cache_aligned;
			作用：结构体会用于保存所有的分片信息，其中frags用于保存具体的分片信息。
		
		struct ip_frag 
		{
			uint16_t ofs;          /**< offset into the packet */
			uint16_t len;          /**< length of fragment */
			struct rte_mbuf *mb;   /**< fragment mbuf */
		};

			
	函数介绍：
		1.struct rte_ip_frag_tbl * rte_ip_frag_table_create(
				uint32_t bucket_num,             //ip分片hash表的篮子个数
				uint32_t bucket_entries,  	     //每个篮子的条目个数
				uint32_t max_entries,            //ip hash表最多能够存储条目的个数，少于bucket_num * bucket_entries.
				uint64_t max_cycles,             //最大老化时间
				int socket_id);
			作用：用于创建ip分片表，存储接收到的分片
			
		2.static inline void rte_ip_frag_table_destroy( struct rte_ip_frag_tbl *tbl)
			作用：删除IP分片表
		
		3.static inline int rte_ipv4_frag_pkt_is_fragmented(const struct ipv4_hdr * hdr) 
			作用：函数通过判断IPv4头部的MF标记和数据偏移是否都为0，来决定此报文是不是分片。都为0，表示报文不是分片报文。
		
		4.struct rte_mbuf * rte_ipv4_frag_reassemble_packet(
				struct rte_ip_frag_tbl *tbl,   //分片hash表
				struct rte_ip_frag_death_row *dr, //释放结构体
				struct rte_mbuf *mb,              //当前分片mbuf
				uint64_t tms,                     //时钟
				struct ipv4_hdr *ip_hdr)          //ip头部结构体
	
		5.void rte_ip_frag_free_death_row(
				struct rte_ip_frag_death_row *dr,   //已经老化的缓冲区结构
				uint32_t prefetch)   //在释放前预取多少mbuf，用于加快释放速度

		6.void rte_ip_frag_table_statistics_dump(FILE * f, const struct rte_ip_frag_tbl *tbl);
			作用：向流中输入IP分表信息


