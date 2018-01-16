
#define	RTE_ACL_MAX_CATEGORIES	16

#define	RTE_ACL_RESULTS_MULTIPLIER	(XMM_SIZE / sizeof(uint32_t))

#define RTE_ACL_MAX_LEVELS 64
#define RTE_ACL_MAX_FIELDS 64

union rte_acl_field_types {
	uint8_t  u8;
	uint16_t u16;
	uint32_t u32;
	uint64_t u64;
};

enum {
	RTE_ACL_FIELD_TYPE_MASK = 0,
	RTE_ACL_FIELD_TYPE_RANGE,
	RTE_ACL_FIELD_TYPE_BITMASK
};

struct rte_acl_field_def {
	uint8_t  type;        /**< type - RTE_ACL_FIELD_TYPE_*. */
	uint8_t	 size;        /**< size of field 1,2,4, or 8. */
	uint8_t	 field_index; /**< index of field inside the rule. */
	uint8_t  input_index; /**< 0-N input index. */
	uint32_t offset;      /**< offset to start of field. */
};

struct rte_acl_config {
	uint32_t num_categories; /**< Number of categories to build with. */
	uint32_t num_fields;     /**< Number of field definitions. */
	struct rte_acl_field_def defs[RTE_ACL_MAX_FIELDS];
	/**< array of field definitions. */
	size_t max_size;
	/**< max memory limit for internal run-time structures. */
};

struct rte_acl_field {
	union rte_acl_field_types value;
	/**< a 1,2,4, or 8 byte value of the field. */
	union rte_acl_field_types mask_range;
	/**<
	 * depending on field type:
	 * mask -> 1.2.3.4/32 value=0x1020304, mask_range=32,
	 * range -> 0 : 65535 value=0, mask_range=65535,
	 * bitmask -> 0x06/0xff value=6, mask_range=0xff.
	 */
};

enum {
	RTE_ACL_TYPE_SHIFT = 29,
	RTE_ACL_MAX_INDEX = RTE_LEN2MASK(RTE_ACL_TYPE_SHIFT, uint32_t),
	RTE_ACL_MAX_PRIORITY = RTE_ACL_MAX_INDEX,
	RTE_ACL_MIN_PRIORITY = 0,
};

#define	RTE_ACL_INVALID_USERDATA	0

#define	RTE_ACL_MASKLEN_TO_BITMASK(v, s)	\
((v) == 0 ? (v) : (typeof(v))((uint64_t)-1 << ((s) * CHAR_BIT - (v))))

/**
 * Miscellaneous data for ACL rule.
 */
struct rte_acl_rule_data {
	uint32_t category_mask; /**< Mask of categories for that rule. */
	int32_t  priority;      /**< Priority for that rule. */
	uint32_t userdata;      /**< Associated with the rule user data. */
};

/**
 * Defines single ACL rule.
 * data - miscellaneous data for the rule.
 * field[] - value and mask or range for each field.
 */
#define	RTE_ACL_RULE_DEF(name, fld_num)	struct name {\
	struct rte_acl_rule_data data;               \
	struct rte_acl_field field[fld_num];         \
}

RTE_ACL_RULE_DEF(rte_acl_rule, 0);

#define	RTE_ACL_RULE_SZ(fld_num)	\
	(sizeof(struct rte_acl_rule) + sizeof(struct rte_acl_field) * (fld_num))


/** Max number of characters in name.*/
#define	RTE_ACL_NAMESIZE		32

/**
 * Parameters used when creating the ACL context.
 */
struct rte_acl_param {
	const char *name;         /**< Name of the ACL context. */
	int         socket_id;    /**< Socket ID to allocate memory for. */
	uint32_t    rule_size;    /**< Size of each rule. */
	uint32_t    max_rule_num; /**< Maximum number of rules. */
};

 //创建acl管理结构
struct rte_acl_ctx * rte_acl_create(const struct rte_acl_param *param);

 //通过名称查找acl结构
struct rte_acl_ctx *rte_acl_find_existing(const char *name);

//释放删除acl结构
void rte_acl_free(struct rte_acl_ctx *ctx);


//向acl结构添加规则rules，其中num为要添加规则个数，rules为规则数组
int rte_acl_add_rules(struct rte_acl_ctx *ctx, const struct rte_acl_rule *rules, uint32_t num);

 //重置ctx结构体，将其有效规则个数置为0
void rte_acl_reset_rules(struct rte_acl_ctx *ctx);


//分析规则，建立内部需要的运行时结构。非线程安全
int rte_acl_build(struct rte_acl_ctx *ctx, const struct rte_acl_config *cfg);


//重置ctx结构体，并重新build。非线程安全
void rte_acl_reset(struct rte_acl_ctx *ctx);

/**
 *  Available implementations of ACL classify.
 */
enum rte_acl_classify_alg {
	RTE_ACL_CLASSIFY_DEFAULT = 0,
	RTE_ACL_CLASSIFY_SCALAR = 1,  /**< generic implementation. */
	RTE_ACL_CLASSIFY_SSE = 2,     /**< requires SSE4.1 support. */
	RTE_ACL_CLASSIFY_AVX2 = 3,    /**< requires AVX2 support. */
	RTE_ACL_CLASSIFY_NEON = 4,    /**< requires NEON support. */
	RTE_ACL_CLASSIFY_NUM          /* should always be the last one. */
};

/**
 * Perform search for a matching ACL rule for each input data buffer.
 * Each input data buffer can have up to *categories* matches.
 * That implies that results array should be big enough to hold
 * (categories * num) elements.
 * Also categories parameter should be either one or multiple of
 * RTE_ACL_RESULTS_MULTIPLIER and can't be bigger than RTE_ACL_MAX_CATEGORIES.
 * If more than one rule is applicable for given input buffer and
 * given category, then rule with highest priority will be returned as a match.
 * Note, that it is a caller's responsibility to ensure that input parameters
 * are valid and point to correct memory locations.
 *
 * @param ctx
 *   ACL context to search with.
 * @param data
 *   Array of pointers to input data buffers to perform search.
 *   Note that all fields in input data buffers supposed to be in network
 *   byte order (MSB).
 * @param results
 *   Array of search results, *categories* results per each input data buffer.
 * @param num
 *   Number of elements in the input data buffers array.
 * @param categories
 *   Number of maximum possible matches for each input buffer, one possible
 *   match per category.
 * @return
 *   zero on successful completion.
 *   -EINVAL for incorrect arguments.
 */
extern int
rte_acl_classify(const struct rte_acl_ctx *ctx,
		 const uint8_t **data,
		 uint32_t *results, uint32_t num,
		 uint32_t categories);

/**
 * Perform search using specified algorithm for a matching ACL rule for
 * each input data buffer.
 * Each input data buffer can have up to *categories* matches.
 * That implies that results array should be big enough to hold
 * (categories * num) elements.
 * Also categories parameter should be either one or multiple of
 * RTE_ACL_RESULTS_MULTIPLIER and can't be bigger than RTE_ACL_MAX_CATEGORIES.
 * If more than one rule is applicable for given input buffer and
 * given category, then rule with highest priority will be returned as a match.
 * Note, that it is a caller's responsibility to ensure that input parameters
 * are valid and point to correct memory locations.
 *
 * @param ctx
 *   ACL context to search with.
 * @param data
 *   Array of pointers to input data buffers to perform search.
 *   Note that all fields in input data buffers supposed to be in network
 *   byte order (MSB).
 * @param results
 *   Array of search results, *categories* results per each input data buffer.
 * @param num
 *   Number of elements in the input data buffers array.
 * @param categories
 *   Number of maximum possible matches for each input buffer, one possible
 *   match per category.
 * @param alg
 *   Algorithm to be used for the search.
 *   It is the caller responsibility to ensure that the value refers to the
 *   existing algorithm, and that it could be run on the given CPU.
 * @return
 *   zero on successful completion.
 *   -EINVAL for incorrect arguments.
 */
extern int
rte_acl_classify_alg(const struct rte_acl_ctx *ctx,
		 const uint8_t **data,
		 uint32_t *results, uint32_t num,
		 uint32_t categories,
		 enum rte_acl_classify_alg alg);

/*
 * Override the default classifier function for a given ACL context.
 * @param ctx
 *   ACL context to change classify function for.
 * @param alg
 *   New default classify algorithm for given ACL context.
 *   It is the caller responsibility to ensure that the value refers to the
 *   existing algorithm, and that it could be run on the given CPU.
 * @return
 *   - -EINVAL if the parameters are invalid.
 *   - Zero if operation completed successfully.
 */
extern int
rte_acl_set_ctx_classify(struct rte_acl_ctx *ctx,
	enum rte_acl_classify_alg alg);

/**
 * Dump an ACL context structure to the console.
 *
 * @param ctx
 *   ACL context to dump.
 */
void
rte_acl_dump(const struct rte_acl_ctx *ctx);

/**
 * Dump all ACL context structures to the console.
 */
void
rte_acl_list_dump(void);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ACL_H_ */
