#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

static volatile bool force_quit;

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define NB_MBUF   8192

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static const struct rte_eth_conf port_conf =
{
    .rxmode =
    {
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
    .txmode =
    {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct rte_mempool * l2fwd_pktmbuf_pool = NULL;

/* A tsc-based timer responsible for triggering statistics printout */
#define TIMER_MILLISECOND 2000000ULL /* around 1ms at 2 Ghz */
#define MAX_TIMER_PERIOD 86400 /* 1 day max */

//主线程循环
static void l2fwd_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    unsigned k, nb_rx;

    while(1)
    {
        nb_rx = rte_eth_rx_burst((uint8_t) 0, 0, pkts_burst, MAX_PKT_BURST);

        if (nb_rx > 0)
        {
            printf("nb_rx = %d\n", nb_rx);

            for (k=0; k<nb_rx; k++)
            {
                rte_pktmbuf_free(pkts_burst[k]);
            }
        }
    }
}

static int
l2fwd_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	l2fwd_main_loop();
	return 0;
}

static void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++)
    {
		if (force_quit)
			return;
		all_ports_up = 1;
        for (portid = 0; portid < port_num; portid++)
        {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
            if (link.link_status == ETH_LINK_DOWN)
            {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

        if (all_ports_up == 0)
        {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1))
        {
			print_flag = 1;
			printf("done\n");
		}
	}
}

void InitPort(int portid)
{
    int ret;

    printf("Initializing port %u... ", (unsigned) portid);

    //初始化端口信息
    fflush(stdout);
    ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", ret, (unsigned) portid);
    }

    //初始化接收队列
    fflush(stdout);
    ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd, rte_eth_dev_socket_id(portid), NULL, l2fwd_pktmbuf_pool);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", ret, (unsigned) portid);
    }

    //初始化发送队列
    fflush(stdout);
    ret = rte_eth_tx_queue_setup(portid, 0, nb_txd, rte_eth_dev_socket_id(portid), NULL);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n", ret, (unsigned) portid);
    }

    //开启设备
    ret = rte_eth_dev_start(portid);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret, (unsigned) portid);
    }

    printf("done: \n");

    //设置设备为混杂模式
    rte_eth_promiscuous_enable(portid);
}

int main(int argc, char **argv)
{
	int ret;
	uint8_t nb_ports;
    unsigned lcore_id;

    //初始化EAL
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
    {
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    }
	argc -= ret;
	argv += ret;

	force_quit = false;

    //创建mbuf内存池
	l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF, 32,
		0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (l2fwd_pktmbuf_pool == NULL)
    {
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
    }

    //获取端口设备个数
	nb_ports = rte_eth_dev_count();
    printf("dev count: %d\n", nb_ports);

    //初始化端口0
    InitPort(0);

    //检查设备
    check_all_ports_link_status(1, 1);

    printf("rte_get_master_lcore = %d\n", rte_get_master_lcore());

	ret = 0;
    if (0 != rte_eal_remote_launch(l2fwd_launch_one_lcore, NULL, 3))
    {
        printf("开启处理线程失败\n");
    }


    RTE_LCORE_FOREACH_SLAVE(lcore_id)
    {
        if (rte_eal_wait_lcore(lcore_id) < 0)
        {
            ret = -1;
            break;
        }
    }
    while(1)
    {
        sleep(100);
    }

	printf("Bye...\n");

	return ret;
}
