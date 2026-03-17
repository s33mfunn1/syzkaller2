/*
 * GTP TAP Injector - отправляет GTP пакет через TAP для триггера netdev_dbg в gtp.c
 *
 * Триггерит netdev_dbg в gtp_encap_recv (строки 680, 684, 688, 697, 701, 702):
 * - "encap_recv sk=%p"
 * - "received GTP1U packet"
 * - "No PDP ctx to decap skb=%p" -> "pass up to the process"
 * - "GTP packet has been dropped" (при коротком/битом пакете)
 *
 * Требования:
 * 1. GTP интерфейс: ip link add gtp0 type gtp role ggsn
 * 2. IP на gtp0: ip addr add 192.168.60.1/24 dev gtp0 && ip link set gtp0 up
 * 3. TAP: программа создаёт tap0
 * 4. Включить KERN_DEBUG: echo 8 > /proc/sys/kernel/printk
 *
 * Сборка: gcc -o gtp_tap_inject gtp_tap_inject.c
 * Запуск: sudo ./gtp_tap_inject 192.168.60.1
 * С coverage: sudo ./gtp_tap_inject --coverage 192.168.60.1
 *   (требует CONFIG_KCOV=y, mount -t debugfs none /sys/kernel/debug)
 */

 #define _GNU_SOURCE

 #include <arpa/inet.h>
 #include <errno.h>
 #include <fcntl.h>
 #include <linux/if.h>
 #include <linux/if_arp.h>
 #include <linux/if_ether.h>
 #include <linux/if_tun.h>
 #include <linux/ip.h>
 #include <linux/types.h>
 #include <linux/udp.h>
 #include <netinet/in.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <sys/ioctl.h>
 #include <sys/mman.h>
 #include <sys/socket.h>
 #include <unistd.h>
 
 /* KCOV: для сбора coverage в gtp.c (TUN ставит kcov_handle на skb) */
 #define KCOV_PATH		"/sys/kernel/debug/kcov"
 #define KCOV_INIT_TRACE		_IOR('c', 1, unsigned long)
 #define KCOV_DISABLE		_IO('c', 101)
 #define KCOV_REMOTE_ENABLE	_IOW('c', 102, struct kcov_remote_arg)
 #define KCOV_TRACE_PC		0
 #define KCOV_SUBSYSTEM_COMMON	(0x00ull << 56)
 #define KCOV_INSTANCE_MASK	(0xffffffffull)
 #define KCOV_COVER_SIZE		(64 << 10)
 
 struct kcov_remote_arg {
     __u32 trace_mode;
     __u32 area_size;
     __u32 num_handles;
     __u64 common_handle;
     __u64 handles[];
 };
 
 static inline __u64 kcov_remote_handle(__u64 subsys, __u64 inst)
 {
     return subsys | inst;
 }
 
 #define TAP_DEVICE   "/dev/net/tun"
 #define GTP1U_PORT   2152
 #define GTP_TPDU     255
 
 /* GTP1-U header (3GPP TS 29.060) */
 struct gtp1_header {
     __u8   flags;   /* version, PT, etc */
     __u8   type;
     __be16 length;
     __be32 tid;
 } __attribute__((packed));
 
 static uint16_t ip_checksum(const void *data, int len)
 {
     const uint16_t *p = data;
     uint32_t sum = 0;
 
     while (len > 1) {
         sum += *p++;
         len -= 2;
     }
     if (len)
         sum += *(const uint8_t *)p;
 
     while (sum >> 16)
         sum = (sum & 0xffff) + (sum >> 16);
 
     return ~sum;
 }
 
 static int tap_alloc(char *dev, int flags)
 {
     struct ifreq ifr;
     int fd, err;
 
     fd = open(TAP_DEVICE, O_RDWR);
     if (fd < 0) {
         perror("open /dev/net/tun");
         return -1;
     }
 
     memset(&ifr, 0, sizeof(ifr));
     ifr.ifr_flags = flags;
     if (*dev)
         strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
 
     err = ioctl(fd, TUNSETIFF, (void *)&ifr);
     if (err < 0) {
         perror("ioctl TUNSETIFF");
         close(fd);
         return -1;
     }
 
     strncpy(dev, ifr.ifr_name, IFNAMSIZ - 1);
     return fd;
 }
 
 static int if_up(const char *dev)
 {
     struct ifreq ifr;
     int sock = socket(AF_INET, SOCK_DGRAM, 0);
 
     if (sock < 0) {
         perror("socket");
         return -1;
     }
 
     memset(&ifr, 0, sizeof(ifr));
     strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
 
     if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
         perror("ioctl SIOCGIFFLAGS");
         close(sock);
         return -1;
     }
 
     ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
 
     if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
         perror("ioctl SIOCSIFFLAGS");
         close(sock);
         return -1;
     }
 
     close(sock);
     return 0;
 }
 
 /* Задать MAC-адрес интерфейса. mac[6] - unicast (первый байт чётный) */
 static int set_if_mac(const char *dev, const unsigned char *mac)
 {
     struct ifreq ifr;
     int sock = socket(AF_INET, SOCK_DGRAM, 0);
 
     if (sock < 0) {
         perror("socket");
         return -1;
     }
 
     memset(&ifr, 0, sizeof(ifr));
     strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
     ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
     memcpy(ifr.ifr_hwaddr.sa_data, mac, ETH_ALEN);
 
     if (ioctl(sock, SIOCSIFHWADDR, &ifr) < 0) {
         perror("ioctl SIOCSIFHWADDR");
         close(sock);
         return -1;
     }
 
     printf("TAP %s MAC set to %02x:%02x:%02x:%02x:%02x:%02x\n",
            dev, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
     close(sock);
     return 0;
 }
 
 /* Парсинг MAC из строки "02:11:22:33:44:55" или "02-11-22-33-44-55" */
 static int parse_mac(const char *str, unsigned char *mac)
 {
     unsigned int m[6];
     int n;
 
     n = sscanf(str, "%x:%x:%x:%x:%x:%x",
            &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
     if (n != 6) {
         n = sscanf(str, "%x-%x-%x-%x-%x-%x",
                &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
     }
     if (n != 6)
         return -1;
 
     for (int i = 0; i < 6; i++) {
         if (m[i] > 0xff)
             return -1;
         mac[i] = (unsigned char)m[i];
     }
     /* unicast: первый байт чётный */
     if (mac[0] & 1) {
         fprintf(stderr, "MAC must be unicast (first byte even), got %02x\n", mac[0]);
         return -1;
     }
     return 0;
 }
 
 /* Настраивает маршрутизацию: IP на TAP, отключает rp_filter */
 static int setup_tap_routing(const char *dev, struct in_addr dst_ip)
 {
     char path[128], cmd[384];
     FILE *f;
     uint32_t base = ntohl(dst_ip.s_addr) & 0xffffff00;
     int a = (base >> 24) & 0xff, b = (base >> 16) & 0xff, c = (base >> 8) & 0xff;
 
     /* 1. Назначить IP на TAP в той же подсети что и GTP */
     snprintf(cmd, sizeof(cmd), "ip addr add %u.%u.%u.2/24 dev %s 2>/dev/null", a, b, c, dev);
     if (system(cmd) != 0) {
         /* Может уже назначен */
         snprintf(cmd, sizeof(cmd), "ip addr replace %u.%u.%u.2/24 dev %s 2>/dev/null", a, b, c, dev);
         system(cmd);
     }
 
     /* 2. Отключить rp_filter - иначе ядро отбросит пакет при проверке reverse path */
     snprintf(path, sizeof(path), "/proc/sys/net/ipv4/conf/%s/rp_filter", dev);
     f = fopen(path, "w");
     if (f) {
         fprintf(f, "0");
         fclose(f);
     }
 
     /* 3. accept_local=1 - принять пакет с src=наш адрес (192.168.60.2 на TAP) */
     snprintf(path, sizeof(path), "/proc/sys/net/ipv4/conf/%s/accept_local", dev);
     f = fopen(path, "w");
     if (f) {
         fprintf(f, "1");
         fclose(f);
     }
 
     return 0;
 }
 
 /* Получить MAC адрес интерфейса для dst в Ethernet frame */
 static void print_ethernet_packet(const unsigned char *buf, int len)
 {
     printf("\n--- Ethernet packet (%d bytes) ---\n", len);
     for (int i = 0; i < len; i++) {
         printf("%02x ", buf[i]);
         if ((i + 1) % 16 == 0)
             printf("\n");
         else if ((i + 1) % 8 == 0)
             printf(" ");
     }
     if (len % 16 != 0)
         printf("\n");
 
     /* Расшифровка заголовков */
     if (len >= 14) {
         printf("\n  Eth: dst %02x:%02x:%02x:%02x:%02x:%02x  src %02x:%02x:%02x:%02x:%02x:%02x  type 0x%04x\n",
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
                buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
                (unsigned int)(buf[12] << 8 | buf[13]));
     }
     if (len >= 34) {
         printf("  IP:  src %u.%u.%u.%u  dst %u.%u.%u.%u  proto %u\n",
                buf[26], buf[27], buf[28], buf[29],
                buf[30], buf[31], buf[32], buf[33],
                (unsigned int)buf[23]);
     }
     if (len >= 42) {
         printf("  UDP: src %u  dst %u  len %u\n",
                (unsigned int)(buf[34] << 8 | buf[35]),
                (unsigned int)(buf[36] << 8 | buf[37]),
                (unsigned int)(buf[38] << 8 | buf[39]));
     }
     printf("---\n\n");
 }
 
 static int get_if_mac(const char *dev, unsigned char *mac)
 {
     struct ifreq ifr;
     int sock = socket(AF_INET, SOCK_DGRAM, 0);
 
     if (sock < 0)
         return -1;
 
     memset(&ifr, 0, sizeof(ifr));
     strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
 
     if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
         close(sock);
         return -1;
     }
 
     memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
     close(sock);
     return 0;
 }
 
 /* Создаёт GTP1-U T-PDU пакет с несуществующим TID -> ret=1 -> "pass up to the process" */
 static int build_gtp_packet(unsigned char *buf, int buf_len,
                struct in_addr dst_ip, struct in_addr src_ip,
                const unsigned char *dst_mac)
 {
     struct ethhdr *eth = (struct ethhdr *)buf;
     struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
     struct udphdr *udph = (struct udphdr *)(buf + sizeof(struct ethhdr) + sizeof(struct iphdr));
     struct gtp1_header *gtp1 = (struct gtp1_header *)(buf + sizeof(struct ethhdr) +
                                sizeof(struct iphdr) + sizeof(struct udphdr));
     unsigned char *payload = (unsigned char *)(gtp1 + 1);
     int udp_len, gtp_payload_len = 20; /* минимальный inner IP */
 
     int total = sizeof(struct ethhdr) + sizeof(struct iphdr) +
             sizeof(struct udphdr) + sizeof(struct gtp1_header) + gtp_payload_len;
 
     if (buf_len < total)
         return -1;
 
     memset(buf, 0, total);
 
     /* Ethernet: dst = MAC TAP (пакет "для нас"), src = произвольный */
     memcpy(eth->h_dest, dst_mac, ETH_ALEN);
     memset(eth->h_source, 0x02, ETH_ALEN);
     eth->h_proto = htons(ETH_P_IP);
 
     /* IP */
     iph->version  = 4;
     iph->ihl      = 5;
     iph->tos      = 0;
     iph->tot_len  = htons(total - sizeof(struct ethhdr));
     iph->id       = htons(1);
     iph->frag_off = 0;
     iph->ttl      = 64;
     iph->protocol = IPPROTO_UDP;
     iph->saddr    = src_ip.s_addr;
     iph->daddr    = dst_ip.s_addr;
     iph->check    = 0;
     iph->check    = ip_checksum(iph, sizeof(struct iphdr));
 
     /* UDP */
     udp_len = sizeof(struct udphdr) + sizeof(struct gtp1_header) + gtp_payload_len;
     udph->source = htons(12345);
     udph->dest   = htons(GTP1U_PORT);
     udph->len    = htons(udp_len);
     udph->check  = 0; /* optional для IPv4 */
 
     /* GTP1-U header: flags=0x30 (v1, GTP-non-prime), type=TPDU */
     gtp1->flags  = 0x30;
     gtp1->type   = GTP_TPDU;
     gtp1->length = htons(sizeof(struct gtp1_header) + gtp_payload_len - 8);
     gtp1->tid    = htonl(0xdeadbeef); /* несуществующий TEID -> No PDP ctx */
 
     /* Минимальный inner IP (чтобы pskb_may_pull не падал) */
     payload[0] = 0x45; /* IP version 4, ihl 5 */
     payload[1] = 0;
     *(uint16_t *)(payload + 2) = htons(20);
     payload[9] = 17; /* UDP */
     *(uint32_t *)(payload + 12) = inet_addr("192.168.1.1");
     *(uint32_t *)(payload + 16) = inet_addr("192.168.1.2");
 
     return total;
 }
 
 /* Короткий пакет -> pskb_may_pull fail -> ret=-1 -> "GTP packet has been dropped" */
 static int build_short_gtp_packet(unsigned char *buf, int buf_len,
                   struct in_addr dst_ip, struct in_addr src_ip,
                   const unsigned char *dst_mac)
 {
     struct ethhdr *eth = (struct ethhdr *)buf;
     struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
     struct udphdr *udph = (struct udphdr *)(buf + sizeof(struct ethhdr) + sizeof(struct iphdr));
     int total = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 4;
 
     if (buf_len < total)
         return -1;
 
     memset(buf, 0, total);
 
     memcpy(eth->h_dest, dst_mac, ETH_ALEN);
     memset(eth->h_source, 0x02, ETH_ALEN);
     eth->h_proto = htons(ETH_P_IP);
 
     iph->version  = 4;
     iph->ihl      = 5;
     iph->tos      = 0;
     iph->tot_len  = htons(total - sizeof(struct ethhdr));
     iph->id       = htons(2);
     iph->frag_off = 0;
     iph->ttl      = 64;
     iph->protocol = IPPROTO_UDP;
     iph->saddr    = src_ip.s_addr;
     iph->daddr    = dst_ip.s_addr;
     iph->check    = 0;
     iph->check    = ip_checksum(iph, sizeof(struct iphdr));
 
     udph->source = htons(12346);
     udph->dest   = htons(GTP1U_PORT);
     udph->len    = htons(12); /* UDP header + 4 bytes - меньше чем GTP header */
     udph->check  = 0;
 
     /* Только 4 байта - недостаточно для GTP header (8 байт) */
     buf[total - 4] = 0x30;
     buf[total - 3] = GTP_TPDU;
 
     return total;
 }
 
 /* MAC по умолчанию для TAP (unicast) */
 static const unsigned char default_tap_mac[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
 
 /* KCOV: открыть, инициализировать, включить remote coverage (common_handle) */
 static int kcov_setup(int *fd_out, unsigned long **cover_out)
 {
     int fd;
     unsigned long *cover;
     struct kcov_remote_arg *arg;
 
     fd = open(KCOV_PATH, O_RDWR);
     if (fd < 0) {
         perror(KCOV_PATH);
         return -1;
     }
     if (ioctl(fd, KCOV_INIT_TRACE, KCOV_COVER_SIZE) < 0) {
         perror("ioctl KCOV_INIT_TRACE");
         close(fd);
         return -1;
     }
     cover = mmap(NULL, KCOV_COVER_SIZE * sizeof(unsigned long),
              PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
     if (cover == MAP_FAILED) {
         perror("mmap kcov");
         close(fd);
         return -1;
     }
     arg = calloc(1, sizeof(*arg));
     if (!arg) {
         munmap(cover, KCOV_COVER_SIZE * sizeof(unsigned long));
         close(fd);
         return -1;
     }
     arg->trace_mode = KCOV_TRACE_PC;
     arg->area_size = KCOV_COVER_SIZE;
     arg->num_handles = 0;
     /* Уникальный handle на процесс — избегаем EEXIST от предыдущего запуска */
     arg->common_handle = kcov_remote_handle(KCOV_SUBSYSTEM_COMMON, (__u64)getpid());
     if (ioctl(fd, KCOV_REMOTE_ENABLE, arg) < 0) {
         perror("ioctl KCOV_REMOTE_ENABLE");
         free(arg);
         munmap(cover, KCOV_COVER_SIZE * sizeof(unsigned long));
         close(fd);
         return -1;
     }
     free(arg);
     *fd_out = fd;
     *cover_out = cover;
     return 0;
 }
 
 /* KCOV: kcov пишет _RET_IP_ (адрес возврата = call+5), syzkaller ждёт адрес call.
  * x86 call rel32 = 5 байт, вычитаем для совместимости с syz-cover. */
 #define KCOV_RET_IP_OFFSET	5
 
 /* KCOV: вывести coverage и отключить. coverfile — путь для syz-cover (raw PCs) */
 static void kcov_teardown(int fd, unsigned long *cover, const char *coverfile)
 {
     unsigned long n, i;
     unsigned long pc;
     FILE *f = NULL;
 
     if (ioctl(fd, KCOV_DISABLE, 0) < 0)
         perror("ioctl KCOV_DISABLE");
     n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
     if (n > 0 && coverfile) {
         f = fopen(coverfile, "w");
         if (f) {
             for (i = 0; i < n; i++) {
                 pc = cover[i + 1];
                 if (pc >= KCOV_RET_IP_OFFSET)
                     pc -= KCOV_RET_IP_OFFSET;
                 fprintf(f, "0x%lx\n", pc);
             }
             fclose(f);
             fprintf(stderr, "KCOV: %lu PCs -> %s (syz-cover format)\n", n, coverfile);
         } else {
             perror(coverfile);
         }
     } else if (n > 0) {
         /* stdout: syz-cover format (можно pipe в syz-cover) */
         for (i = 0; i < n; i++) {
             pc = cover[i + 1];
             if (pc >= KCOV_RET_IP_OFFSET)
                 pc -= KCOV_RET_IP_OFFSET;
             printf("0x%lx\n", pc);
         }
     }
     munmap(cover, KCOV_COVER_SIZE * sizeof(unsigned long));
     close(fd);
 }
 
 int main(int argc, char *argv[])
 {
     char dev[IFNAMSIZ] = "tap0";
     unsigned char buf[2048], tap_mac[ETH_ALEN], set_mac[ETH_ALEN];
     struct in_addr dst_ip, src_ip;
     int fd, len;
     int drop_mode = 0;
     int mac_specified = 0;
     int use_coverage = 0;
     const char *coverfile = NULL;
     int kcov_fd = -1;
     unsigned long *kcov_cover = NULL;
 
     if (argc < 2) {
         fprintf(stderr,
             "Usage: %s [--coverage [--coverfile FILE]] <gtp_dst_ip> [tap_name] [--drop] [--mac XX:XX:XX:XX:XX:XX]\n"
             "\n"
             "  --coverage     - собрать kcov coverage в gtp.c (CONFIG_KCOV, debugfs)\n"
             "  --coverfile F  - записать raw PCs в F (формат syz-cover)\n"
             "  gtp_dst_ip - IP адрес GTP интерфейса (куда слать пакет)\n"
             "  tap_name   - имя TAP (по умолчанию tap0)\n"
             "  --drop     - отправить битый пакет (триггер 'GTP packet has been dropped')\n"
             "  --mac      - задать MAC TAP (unicast, напр. 02:11:22:33:44:55)\n"
             "\n"
             "Пример настройки GTP:\n"
             "  ip link add gtp0 type gtp role ggsn\n"
             "  ip addr add 192.168.60.1/24 dev gtp0\n"
             "  ip link set gtp0 up\n"
             "\n"
             "Включить netdev_dbg: echo 8 > /proc/sys/kernel/printk\n",
             argv[0]);
         return 1;
     }
 
     if (strcmp(argv[1], "--coverage") == 0) {
         use_coverage = 1;
         if (argc < 3) {
             fprintf(stderr, "Missing gtp_dst_ip after --coverage\n");
             return 1;
         }
         argv++;
         argc--;
     } else if (strcmp(argv[1], "--coverfile") == 0) {
         use_coverage = 1;
         if (argc < 4) {
             fprintf(stderr, "Usage: --coverfile FILE gtp_dst_ip\n");
             return 1;
         }
         coverfile = argv[2];
         argv += 2;
         argc -= 2;
     }
     if (inet_pton(AF_INET, argv[1], &dst_ip) != 1) {
         fprintf(stderr, "Invalid IP: %s\n", argv[1]);
         return 1;
     }
 
     /* src_ip - "внешний" хост в подсети (не наш адрес), иначе нужен accept_local */
     src_ip.s_addr = (dst_ip.s_addr & htonl(0xffffff00)) | htonl(100);
 
     for (int i = 2; i < argc; i++) {
         if (strcmp(argv[i], "--drop") == 0)
             drop_mode = 1;
         else if (strcmp(argv[i], "--coverage") == 0)
             use_coverage = 1;
         else if (strcmp(argv[i], "--coverfile") == 0 && i + 1 < argc) {
             coverfile = argv[++i];
             use_coverage = 1;
         }
         else if (strcmp(argv[i], "--mac") == 0 && i + 1 < argc) {
             if (parse_mac(argv[++i], set_mac) < 0) {
                 fprintf(stderr, "Invalid MAC: %s (use 02:11:22:33:44:55)\n", argv[i]);
                 return 1;
             }
             mac_specified = 1;
         } else if (argv[i][0] != '-')
             strncpy(dev, argv[i], IFNAMSIZ - 1);
     }
 
     fd = tap_alloc(dev, IFF_TAP | IFF_NO_PI);
     if (fd < 0)
         return 1;
 
     printf("TAP %s created\n", dev);
 
     if (if_up(dev) < 0) {
         fprintf(stderr, "Failed to bring interface up\n");
         close(fd);
         return 1;
     }
 
     /* Задать MAC TAP (по умолчанию 02:00:00:00:00:01) */
     if (set_if_mac(dev, mac_specified ? set_mac : default_tap_mac) < 0) {
         fprintf(stderr, "Failed to set MAC (using default)\n");
         /* не выходим - ядро назначит свой MAC */
     }
 
     /* Настроить маршрутизацию: IP на TAP, отключить rp_filter */
     setup_tap_routing(dev, dst_ip);
 
     /* MAC TAP для dst в Ethernet (или broadcast если не получилось) */
     if (get_if_mac(dev, tap_mac) < 0)
         memset(tap_mac, 0xff, ETH_ALEN); /* fallback: broadcast */
 
     if (drop_mode) {
         len = build_short_gtp_packet(buf, sizeof(buf), dst_ip, src_ip, tap_mac);
         printf("Sending SHORT (malformed) GTP packet -> triggers 'GTP packet has been dropped'\n");
     } else {
         len = build_gtp_packet(buf, sizeof(buf), dst_ip, src_ip, tap_mac);
         printf("Sending GTP1-U T-PDU with unknown TEID -> triggers 'pass up to the process'\n");
     }
 
     if (len < 0) {
         fprintf(stderr, "Failed to build packet\n");
         close(fd);
         return 1;
     }
 
     printf("Injecting %d bytes to %s (dst %s:%d)\n", len, dev, argv[1], GTP1U_PORT);
 
     print_ethernet_packet(buf, len);
 
     if (use_coverage && kcov_setup(&kcov_fd, &kcov_cover) < 0) {
         fprintf(stderr, "KCOV setup failed, continuing without coverage\n");
         use_coverage = 0;
     } else if (use_coverage) {
         printf("KCOV enabled (remote coverage in gtp.c)\n");
     }
 
     if (write(fd, buf, len) != len) {
         perror("write");
         if (use_coverage)
             kcov_teardown(kcov_fd, kcov_cover, coverfile);
         close(fd);
         return 1;
     }
 
     printf("Packet sent. Check dmesg for netdev_dbg output.\n");
     printf("  dmesg -w\n");
 
     if (use_coverage) {
         /* GTP обрабатывает пакет в softirq — даём время на доставку */
         usleep(50000);
         kcov_teardown(kcov_fd, kcov_cover, coverfile);
     }
 
     close(fd);
     return 0;
 }
 