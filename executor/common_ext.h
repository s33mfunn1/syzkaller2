// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <net/if.h>

// This file is included into executor and C reproducers and can be used to add
// non-mainline pseudo-syscalls and to provide some other extension points
// w/o changing any other files. See common_ext_example.h for an example implementation.

// Pseudo-syscalls defined in this file should start with syz_ext_.

// This file can also define SYZ_HAVE_SETUP_EXT to 1 and provide
// void setup_ext() function that will be called during VM setup.

// This file can also define SYZ_HAVE_SETUP_EXT_TEST to 1 and provide
// void setup_ext_test() function that will be called during setup of each test process.

#define SYZ_HAVE_SETUP_EXT_TEST 1
static void setup_ext_test()
{
	debug("setup_ext_test: starting GTP setup\n");
	// Check syz_tun presence before GTP setup
	unsigned int ifindex_before = if_nametoindex("syz_tun");
	debug("setup_ext_test: syz_tun before gtp0: %s (ifindex=%u)\n",
	      ifindex_before ? "exists" : "MISSING", ifindex_before);

	const char* ip = "/usr/sbin/ip";
	if (access("/usr/sbin/ip", X_OK) == 0)
		;
	else if (access("/sbin/ip", X_OK) == 0)
		ip = "/sbin/ip";
	else if (access("/bin/ip", X_OK) == 0)
		ip = "/bin/ip";
	else if (access("/usr/bin/ip", X_OK) == 0)
		ip = "/usr/bin/ip";
	else
		debug("setup_ext_test: ip not found at /usr/sbin, /sbin, /bin or /usr/bin\n");
	debug("setup_ext_test: using ip=%s\n", ip);
	// GTP setup per gtp_tap_inject.c: gtp0 + IP 192.168.60.1 for syz_emit -> gtp.c
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "%s link add gtp0 type gtp role ggsn", ip);
	int r1 = system(cmd);
	snprintf(cmd, sizeof(cmd), "%s addr add 192.168.60.1/24 dev gtp0", ip);
	int r2 = system(cmd);
	snprintf(cmd, sizeof(cmd), "%s link set gtp0 up", ip);
	int r3 = system(cmd);
	debug("setup_ext_test: ip link add=%d ip addr add=%d ip link set=%d\n", r1, r2, r3);

	// Check syz_tun presence after GTP setup
	unsigned int ifindex_after = if_nametoindex("syz_tun");
	debug("setup_ext_test: syz_tun after gtp0: %s (ifindex=%u)\n",
	      ifindex_after ? "exists" : "MISSING", ifindex_after);
	if (ifindex_before && !ifindex_after)
		debug("setup_ext_test: WARNING syz_tun disappeared after adding gtp0!\n");

	// rp_filter=0: allow packets from TUN to gtp0 (reverse path check)
	// int _ = system("echo 0 > /proc/sys/net/ipv4/conf/syz_tun/rp_filter 2>/dev/null");
	// accept_local=1: accept packets with src=our address
	// _ = system("echo 1 > /proc/sys/net/ipv4/conf/syz_tun/accept_local 2>/dev/null");
	// IPv4 only: disable IPv6 on TUN
	// _ = system("echo 1 > /proc/sys/net/ipv6/conf/syz_tun/disable_ipv6 2>/dev/null");
	// (void)_;
}
