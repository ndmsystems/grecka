/* Copyright (c) 2017 NDM Systems, Inc. http://www.ndmsystems.com/

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <linux/if.h>
#include <linux/ip.h>
#include <linux/sockios.h>
#include <linux/if_ether.h>
#include <linux/if_tunnel.h>
#include <linux/filter.h>

#if !defined(IP_DF)
#define IP_DF						0x4000
#endif

/* libndm headers */
#include <ndm/log.h>
#include <ndm/ip_sockaddr.h>
#include <ndm/ip_checksum.h>
#include <ndm/time.h>
#include <ndm/sys.h>
#include <ndm/feedback.h>
#include <ndm/attr.h>

#define POLL_TIME					950 // 1 sec
#define READ_RETRY_MS				100 // ms
#define READ_RETRY_TIMES			5 //

#define GRE_KA_FLAGS				0
#define GRE_KA_VERSION				0
#define GRE_KA_PROTOCOL				0

struct gre_hdr
{
	uint8_t flags;
	uint8_t version;
	uint16_t protocol;
} NDM_ATTR_PACKED;

struct keepalive_packet
{
	struct iphdr outer_ip_hdr;
	struct gre_hdr outer_gre_hdr;
	struct iphdr inner_ip_hdr;
	struct gre_hdr inner_gre_hdr;
} NDM_ATTR_PACKED;

/* external configuration */
static bool handle_requests = false;
static bool send_probes = false;
static bool debug = false;
static unsigned long interval = 5;
static unsigned long count = 3;
static const char *interface_id = "";
static const char *feedback = "";
static struct ndm_ip_sockaddr_t local_address;
static struct ndm_ip_sockaddr_t remote_address;

/* internal state */
static int fd_request = -1;
static int fd_reply = -1;
static int fd_send = -1;
static struct pollfd pfds[2];
static struct timespec last_send;
static struct timespec last_recv;
static bool is_down = false;

/*
 * gre_ka_reply_filter_code as disassembled
 */
/*
ld len
jne #24, drop
ldb [0]
jne #0x45, drop
ldb [3]
jne #24, drop
ldb [9]
jne #47, drop
ldh [22]
jne #0, drop
ret #-1
drop: ret #0
*/

static struct sock_filter gre_ka_reply_filter_code[] = {
	{ 0x80,  0,  0, 0000000000 },
	{ 0x15,  0,  9, 0x00000018 },
	{ 0x30,  0,  0, 0000000000 },
	{ 0x15,  0,  7, 0x00000045 },
	{ 0x30,  0,  0, 0x00000003 },
	{ 0x15,  0,  5, 0x00000018 },
	{ 0x30,  0,  0, 0x00000009 },
	{ 0x15,  0,  3, 0x0000002f },
	{ 0x28,  0,  0, 0x00000016 },
	{ 0x15,  0,  1, 0000000000 },
	{ 0x06,  0,  0, 0xffffffff },
	{ 0x06,  0,  0, 0000000000 },
};

/*
 * gre_ka_request_filter_code as disassembled
 */

/*
ld len
jne #48, drop
ldb [0]
jne #0x45, drop
ldb [3]
jne #48, drop
ldb [9]
jne #47, drop
ld [12]
st M[0]
ld [16]
st M[1]
ldh [20]
jne #0,drop
ldh [22]
jne #0x0800, drop
ldb [24]
jne #0x45, drop
ldb [27]
jne #24, drop
ldb [33]
jne #47, drop
ld [36]
ldx M[1]
xor x
jne #0, drop
ld [40]
ldx M[0]
xor x
jne #0, drop
ldh [44]
jne #0, drop
ldh [46]
jne #0, drop
ret #-1
drop: ret #0
*/

static struct sock_filter gre_ka_request_filter_code[] = {
	{ 0x80,  0,  0, 0000000000 },
	{ 0x15,  0, 33, 0x00000030 },
	{ 0x30,  0,  0, 0000000000 },
	{ 0x15,  0, 31, 0x00000045 },
	{ 0x30,  0,  0, 0x00000003 },
	{ 0x15,  0, 29, 0x00000030 },
	{ 0x30,  0,  0, 0x00000009 },
	{ 0x15,  0, 27, 0x0000002f },
	{ 0x20,  0,  0, 0x0000000c },
	{ 0x02,  0,  0, 0000000000 },
	{ 0x20,  0,  0, 0x00000010 },
	{ 0x02,  0,  0, 0x00000001 },
	{ 0x28,  0,  0, 0x00000014 },
	{ 0x15,  0, 21, 0000000000 },
	{ 0x28,  0,  0, 0x00000016 },
	{ 0x15,  0, 19, 0x00000800 },
	{ 0x30,  0,  0, 0x00000018 },
	{ 0x15,  0, 17, 0x00000045 },
	{ 0x30,  0,  0, 0x0000001b },
	{ 0x15,  0, 15, 0x00000018 },
	{ 0x30,  0,  0, 0x00000021 },
	{ 0x15,  0, 13, 0x0000002f },
	{ 0x20,  0,  0, 0x00000024 },
	{ 0x61,  0,  0, 0x00000001 },
	{ 0xac,  0,  0, 0000000000 },
	{ 0x15,  0,  9, 0000000000 },
	{ 0x20,  0,  0, 0x00000028 },
	{ 0x61,  0,  0, 0000000000 },
	{ 0xac,  0,  0, 0000000000 },
	{ 0x15,  0,  5, 0000000000 },
	{ 0x28,  0,  0, 0x0000002c },
	{ 0x15,  0,  3, 0000000000 },
	{ 0x28,  0,  0, 0x0000002e },
	{ 0x15,  0,  1, 0000000000 },
	{ 0x06,  0,  0, 0xffffffff },
	{ 0x06,  0,  0, 0000000000 },
};

/*
 * gre_ka_empty_filter as disassembled
 */

/*
ret #0
*/

static struct sock_filter gre_ka_empty_filter[] = {
	{ 0x06,  0,  0, 0000000000 },
};

static bool grecka_attach_bpf(int fd, struct sock_fprog *bpf)
{
	if (!bpf) {
		NDM_LOG_CRITICAL("null value as filter");

		return false;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, bpf, sizeof(*bpf)) < 0) {
		const int err = errno;

		NDM_LOG_ERROR("unable to attach BPF socket filter: %s", strerror(err));

		return false;
	}

	return true;
}

static bool grecka_set_nonblock(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1) {
		const int err = errno;

		NDM_LOG_ERROR("unable to get socket flags: %s", strerror(err));

		return false;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		const int err = errno;

		NDM_LOG_ERROR("unable to set socket flags: %s", strerror(err));

		return false;
	}

	return true;
}

static bool grecka_nonblock_read(
		int fd, void *p, size_t buf_size, size_t *bytes_read)
{
	const ssize_t n = recv(fd, p, buf_size, 0);

	*bytes_read = 0;

	if (n < 0) {
		const int error = errno;

		if (error == EINTR || error == EAGAIN || error == EWOULDBLOCK) {
			return false;

		} else {
			NDM_LOG_ERROR("unable receive packet: %s", strerror(error));

			return false;
		}
	} else {
		*bytes_read = (size_t)n;
	}

	return true;
}

static bool grecka_nonblock_write(
		int fd, const void *p, size_t buf_size, size_t *bytes_written,
		const struct ndm_ip_sockaddr_t *psa)
{
	size_t bwrite = 0;
	unsigned long retries = 0;

	*bytes_written = 0;

	while (!ndm_sys_is_interrupted() && bwrite == 0) {
		struct sockaddr_in sa;
		ssize_t n;

		memset(&sa, 0, sizeof(sa));
		sa.sin_family = PF_INET;
		sa.sin_addr = psa->un.in.sin_addr;

		n = sendto(fd, p, buf_size, 0, (struct sockaddr*)&sa, sizeof(sa)); 

		if (n < 0) {
			const int error = errno;

			if (error == EINTR || error == EAGAIN || error == EWOULDBLOCK) {
				if (++retries <= READ_RETRY_TIMES) {
					struct timespec ts;

					ts.tv_sec = 0;
					ts.tv_nsec = READ_RETRY_MS * 1000;

					nanosleep(&ts, NULL);
				} else {
					return false;
				}
			} else {
				NDM_LOG_ERROR("unable send packet: %s", strerror(error));

				return false;
			}
		} else {
			bwrite = (size_t)n;
		}
	}

	*bytes_written = bwrite;

	return true;
}

static void grecka_handle_ka_reply()
{
	struct keepalive_packet p;
	size_t bytes_read = 0;

	if (fd_reply == -1) {
		NDM_LOG_ERROR("reply receiving socket is invalid");

		return;
	}

	if (!grecka_nonblock_read(fd_reply, &p, sizeof(p), &bytes_read) ||
			bytes_read != (sizeof(struct iphdr) + sizeof(struct gre_hdr))) {

		if (bytes_read == 0) {
			return;
		}

		NDM_LOG_ERROR("(>) unable to receive keepalive reply: %d", bytes_read);

		return;
	}

	if (p.outer_ip_hdr.version == IPVERSION &&
		p.outer_ip_hdr.ihl == 5 &&
		p.outer_ip_hdr.protocol == IPPROTO_GRE &&
		p.outer_ip_hdr.saddr == remote_address.un.in.sin_addr.s_addr &&
		p.outer_ip_hdr.daddr == local_address.un.in.sin_addr.s_addr &&
		p.outer_gre_hdr.protocol == GRE_KA_PROTOCOL) {

		ndm_time_get_monotonic(&last_recv);

		if (debug) {
			char buf[NDM_IP_SOCKADDR_LEN];

			NDM_LOG_INFO("(>) receive GRE keepalive reply packet from %s",
				ndm_ip_sockaddr_ntop(&remote_address, buf, NDM_IP_SOCKADDR_LEN));
		}
	}
}

static void grecka_handle_ka_request()
{
	struct keepalive_packet p;
	size_t bytes_read = 0;

	if (fd_request == -1) {
		NDM_LOG_ERROR("request receiving socket is invalid");

		return;
	}

	if (!grecka_nonblock_read(fd_request, &p, sizeof(p), &bytes_read) ||
			bytes_read != (sizeof(p))) {

		if (bytes_read == 0) {
			return;
		}

		NDM_LOG_ERROR("(<) unable to receive keepalive request: %d",
			bytes_read);

		return;
	}

	if (p.outer_ip_hdr.version == IPVERSION &&
		p.outer_ip_hdr.ihl == 5 &&
		p.outer_ip_hdr.protocol == IPPROTO_GRE &&
		p.outer_ip_hdr.saddr == remote_address.un.in.sin_addr.s_addr &&
		p.outer_ip_hdr.daddr == local_address.un.in.sin_addr.s_addr &&
		p.outer_gre_hdr.protocol == htons(ETH_P_IP) &&
		p.inner_ip_hdr.version == IPVERSION &&
		p.inner_ip_hdr.ihl == 5 &&
		p.inner_ip_hdr.protocol == IPPROTO_GRE &&
		p.inner_ip_hdr.saddr == local_address.un.in.sin_addr.s_addr &&
		p.inner_ip_hdr.daddr == remote_address.un.in.sin_addr.s_addr &&
		p.inner_gre_hdr.protocol == GRE_KA_PROTOCOL) {

		const size_t reply_len = sizeof(struct iphdr) + sizeof(struct gre_hdr);
		size_t bytes_written = 0;

		if (debug) {
			char buf[NDM_IP_SOCKADDR_LEN];

			NDM_LOG_INFO("(<) receive GRE keepalive request packet from %s",
				ndm_ip_sockaddr_ntop(&remote_address, buf, NDM_IP_SOCKADDR_LEN));
		}

		if (fd_send == -1) {
			NDM_LOG_ERROR("sending socket is invalid");

			return;
		}

		if (!grecka_nonblock_write(fd_send,
					&(p.inner_ip_hdr), reply_len,
					&bytes_written, &remote_address) ||
				bytes_written != reply_len) {
			NDM_LOG_ERROR("unable to send reply to GRE keepalive request packet: %u",
				bytes_written);
		} else
		if (debug) {
			char buf[NDM_IP_SOCKADDR_LEN];

			NDM_LOG_INFO("(<) sent GRE keepalive request response to %s",
				ndm_ip_sockaddr_ntop(&remote_address, buf, NDM_IP_SOCKADDR_LEN));
		}
	} else {
		char buf[NDM_IP_SOCKADDR_LEN];

		NDM_LOG_ERROR("(<) receive invalid GRE keepalive request packet from %s",
			ndm_ip_sockaddr_ntop(&remote_address, buf, NDM_IP_SOCKADDR_LEN));
	}
}

static void grecka_send_keepalive()
{
	struct keepalive_packet p;
	size_t bytes_written = 0;

	if (fd_send == -1) {
		NDM_LOG_ERROR("sending socket is invalid");

		return;
	}

	memset(&p, 0, sizeof(p));

	p.outer_ip_hdr.ihl = 5;
	p.outer_ip_hdr.version = IPVERSION;
	p.outer_ip_hdr.ttl = IPDEFTTL;
	p.outer_ip_hdr.protocol = IPPROTO_GRE;
	p.outer_ip_hdr.daddr = remote_address.un.in.sin_addr.s_addr;
	p.outer_ip_hdr.saddr = local_address.un.in.sin_addr.s_addr;
	p.outer_ip_hdr.tot_len = htons(sizeof(p));
	p.outer_ip_hdr.frag_off = htons(IP_DF);

	p.outer_gre_hdr.flags = GRE_KA_FLAGS;
	p.outer_gre_hdr.version = GRE_KA_VERSION;
	p.outer_gre_hdr.protocol = htons(ETH_P_IP);

	p.inner_ip_hdr.ihl = 5;
	p.inner_ip_hdr.version = IPVERSION;
	p.inner_ip_hdr.ttl = IPDEFTTL;
	p.inner_ip_hdr.protocol = IPPROTO_GRE;
	p.inner_ip_hdr.saddr = remote_address.un.in.sin_addr.s_addr;
	p.inner_ip_hdr.daddr = local_address.un.in.sin_addr.s_addr;
	p.inner_ip_hdr.frag_off = htons(IP_DF);
	p.inner_ip_hdr.tot_len = htons(
		sizeof(struct iphdr) + sizeof(struct gre_hdr));

	p.inner_ip_hdr.check = ndm_ip_checksum(&(p.inner_ip_hdr), sizeof(struct iphdr));

	p.inner_gre_hdr.flags = GRE_KA_FLAGS;
	p.inner_gre_hdr.version = GRE_KA_VERSION;
	p.inner_gre_hdr.protocol = GRE_KA_PROTOCOL;

	if (!grecka_nonblock_write(fd_send, &p, sizeof(p),
				&bytes_written, &remote_address) ||
			bytes_written != sizeof(p)) {
		NDM_LOG_ERROR("(>) unable to send GRE keepalive packet: %u",
			bytes_written);
	} else
	if (debug) {
		char buf[NDM_IP_SOCKADDR_LEN];
		struct timespec ts;

		NDM_LOG_INFO("(>) sent GRE keepalive request to %s",
			ndm_ip_sockaddr_ntop(&remote_address, buf, NDM_IP_SOCKADDR_LEN));

		ndm_time_get_monotonic(&ts);
		ndm_time_sub(&ts, &last_recv);

		NDM_LOG_INFO("(>) last GRE keepalive reply was %ld s ago", ts.tv_sec);
	}
}

static void grecka_event_loop()
{
	while (!ndm_sys_is_interrupted()) {
		int ret = poll(pfds, NDM_ARRAY_SIZE(pfds), POLL_TIME);
		bool has_error = false;

		if (ndm_sys_is_interrupted())
			return;

		if (ret < 0) {
			const int err = errno;

			if (err == EINTR || err == EAGAIN) {
				return;
			}

			NDM_LOG_ERROR("poll error: %s", strerror(err));

			ndm_sys_sleep_msec(NDM_SYS_SLEEP_GRANULARITY_MSEC);

			goto reinit;
		}

		if (send_probes && !is_down) {
			struct timespec ts = last_send;
			struct timespec ts_rcv = last_recv;
			struct timespec ts_now;

			ndm_time_get_monotonic(&ts_now);
			ndm_time_add_sec(&ts, interval);

			if (ndm_time_greater_or_equal(&ts_now, &ts)) {
				grecka_send_keepalive();
				last_send = ts_now;
			}

			ndm_time_add_sec(&ts_rcv, interval * count);

			if (ndm_time_greater_or_equal(&ts_now, &ts_rcv)) {
				const char *args[] = {
					feedback,
					interface_id,
					"timeout",
					NULL
				};

				if (!ndm_feedback(
						NDM_FEEDBACK_TIMEOUT_MSEC,
						args,
						"SRC=greka")) {
					NDM_LOG_ERROR("unable to send feedback");
				} else {
					is_down = true;
				}
			}
		}

		if (ret == 0) {
			continue;
		}

		for (unsigned long i = 0; i < NDM_ARRAY_SIZE(pfds); ++i) {
			if ((pfds[i].revents & POLLERR) || (pfds[i].revents & POLLHUP)) {
				has_error = true;
			}

			if (pfds[i].fd != -1 && (pfds[i].revents & POLLNVAL)) {
				has_error = true;
			}
		}

		if (has_error) {
			NDM_LOG_ERROR("socket was unexpectedly closed");

			return;
		}

		for (unsigned long i = 0; i < NDM_ARRAY_SIZE(pfds); ++i) {
			if ((pfds[i].revents & POLLIN) && pfds[i].fd == fd_request) {
				grecka_handle_ka_request();
			}

			if ((pfds[i].revents & POLLIN) && pfds[i].fd == fd_reply) {
				grecka_handle_ka_reply();
			}
		}

reinit:
		pfds[0].fd = fd_request;
		pfds[0].events = POLLIN;
		pfds[0].revents = 0;
		pfds[1].fd = fd_reply;
		pfds[1].events = POLLIN;
		pfds[1].revents = 0;
	}
}

static void grecka_main(void)
{
	int opt;

	fd_send = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);

	if (fd_send == -1) {
		const int err = errno;

		NDM_LOG_ERROR("unable to open send socket: %s", strerror(err));

		goto cleanup;
	}

	opt = 1; /* enable */

	if (setsockopt(fd_send, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
		const int err = errno;

		NDM_LOG_ERROR("unable to set IP_HDRINCL on send socket: %s",
			strerror(err));

		goto cleanup;
	}

	if (!grecka_set_nonblock(fd_send)) {
		goto cleanup;
	}

	/* Drop everything that income, socket only for sending */
	{
		struct sock_fprog bpf = {
			.len = NDM_ARRAY_SIZE(gre_ka_empty_filter),
			.filter = gre_ka_empty_filter,
		};

		if (!grecka_attach_bpf(fd_send, &bpf)) {
			goto cleanup;
		}
	}

	if (handle_requests) {
		fd_request = socket(PF_INET, SOCK_RAW, IPPROTO_GRE);

		if (fd_request == -1) {
			const int err = errno;

			NDM_LOG_ERROR("unable to open keepalive request handling socket: %s",
				strerror(err));

			goto cleanup;
		}

		if (!grecka_set_nonblock(fd_request)) {
			goto cleanup;
		}

		{
			struct sock_fprog bpf = {
				.len = NDM_ARRAY_SIZE(gre_ka_request_filter_code),
				.filter = gre_ka_request_filter_code,
			};

			if (!grecka_attach_bpf(fd_request, &bpf)) {
				goto cleanup;
			}
		}
	}

	if (send_probes) {
		fd_reply = socket(PF_INET, SOCK_RAW, IPPROTO_GRE);

		if (fd_reply == -1) {
			const int err = errno;

			NDM_LOG_ERROR("unable to open keepalive reply handling socket: %s",
				strerror(err));

			goto cleanup;
		}

		if (!grecka_set_nonblock(fd_reply)) {
			goto cleanup;
		}

		{
			struct sock_fprog bpf = {
				.len = NDM_ARRAY_SIZE(gre_ka_reply_filter_code),
				.filter = gre_ka_reply_filter_code,
			};

			if (!grecka_attach_bpf(fd_reply, &bpf)) {
				goto cleanup;
			}
		}
	}

	ndm_time_get_monotonic(&last_send);
	ndm_time_get_monotonic(&last_recv);

	memset(&pfds, 0, sizeof(pfds));

	pfds[0].fd = fd_request;
	pfds[0].events = POLLIN;
	pfds[1].fd = fd_reply;
	pfds[1].events = POLLIN;

	grecka_event_loop();

cleanup:
	if (fd_reply != -1)
		close(fd_reply);

	if (fd_request != -1)
		close(fd_request);

	if (fd_send != -1)
		close(fd_send);
}

int main(int argc, char *argv[])
{
	int ret_code = EXIT_FAILURE;
	const char *const ident = ndm_log_get_ident(argv);
	int c;

	if (!ndm_log_init(ident, NULL, false, true)) {
		fprintf(stderr, "%s: failed to initialize a log\n", ident);

		return ret_code;
	}

	local_address = NDM_IP_SOCKADDR_ANY;
	remote_address = NDM_IP_SOCKADDR_ANY;

	for (;;) {
		c = getopt(argc, argv, "i:c:raI:L:R:dF:");

		if (c < 0)
			break;

		switch (c) {

		case 'd':
			debug = true;
			break;

		case 'r':
			handle_requests = true;
			break;

		case 'a':
			send_probes = true;
			break;

		case 'i':
			if (!ndm_int_parse_ulong(optarg, &(interval))) {
				NDM_LOG_ERROR("invalid interval value: \"%s\"",
							  optarg);
				return ret_code;
			}
			break;

		case 'c':
			if (!ndm_int_parse_ulong(optarg, &(count))) {
				NDM_LOG_ERROR("invalid count value: \"%s\"",
							  optarg);
				return ret_code;
			}
			break;

		case 'I':
			interface_id = optarg;
			break;

		case 'F':
			feedback = optarg;
			break;

		case 'L':
			if (!ndm_ip_sockaddr_pton(optarg, &local_address)) {
				NDM_LOG_ERROR("invalid local source value: \"%s\"",
							  optarg);
				return ret_code;
			}
			break;

		case 'R':
			if (!ndm_ip_sockaddr_pton(optarg, &remote_address)) {
				NDM_LOG_ERROR("invalid remote destination value: \"%s\"",
							  optarg);
				return ret_code;
			}
			break;

		default:
			NDM_LOG_ERROR("unknown option \"%c\"", (char) optopt);

			return ret_code;
		}
	}

	if (!ndm_log_init(ident, interface_id, false, true)) {
		fprintf(stderr, "%s: failed to reinitialize log\n", ident);

		return ret_code;
	}

	if (!ndm_sys_init()) {
		NDM_LOG_ERROR("unable to init libndm");

		return ret_code;
	}

	if (!ndm_sys_set_default_signals()) {
		NDM_LOG_ERROR("unable set signal handlers");

		return ret_code;
	}

	NDM_LOG_INFO("GRE keepalive daemon started");

	if (send_probes) {
		NDM_LOG_INFO("send active requests enabled");
	}

	if (handle_requests) {
		NDM_LOG_INFO("replies to external requests enabled");
	}

	grecka_main();

	NDM_LOG_INFO("GRE keepalive daemon stopped");

	return EXIT_SUCCESS;
}
