#ifndef NETWORK_NATIVE_HPP
#define NETWORK_NATIVE_HPP

namespace network::native
{
#include <arch.hpp>

#if defined(OS_UNIX)

#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

	using socket_type = int;
	constexpr socket_type invalid_socket = -1;
	constexpr int socket_error_retval = -1;

#elif defined(OS_WIN)

#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>

	using socket_type = SOCKET;
	constexpr socket_type invalid_socket = INVALID_SOCKET;
	constexpr int socket_error_retval = SOCKET_ERROR;

#ifdef _WIN64
	using ssize_t = __int64;
#else
	using ssize_t = int;
#endif

#endif

using socket_addr = sockaddr;
using sock_addr_v4 = sockaddr_in;
using sock_addr_v6 = sockaddr_in6;
using socket_in_addr = in_addr;
using socket_addr_v6 = in6_addr;
using addr_info = addrinfo;

using socket_addr_storage = sockaddr_storage;
using linger = ::linger;

	enum address_family { none = AF_UNSPEC, v4 = AF_INET, v6 = AF_INET6 };

	namespace socket
	{
		enum type { stream = SOCK_STREAM, datagram = SOCK_DGRAM };
		enum proto { tcp = IPPROTO_TCP, udp = IPPROTO_UDP };
		constexpr socket_type invalid = ;
	}

	constexpr int max_listen_connections = NETWORK_MAX_CONNECTIONS;

	inline int error_code() noexcept { return NETWORK_LAST_ERROR; }

	inline CONSTEXPR uint16_t to_network_format(uint16_t value) { return TO_BIG_16(value); }
	inline CONSTEXPR uint16_t from_network_format(uint16_t value) { return TO_LITTLE_16(value); }

	inline CONSTEXPR uint32_t to_network_format(uint32_t value) { return TO_BIG_32(value); }
	inline CONSTEXPR uint32_t from_network_format(uint32_t value) { return TO_LITTLE_32(value); }

	inline int close(socket_type fd) { return ::NETWORK_CLOSE(fd); }
	inline int io_control(socket_type fd, uint64_t flag, IOCTL_ARG_TYPE* value) { return ::NETWORK_SOCKET_IOCTL(fd, flag, value); }
	inline int host_name(char* buffer, size_t size) { return ::gethostname(buffer, size); }
	inline hostent* resolve_host(const char* str, int address_family) { return ::HOST_RESOLVER(str, address_family); }

	constexpr inline int shutdown_flag_read() { return NETWORK_OPTION_SHUTDOWN_READ; }
	constexpr inline int shutdown_flag_write() { return NETWORK_OPTION_SHUTDOWN_WRITE; }
	constexpr inline int shutdown_flag_both() { return NETWORK_OPTION_SHUTDOWN_BOTH; }

	constexpr inline int option_boolean_flag_broadcast() { return NETWORK_OPTION_FLAG_BROADCAST; }
	constexpr inline int option_boolean_flag_reuse_address() { return NETWORK_OPTION_FLAG_REUSE_ADDRESS; }
	constexpr inline int option_boolean_flag_reuse_port() { return NETWORK_OPTION_FLAG_REUSE_PORT; }
	constexpr inline int option_boolean_flag_debug() { return NETWORK_OPTION_FLAG_DEBUG; }
	constexpr inline int option_boolean_flag_oob_inline() { return NETWORK_OPTION_FLAG_OOB_INLINE; }
	constexpr inline int option_boolean_flag_do_not_route() { return NETWORK_OPTION_FLAG_DO_NOT_ROUTE; }
	constexpr inline int option_boolean_flag_non_block() { return NETWORK_OPTION_FLAG_NON_BLOCK; }
	constexpr inline int option_boolean_flag_keep_alive() { return NETWORK_OPTION_FLAG_KEEP_ALIVE; }

	constexpr inline int option_value_flag_linger() { return NETWORK_OPTION_FLAG_LINGER; }
	constexpr inline int option_value_flag_write_buffer() { return NETWORK_OPTION_FLAG_WRITE_BUFFER; }
	constexpr inline int option_value_flag_read_buffer() { return NETWORK_OPTION_FLAG_READ_BUFFER; }

	constexpr inline int option_timeout_flag_read() { return NETWORK_OPTION_FLAG_READ_TIMEOUT; }
	constexpr inline int option_timeout_flag_write() { return NETWORK_OPTION_FLAG_WRITE_TIMEOUT; }

	constexpr inline int option_read_flag_non_block() { return NETWORK_READ_FLAG_NON_BLOCK; }
	constexpr inline int option_read_flag_peek() { return NETWORK_READ_FLAG_PEEK; }
	constexpr inline int option_read_flag_wait_all() { return NETWORK_READ_FLAG_WAIT_ALL; }
	constexpr inline int option_read_flag_no_signal() { return NETWORK_READ_FLAG_NO_SIGNAL; }

	constexpr inline int option_write_flag_confirm() { return NETWORK_WRITE_FLAG_CONFIRM; }
	constexpr inline int option_write_flag_do_not_route() { return NETWORK_WRITE_FLAG_DO_NOT_ROUTE; }
	constexpr inline int option_write_flag_do_not_wait() { return NETWORK_WRITE_FLAG_DO_NOT_WAIT; }
	constexpr inline int option_write_flag_eor() { return NETWORK_WRITE_FLAG_EOR; }
	constexpr inline int option_write_flag_mor() { return NETWORK_WRITE_FLAG_MORE; }
	constexpr inline int option_write_flag_no_signal() { return NETWORK_WRITE_FLAG_NO_SIGNAL; }
	constexpr inline int option_write_flag_oob() { return NETWORK_WRITE_FLAG_OOB; }

	inline bool is_address_loopback(const unsigned char* data) { return IN6_IS_ADDR_LOOPBACK((IN6_ADDR*)data); }
	inline bool is_address_unspecified(const unsigned char* data) { return IN6_IS_ADDR_UNSPECIFIED((IN6_ADDR*)data); }
	inline bool is_address_link_local(const unsigned char* data) { return IN6_IS_ADDR_LINKLOCAL((IN6_ADDR*)data); }
	inline bool is_address_site_local(const unsigned char* data) { return IN6_IS_ADDR_SITELOCAL((IN6_ADDR*)data); }
	inline bool is_address_v4_mapped(const unsigned char* data) { return IN6_IS_ADDR_V4MAPPED((IN6_ADDR*)data); }
	inline bool is_address_multi_cast(const unsigned char* data) { return IN6_IS_ADDR_MULTICAST((IN6_ADDR*)data); }
	inline bool is_address_mc_global(const unsigned char* data) { return IN6_IS_ADDR_MC_GLOBAL((IN6_ADDR*)data); }
	inline bool is_address_mc_local(const unsigned char* data) { return IN6_IS_ADDR_MC_LINKLOCAL((IN6_ADDR*)data); }
	inline bool is_address_mc_node_local(const unsigned char* data) { return IN6_IS_ADDR_MC_NODELOCAL((IN6_ADDR*)data); }
	inline bool is_address_mc_org_local(const unsigned char* data) { return IN6_IS_ADDR_MC_ORGLOCAL((IN6_ADDR*)data); }
	inline bool is_address_mc_site_local(const unsigned char* data) { return IN6_IS_ADDR_MC_SITELOCAL((IN6_ADDR*)data); }

	inline bool is_address_equal(const unsigned char* l, const unsigned char* r)
	{
		return IN6_ARE_ADDR_EQUAL(reinterpret_cast<const IN6_ADDR*>(l), reinterpret_cast<const IN6_ADDR*>(r));
	}

	inline int set_socket_option(socket_type descriptor, int option, int value)
	{
		int out = 0;
		if(option == NETWORK_OPTION_FLAG_NON_BLOCK)
		{
#if defined(OS_Windows)
			int iSize, iValOld, iValNew = 1;
			iSize = sizeof(iValOld);
			out	= getsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, (char*)&iValOld, &iSize);

			if(out == -1)
				return out;

			out = setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, (char*)&iValNew, iSize);
#elif defined(OS_Linux)
			out = fcntl(descriptor, F_GETFL, 0);

			if(out == -1)
				return out;

			if(value)
				out |= O_NONBLOCK;
			else
				out &= ~O_NONBLOCK;

			out = fcntl(descriptor, F_SETFL, out);
#endif
			if(out == -1)
				return out;
		}
		else
			return ::setsockopt(descriptor, SOL_SOCKET, option, (char*)&value, sizeof(int));
		return 0;
	}
} // namespace network::native

#endif // NETWORK_CONFIG_HPP
