// MIT License
//
// Copyright (c) 2016-2017 Simon Ninon <simon.ninon@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "tcp_server.hpp"
#include "error.hpp"
#include "logger.hpp"

#ifdef _WIN32
#ifdef __GNUC__
#   include <Ws2tcpip.h>	   // Mingw / gcc on windows
#define _WIN32_WINNT 0x0501
#include <winsock2.h>
#   include <Ws2tcpip.h>
extern "C" {
	WINSOCK_API_LINKAGE  INT WSAAPI inet_pton(INT Family, PCSTR pszAddrString, PVOID pAddrBuf);
	WINSOCK_API_LINKAGE  PCSTR WSAAPI inet_ntop(INT  Family, PVOID pAddr, PSTR pStringBuf, size_t StringBufSize);
}

#else
  // Windows...
#include <winsock2.h>
#include <In6addr.h>
#include <Ws2tcpip.h>
#endif
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#endif /* _WIN32 */

#ifndef SOCKET_ERROR
	#define SOCKET_ERROR -1
#endif /* SOCKET_ERROR */

#if _WIN32
	#define __TACOPIE_LENGTH(size) static_cast<int>(size) // for Windows, convert buffer size to `int`
	#pragma warning(disable : 4996)                       // for Windows, `inet_ntoa` is deprecated as it does not support IPv6
#else
	#define __TACOPIE_LENGTH(size) size // for Unix, keep buffer size as `size_t`
#endif                              /* _WIN32 */

namespace tacopie
{

	tcp_socket::tcp_socket()
		: m_fd(__TACOPIE_INVALID_FD)
		, m_host("")
		, m_port(0)
		, m_type(type::UNKNOWN)
	{
		__TACOPIE_LOG(debug, "create tcp_socket");
	}

	// custom ctor
	// build socket from existing file descriptor
	tcp_socket::tcp_socket(fd_t fd, const std::string& host, std::uint32_t port, type t)
		: m_fd(fd)
		, m_host(host)
		, m_port(port)
		, m_type(t)
	{
		__TACOPIE_LOG(debug, "create tcp_socket");
	}

	// Move constructor
	tcp_socket::tcp_socket(tcp_socket&& socket)
		: m_fd(std::move(socket.m_fd))
		, m_host(socket.m_host)
		, m_port(socket.m_port)
		, m_type(socket.m_type)
	{
		socket.m_fd = __TACOPIE_INVALID_FD;
		socket.m_type = type::UNKNOWN;

		__TACOPIE_LOG(debug, "moved tcp_socket");
	}

	// client socket operations
	std::vector<char> tcp_socket::recv(std::size_t size_to_read)
	{
		create_socket_if_necessary();
		check_or_set_type(type::CLIENT);

		std::vector<char> data(size_to_read, 0);

		ssize_t rd_size = ::recv(m_fd, const_cast<char*>(data.data()), __TACOPIE_LENGTH(size_to_read), 0);

		if (rd_size == SOCKET_ERROR) { __TACOPIE_THROW(error, "recv() failure"); }
		if (rd_size == 0)            { __TACOPIE_THROW(warn, "nothing to read, socket has been closed by remote host"); }

		data.resize(rd_size);

		return data;
	}

	std::size_t tcp_socket::send(const std::vector<char>& data, std::size_t size_to_write)
	{
		create_socket_if_necessary();
		check_or_set_type(type::CLIENT);

		ssize_t wr_size = ::send(m_fd, data.data(), __TACOPIE_LENGTH(size_to_write), 0);

		if (wr_size == SOCKET_ERROR) { __TACOPIE_THROW(error, "send() failure"); }

		return wr_size;
	}

	void tcp_socket::listen(std::size_t max_connection_queue) 
	{
		create_socket_if_necessary();
		check_or_set_type(type::SERVER);

		if (::listen(m_fd, __TACOPIE_LENGTH(max_connection_queue)) == SOCKET_ERROR) { __TACOPIE_THROW(debug, "listen() failure"); }
	}

	tcp_socket tcp_socket::accept()
	{
		create_socket_if_necessary();
		check_or_set_type(type::SERVER);

		struct sockaddr_storage ss;
		socklen_t addrlen = sizeof(ss);

		fd_t client_fd = ::accept(m_fd, reinterpret_cast<struct sockaddr*>(&ss), &addrlen);

		if (client_fd == __TACOPIE_INVALID_FD) { __TACOPIE_THROW(error, "accept() failure"); }

		// now determine host and port based on socket type
		std::string saddr;
		std::uint32_t port;

		// ipv6
		if (ss.ss_family == AF_INET6)
		{
			struct sockaddr_in6* addr6 = reinterpret_cast<struct sockaddr_in6*>(&ss);
			char buf[INET6_ADDRSTRLEN] = {};
			const char* addr = ::inet_ntop(ss.ss_family, &addr6->sin6_addr, buf, INET6_ADDRSTRLEN);

			if (addr) 
			{
				saddr = std::string("[") + addr + "]";
			}

			port = ntohs(addr6->sin6_port);
		}
		// ipv4
		else
		{
			struct sockaddr_in* addr4 = reinterpret_cast<struct sockaddr_in*>(&ss);
			char buf[INET_ADDRSTRLEN] = {};
			const char* addr = ::inet_ntop(ss.ss_family, &addr4->sin_addr, buf, INET_ADDRSTRLEN);

			if (addr)
			{
				saddr = addr;
			}

			port = ntohs(addr4->sin_port);
		}
		return { client_fd, saddr, port, type::CLIENT };
	}

	//
	// check whether the current socket has an appropriate type for that kind of operation
	// if current type is UNKNOWN, update internal type with given type
	//

	void tcp_socket::check_or_set_type(type t) 
	{
		if (m_type != type::UNKNOWN && m_type != t) { __TACOPIE_THROW(error, "trying to perform invalid operation on socket"); }

		m_type = t;
	}

	// get socket name information
	const std::string& tcp_socket::get_host() const { return m_host; }
	std::uint32_t tcp_socket::get_port() const { return m_port; }

	// get socket type
	tcp_socket::type tcp_socket::get_type() const { return m_type; }

	// set type, should be used if some operations determining socket type
	// have been done on the behalf of the tcp_socket instance
	void tcp_socket::set_type(type t) { m_type = t; }

	// direct access to the underlying fd
	fd_t tcp_socket::get_fd() const { return m_fd; }

	// ipv6 checking
	bool tcp_socket::is_ipv6() const { return m_host.find(':') != std::string::npos; }

	bool tcp_socket::operator==(const tcp_socket& rhs) const { return m_fd == rhs.m_fd && m_type == rhs.m_type; }
	bool tcp_socket::operator!=(const tcp_socket& rhs) const { return !operator==(rhs); }

} // namespace tacopie

/// =========================
/// WINDOWS
/// =========================
#ifdef _WIN32

  // force link with ws2_32.lib
  // some user of the lib forgot to link with it #34
#pragma comment(lib, "ws2_32.lib")

#include "tcp_server.hpp"
#include "error.hpp"
#include "logger.hpp"
#include "typedefs.hpp"

#include <cstring>

#ifdef __GNUC__
#include <Ws2tcpip.h>	   // Mingw / gcc on windows
#define _WIN32_WINNT 0x0501
#include <winsock2.h>
#include <Ws2tcpip.h>
extern "C" {
	WINSOCK_API_LINKAGE  INT WSAAPI inet_pton(INT Family, PCSTR pszAddrString, PVOID pAddrBuf);
	WINSOCK_API_LINKAGE  PCSTR WSAAPI inet_ntop(INT  Family, PVOID pAddr, PSTR pStringBuf, size_t StringBufSize);
}
#else
  // Windows...
#include <winsock2.h>
#include <In6addr.h>
#include <Ws2tcpip.h>
#endif

namespace tacopie {

	void tcp_socket::connect(const std::string& host, std::uint32_t port, std::uint32_t timeout_msecs) 
	{
		// Reset host and port
		m_host = host;
		m_port = port;

		create_socket_if_necessary();
		check_or_set_type(type::CLIENT);

		struct sockaddr_storage ss;
		socklen_t addr_len;

		// 0-init addr info struct
		std::memset(&ss, 0, sizeof(ss));

		if (is_ipv6())
		{
			// init sockaddr_in6 struct
			struct sockaddr_in6* addr = reinterpret_cast<struct sockaddr_in6*>(&ss);
			// convert addr
			if (::inet_pton(AF_INET6, host.data(), &addr->sin6_addr) < 0) {
				__TACOPIE_THROW(error, "inet_pton() failure");
			}
			// remaining fields
			ss.ss_family = AF_INET6;
			addr->sin6_port = htons(port);
			addr_len = sizeof(*addr);
		}
		else
		{
			struct addrinfo* result = nullptr;
			struct addrinfo hints;

			memset(&hints, 0, sizeof(hints));
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_family = AF_INET;

			// resolve DNS
			if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) { __TACOPIE_THROW(error, "getaddrinfo() failure"); }

			// init sockaddr_in struct
			struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(&ss);
			// host
			addr->sin_addr = ((struct sockaddr_in*) (result->ai_addr))->sin_addr;
			// Remaining fields
			addr->sin_port = htons(port);
			ss.ss_family = AF_INET;
			addr_len = sizeof(*addr);

			freeaddrinfo(result);
		}

		if (timeout_msecs > 0)
		{
			// for timeout connection handling:
			//  1. set socket to non blocking
			//  2. connect
			//  3. poll select
			//  4. check connection status
			u_long mode = 1;
			if (ioctlsocket(m_fd, FIONBIO, &mode) != 0)
			{
				close();
				__TACOPIE_THROW(error, "connect() set non-blocking failure");
			}
		}
		else
		{
			// For no timeout case, still make sure that the socket is in blocking mode
			// As reported in #32, this might not be the case on some OS
			u_long mode = 0;
			if (ioctlsocket(m_fd, FIONBIO, &mode) != 0)
			{
				close();
				__TACOPIE_THROW(error, "connect() set blocking failure");
			}
		}

		int ret = ::connect(m_fd, reinterpret_cast<const struct sockaddr*>(&ss), addr_len);
		if (ret == -1 && WSAGetLastError() != WSAEWOULDBLOCK)
		{
			close();
			__TACOPIE_THROW(error, "connect() failure");
		}

		if (timeout_msecs > 0)
		{
			timeval tv;
			tv.tv_sec = (timeout_msecs / 1000);
			tv.tv_usec = ((timeout_msecs - (tv.tv_sec * 1000)) * 1000);

			FD_SET set;
			FD_ZERO(&set);
			FD_SET(m_fd, &set);

			// 1 means we are connected.
			// 0 means a timeout.
			if (select(static_cast<int>(m_fd) + 1, NULL, &set, NULL, &tv) == 1)
			{
				// Make sure there are no async connection errors
				int err = 0;
				int len = sizeof(len);
				if (getsockopt(m_fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) == -1 || err != 0)
				{
					close();
					__TACOPIE_THROW(error, "connect() failure");
				}

				// Set back to blocking mode as the user of this class is expecting
				u_long mode = 0;
				if (ioctlsocket(m_fd, FIONBIO, &mode) != 0)
				{
					close();
					__TACOPIE_THROW(error, "connect() set blocking failure");
				}
			}
			else
			{
				close();
				__TACOPIE_THROW(error, "connect() timed out");
			}
		}
	}

	//
	// server socket operations
	//

	void tcp_socket::bind(const std::string& host, std::uint32_t port)
	{
		// Reset host and port
		m_host = host;
		m_port = port;

		create_socket_if_necessary();
		check_or_set_type(type::SERVER);

		struct sockaddr_storage ss;
		socklen_t addr_len;

		// 0-init addr info struct
		std::memset(&ss, 0, sizeof(ss));

		if (is_ipv6())
		{
			// init sockaddr_in6 struct
			struct sockaddr_in6* addr = reinterpret_cast<struct sockaddr_in6*>(&ss);
			// convert addr
			if (::inet_pton(AF_INET6, host.data(), &addr->sin6_addr) < 0)
			{
				__TACOPIE_THROW(error, "inet_pton() failure");
			}
			// remaining fields
			addr->sin6_port = htons(port);
			ss.ss_family = AF_INET6;
			addr_len = sizeof(*addr);
		}
		else
		{
			struct addrinfo* result = nullptr;

			// dns resolution
			if (getaddrinfo(host.c_str(), nullptr, nullptr, &result) != 0) 
			{
				__TACOPIE_THROW(error, "getaddrinfo() failure");
			}

			// init sockaddr_in struct
			struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(&ss);
			// addr
			addr->sin_addr = ((struct sockaddr_in*) (result->ai_addr))->sin_addr;
			// remaining fields
			addr->sin_port = htons(port);
			ss.ss_family = AF_INET;
			addr_len = sizeof(*addr);

			freeaddrinfo(result);
		}

		if (::bind(m_fd, reinterpret_cast<const struct sockaddr*>(&ss), addr_len) == SOCKET_ERROR) { __TACOPIE_THROW(error, "bind() failure"); }
	}

	//
	// general socket operations
	//

	void tcp_socket::close()
	{
		if (m_fd != __TACOPIE_INVALID_FD)
		{
			__TACOPIE_LOG(debug, "close socket");
			closesocket(m_fd);
		}

		m_fd = __TACOPIE_INVALID_FD;
		m_type = type::UNKNOWN;
	}

	// create a new socket if no socket has been initialized yet
	void tcp_socket::create_socket_if_necessary()
	{
		if (m_fd != __TACOPIE_INVALID_FD) { return; }

		// new TCP socket
		// handle ipv6 addr
		short family;
		if (is_ipv6())
		{
			family = AF_INET6;
		}
		else
		{
			family = AF_INET;
		}
		m_fd = socket(family, SOCK_STREAM, 0);
		m_type = type::UNKNOWN;

		if (m_fd == __TACOPIE_INVALID_FD) { __TACOPIE_THROW(error, "tcp_socket::create_socket_if_necessary: socket() failure"); }
	}

} // namespace tacopie

#endif /* _WIN32 */


/// =========================
/// *NIX
/// =========================
#ifndef _WIN32

#include "tcp_server.hpp"
#include "error.hpp"
#include "logger.hpp"

#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

namespace tacopie
{

	void tcp_socket::connect(const std::string& host, std::uint32_t port, std::uint32_t timeout_msecs)
	{
		// Reset host and port
		m_host = host;
		m_port = port;

		create_socket_if_necessary();
		check_or_set_type(type::CLIENT);

		struct sockaddr_storage ss;
		socklen_t addr_len;

		// 0-init addr info struct
		std::memset(&ss, 0, sizeof(ss));

		// Handle case of unix sockets if port is 0
		bool is_unix_socket = m_port == 0;
		if (is_unix_socket)
		{
			// init sockaddr_un struct
			struct sockaddr_un* addr = reinterpret_cast<struct sockaddr_un*>(&ss);
			// host
			strncpy(addr->sun_path, host.c_str(), sizeof(addr->sun_path) - 1);
			// Remaining fields
			ss.ss_family = AF_UNIX;
			addr_len = sizeof(*addr);
		}
		else if (is_ipv6())
		{
			// init sockaddr_in6 struct
			struct sockaddr_in6* addr = reinterpret_cast<struct sockaddr_in6*>(&ss);
			// convert addr
			if (::inet_pton(AF_INET6, host.data(), &addr->sin6_addr) < 0) {
				__TACOPIE_THROW(error, "inet_pton() failure");
			}
			// remaining fields
			ss.ss_family = AF_INET6;
			addr->sin6_port = htons(port);
			addr_len = sizeof(*addr);
		}
		else
		{
			struct addrinfo* result = nullptr;
			struct addrinfo hints;

			memset(&hints, 0, sizeof(hints));
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_family = AF_INET;

			// resolve DNS
			if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) { __TACOPIE_THROW(error, "getaddrinfo() failure"); }

			// init sockaddr_in struct
			struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(&ss);
			// host
			addr->sin_addr = ((struct sockaddr_in*) (result->ai_addr))->sin_addr;
			// Remaining fields
			addr->sin_port = htons(port);
			ss.ss_family = AF_INET;
			addr_len = sizeof(*addr);

			freeaddrinfo(result);
		}

		if (timeout_msecs > 0)
		{
			// for timeout connection handling:
			//  1. set socket to non blocking
			//  2. connect
			//  3. poll select
			//  4. check connection status
			if (fcntl(m_fd, F_SETFL, fcntl(m_fd, F_GETFL, 0) | O_NONBLOCK) == -1)
			{
				close();
				__TACOPIE_THROW(error, "connect() set non-blocking failure");
			}
		}
		else
		{
			// For no timeout case, still make sure that the socket is in blocking mode
			// As reported in #32, this might not be the case on some OS
			if (fcntl(m_fd, F_SETFL, fcntl(m_fd, F_GETFL, 0) & (~O_NONBLOCK)) == -1)
			{
				close();
				__TACOPIE_THROW(error, "connect() set blocking failure");
			}
		}

		int ret = ::connect(m_fd, reinterpret_cast<const struct sockaddr*>(&ss), addr_len);
		if (ret < 0 && errno != EINPROGRESS)
		{
			close();
			__TACOPIE_THROW(error, "connect() failure");
		}

		if (timeout_msecs > 0)
		{
			timeval tv;
			tv.tv_sec = (timeout_msecs / 1000);
			tv.tv_usec = ((timeout_msecs - (tv.tv_sec * 1000)) * 1000);

			fd_set set;
			FD_ZERO(&set);
			FD_SET(m_fd, &set);

			// 1 means we are connected.
			// 0/-1 means a timeout.
			if (select(m_fd + 1, NULL, &set, NULL, &tv) == 1)
			{
				// Make sure there are no async connection errors
				int err = 0;
				socklen_t len = sizeof(len);
				if (getsockopt(m_fd, SOL_SOCKET, SO_ERROR, &err, &len) == -1 || err != 0)
				{
					close();
					__TACOPIE_THROW(error, "connect() failure");
				}

				// Set back to blocking mode as the user of this class is expecting
				if (fcntl(m_fd, F_SETFL, fcntl(m_fd, F_GETFL, 0) & (~O_NONBLOCK)) == -1)
				{
					close();
					__TACOPIE_THROW(error, "connect() set blocking failure");
				}
			}
			else
			{
				close();
				__TACOPIE_THROW(error, "connect() timed out");
			}
		}
	}

	void tcp_socket::bind(const std::string& host, std::uint32_t port)
	{
		// Reset host and port
		m_host = host;
		m_port = port;

		create_socket_if_necessary();
		check_or_set_type(type::SERVER);

		struct sockaddr_storage ss;
		socklen_t addr_len;

		// 0-init addr info struct
		std::memset(&ss, 0, sizeof(ss));

		// Handle case of unix sockets if port is 0
		bool is_unix_socket = m_port == 0;
		if (is_unix_socket)
		{
			// init sockaddr_un struct
			struct sockaddr_un* addr = reinterpret_cast<struct sockaddr_un*>(&ss);
			// host
			strncpy(addr->sun_path, host.c_str(), sizeof(addr->sun_path) - 1);
			// remaining fields
			ss.ss_family = AF_UNIX;
			addr_len = sizeof(*addr);
		}
		else if (is_ipv6())
		{
			// init sockaddr_in6 struct
			struct sockaddr_in6* addr = reinterpret_cast<struct sockaddr_in6*>(&ss);
			// convert addr
			if (::inet_pton(AF_INET6, host.data(), &addr->sin6_addr) < 0) {
				__TACOPIE_THROW(error, "inet_pton() failure");
			}
			// remaining fields
			addr->sin6_port = htons(port);
			ss.ss_family = AF_INET6;
			addr_len = sizeof(*addr);
		}
		else
		{
			struct addrinfo* result = nullptr;

			// dns resolution
			if (getaddrinfo(host.c_str(), nullptr, nullptr, &result) != 0) {
				__TACOPIE_THROW(error, "getaddrinfo() failure");
			}

			// init sockaddr_in struct
			struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(&ss);
			// addr
			addr->sin_addr = ((struct sockaddr_in*) (result->ai_addr))->sin_addr;
			// remaining fields
			addr->sin_port = htons(port);
			ss.ss_family = AF_INET;
			addr_len = sizeof(*addr);

			freeaddrinfo(result);
		}

		if (::bind(m_fd, reinterpret_cast<const struct sockaddr*>(&ss), addr_len) == -1) { __TACOPIE_THROW(error, "bind() failure"); }
	}

	void tcp_socket::close()
	{
		if (m_fd != __TACOPIE_INVALID_FD)
		{
			__TACOPIE_LOG(debug, "close socket");
			::close(m_fd);
		}

		m_fd = __TACOPIE_INVALID_FD;
		m_type = type::UNKNOWN;
	}

	void tcp_socket::create_socket_if_necessary()
	{
		if (m_fd != __TACOPIE_INVALID_FD) { return; }

		// new TCP socket
		// handle case of unix sockets by checking whether the port is 0 or not
		// also handle ipv6 addr
		short family;
		if (m_port == 0)
		{
			family = AF_UNIX;
		}
		else if (is_ipv6())
		{
			family = AF_INET6;
		}
		else
		{
			family = AF_INET;
		}

		m_fd = socket(family, SOCK_STREAM, 0);
		m_type = type::UNKNOWN;

		if (m_fd == __TACOPIE_INVALID_FD) { __TACOPIE_THROW(error, "tcp_socket::create_socket_if_necessary: socket() failure"); }
	}

} // namespace tacopie

#endif /* _WIN32 */

