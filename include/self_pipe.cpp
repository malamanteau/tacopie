
/// =========================
/// WINDOWS
/// =========================
#ifdef _WIN32

#include "self_pipe.hpp"
#include "error.hpp"

#include <winsock2.h>

#include "typedefs.hpp"

#include <fcntl.h>
#include <iostream>
namespace tacopie
{
	self_pipe::self_pipe()
		: m_fd(__TACOPIE_INVALID_FD)
	{
		// Create a server
		m_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
		if (m_fd == __TACOPIE_INVALID_FD) { __TACOPIE_THROW(error, "fail socket()"); }

		u_long flags = 1;
		ioctlsocket(m_fd, FIONBIO, &flags);

		// Bind server to localhost
		struct sockaddr_in inaddr;
		memset(&inaddr, 0, sizeof(inaddr));
		inaddr.sin_family = AF_INET;
		inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		inaddr.sin_port = 0;
		if (bind(m_fd, (struct sockaddr*) &inaddr, sizeof(inaddr)) == SOCKET_ERROR) { __TACOPIE_THROW(error, "fail bind()"); }

		// Retrieve server information
		m_addr_len = sizeof(m_addr);
		memset(&m_addr, 0, sizeof(m_addr));
		if (getsockname(m_fd, &m_addr, &m_addr_len) == SOCKET_ERROR) { __TACOPIE_THROW(error, "fail getsockname()"); }

		// connect read fd to the server
		if (connect(m_fd, &m_addr, m_addr_len) == SOCKET_ERROR) { __TACOPIE_THROW(error, "fail connect()"); }
	}

	self_pipe::~self_pipe()
	{
		if (m_fd != __TACOPIE_INVALID_FD)
			closesocket(m_fd);
	}

	fd_t self_pipe::get_read_fd()  const { return m_fd; }
	fd_t self_pipe::get_write_fd() const { return m_fd; }

	void self_pipe::notify() { (void)sendto(m_fd, "a", 1, 0, &m_addr, m_addr_len); }
	void self_pipe::clr_buffer()
	{ 
		char buf[1024]; 
		(void)recvfrom(m_fd, buf, 1024, 0, &m_addr, &m_addr_len);
	}

} // namespace tacopie

#endif /* _WIN32 */

/// =========================
/// *NIX
/// =========================
#ifndef _WIN32

#include "self_pipe.hpp"
#include "error.hpp"

#include <fcntl.h>
#include <unistd.h>

namespace tacopie {

	//
	// ctor & dtor
	//
	self_pipe::self_pipe()
		: m_fds{ __TACOPIE_INVALID_FD, __TACOPIE_INVALID_FD }
	{
		if (pipe(m_fds) == -1) { __TACOPIE_THROW(error, "pipe() failure"); }
	}

	self_pipe::~self_pipe()
	{
		if (m_fds[0] != __TACOPIE_INVALID_FD)
			close(m_fds[0]);

		if (m_fds[1] != __TACOPIE_INVALID_FD)
			close(m_fds[1]);
	}

	fd_t self_pipe::get_read_fd()  const { return m_fds[0]; }
	fd_t self_pipe::get_write_fd() const { return m_fds[1]; }

	template <typename T1>
	void ___ignore_unused(T1 const&) { }

	void self_pipe::notify() { ___ignore_unused(write(m_fds[1], "a", 1)); }

	void self_pipe::clr_buffer()
	{
		char buf[1024];
		___ignore_unused(read(m_fds[0], buf, 1024));
	}

} // namespace tacopie

#endif /* _WIN32 */
