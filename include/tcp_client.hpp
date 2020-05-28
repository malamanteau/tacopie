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

#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <queue>
#include <string>

#include "io_service.hpp"
#include "tcp_socket.hpp"
#include "typedefs.hpp"

namespace tacopie {

	// tacopie::tcp_server is the class providing TCP Client features.
	// The tcp_client works entirely asynchronously
	class tcp_client {
	public:
		// disconnection handle
		// called whenever a disconnection occured
		typedef std::function<void()> disconnection_handler_t;

		// structure to store read requests result
		//  * success: Whether the read operation has succeeded or not. If false, the client has been disconnected
		//  * buffer: Vector containing the read bytes
		struct read_result 
		{
			bool success; // whether the operation succeeeded or not
			std::vector<char> buffer; // read bytes
		};

		// structure to store write requests result
		//  * success: Whether the write operation has succeeded or not. If false, the client has been disconnected
		//  * size: Number of bytes written
		struct write_result 
		{
			bool success; // whether the operation succeeeded or not
			std::size_t size; // number of bytes written
		};

		// callback to be called on async read completion
		// takes the read_result as a parameter
		typedef std::function<void(read_result&)> async_read_callback_t;

		// callback to be called on async write completion
		// takes the write_result as a parameter
		typedef std::function<void(write_result&)> async_write_callback_t;

		// structure to store read requests information
		//  * size: Number of bytes to read
		//  * async_read_callback: Callback to be called on a read operation completion, even though the operation read less bytes than requested.
		struct read_request
		{
			std::size_t size; // number of bytes to read
			async_read_callback_t async_read_callback; // callback to be executed on read operation completion
		};

		// structure to store write requests information
		//  * buffer: Bytes to be written
		//  * async_write_callback: Callback to be called on a write operation completion, even though the operation wrote less bytes than requested.
		struct write_request
		{
			std::vector<char> buffer; // bytes to write
			async_write_callback_t async_write_callback; // callback to be executed on write operation completion
		};

	private:
		// io service read callback
		// called by the io service whenever the socket is readable
		//
		// fd: file description of the socket for which the read is available
		void on_read_available(fd_t fd);

		// io service write callback
		// called by the io service whenever the socket is writable
		//
		// fd: file description of the socket for which the write is available
		void on_write_available(fd_t fd);

		void clear_read_requests();  // Clear pending read requests (basically empty the queue of read requests)
		void clear_write_requests(); // Clear pending write requests (basically empty the queue of write requests)

		// process read operations when available
		// basically called whenever on_read_available is called and try to read from the socket
		// handle possible case of failure and fill in the result
		//
		// result: result of the read operation
		// Returns the callback to be executed (set in the read request) on read completion (may be null)
		async_read_callback_t process_read(read_result& result);

		// process write operations when available
		// basically called whenever on_write_available is called and try to write to the socket
		// handle possible case of failure and fill in the result
		//
		// result: result of the write operation
		// Returns the callback to be executed (set in the write request) on read completion (may be null)
		async_write_callback_t process_write(write_result& result);

		// Call the user-defined disconnection handler
		void call_disconnection_handler();

		std::shared_ptr<io_service> m_io_service; // prevent deletion of io_service before the tcp_client itself


		tacopie::tcp_socket m_socket; // client socket

		// whether the client is currently connected or not
		std::atomic<bool> m_is_connected = ATOMIC_VAR_INIT(false);

		std::queue<read_request>  m_read_requests;
		std::mutex                m_read_requests_mtx;
		std::queue<write_request> m_write_requests;
		std::mutex                m_write_requests_mtx;

		disconnection_handler_t m_disconnection_handler;

	public:
		 tcp_client();
		~tcp_client();

		// custom ctor
		// build socket from existing socket
		//
		// socket: tcp_socket instance to be used for building the client (socket will be moved)
		explicit tcp_client(tcp_socket&& socket);
		
		tcp_client            (tcp_client const &) = delete; // copy ctor
		tcp_client & operator=(tcp_client const &) = delete; // assignment operator

		// Returns true when the underlying sockets are the same (same file descriptor and socket type).
		bool operator==(tcp_client const & rhs) const { return m_socket == rhs.m_socket; }

		// Returns true when the underlying sockets are different (different file descriptor or socket type).
		bool operator!=(tcp_client const & rhs) const { return !operator==(rhs); }

		// Returns the hostname associated with the underlying socket.
		const std::string& get_host() const;

		// Returns the port associated with the underlying socket.
		std::uint32_t get_port() const;

		// Connect the socket to the remote server.
		//
		// host: Hostname of the target server
		// port: Port of the target server
		// timeout_msecs: maximum time to connect (will block until connect succeed or timeout expire). 0 will block undefinitely. If timeout expires, connection fails
		void connect(std::string const & host, std::uint32_t port, std::uint32_t timeout_msecs = 0);

		// Disconnect the tcp_client if it was currently connected.
		//
		// wait_for_removal: When sets to true, disconnect blocks until the underlying TCP client has been effectively removed from the io_service and that all the underlying callbacks have completed.
		void disconnect(bool wait_for_removal = false);

		// Returns whether the client is currently connected or not
		bool is_connected() const { return m_is_connected; }

		// async read operation
		//
		// request: read request information
		void async_read(read_request const & request);

		// async write operation
		//
		// request: write request information
		void async_write(write_request const & request);

		tacopie::tcp_socket       & get_socket()       { return m_socket; } // Returns underlying tcp_socket (non-const version)
		tacopie::tcp_socket const & get_socket() const { return m_socket; } // Returns underlying tcp_socket (const version)

		// Returns io service monitoring this tcp connection
		std::shared_ptr<tacopie::io_service> const & get_io_service() const { return m_io_service; }

		// set on disconnection handler
		//
		// disconnection_handler: the handler to be called on disconnection
		void set_on_disconnection_handler(disconnection_handler_t const & disconnection_handler) { m_disconnection_handler = disconnection_handler; }
	};

} // namespace tacopie
