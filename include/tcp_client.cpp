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

#include "tcp_client.hpp"
#include "error.hpp"
#include "logger.hpp"

namespace tacopie {

	//
	// ctor & dtor
	//

	tcp_client::tcp_client()
		: m_disconnection_handler(nullptr) 
	{
		m_io_service = get_default_io_service();
		__TACOPIE_LOG(debug, "create tcp_client");
	}

	tcp_client::~tcp_client() 
	{
		__TACOPIE_LOG(debug, "destroy tcp_client");
		disconnect(true);
	}

	// custom ctor
	// build client from existing socket
	tcp_client::tcp_client(tcp_socket&& socket)
		: m_io_service(get_default_io_service())
		, m_socket(std::move(socket))
		, m_disconnection_handler(nullptr)
	{
		m_is_connected = true;
		__TACOPIE_LOG(debug, "create tcp_client");
		m_io_service->track(m_socket);
	}

	const std::string& tcp_client::get_host() const { return m_socket.get_host(); }
	std::uint32_t      tcp_client::get_port() const { return m_socket.get_port(); }

	void tcp_client::connect(const std::string& host, std::uint32_t port, std::uint32_t timeout_msecs)
	{
		if (is_connected()) { __TACOPIE_THROW(warn, "tcp_client is already connected"); }

		try 
		{
			m_socket.connect(host, port, timeout_msecs);
			m_io_service->track(m_socket);
		}
		catch (const tacopie_error& e)
		{
			m_socket.close();
			throw e;
		}

		m_is_connected = true;

		__TACOPIE_LOG(info, "tcp_client connected");
	}

	void tcp_client::disconnect(bool wait_for_removal) 
	{
		if (!is_connected()) { return; }

		// update state
		m_is_connected = false;

		// clear all pending requests
		clear_read_requests();
		clear_write_requests();

		// remove socket from io service and wait for removal if necessary
		m_io_service->untrack(m_socket);
		if (wait_for_removal) { m_io_service->wait_for_removal(m_socket); }

		// close the socket
		m_socket.close();

		__TACOPIE_LOG(info, "tcp_client disconnected");
	}

	void tcp_client::clear_read_requests() 
	{
		std::lock_guard<std::mutex> lock(m_read_requests_mtx);

		std::queue<read_request> empty;
		std::swap(m_read_requests, empty);
	}

	void tcp_client::clear_write_requests() 
	{
		std::lock_guard<std::mutex> lock(m_write_requests_mtx);

		std::queue<write_request> empty;
		std::swap(m_write_requests, empty);
	}

	void tcp_client::call_disconnection_handler() 
	{
		if (m_disconnection_handler) 
		{
			m_disconnection_handler();
		}
	}

	// io service read callback
	void tcp_client::on_read_available(fd_t) 
	{
		__TACOPIE_LOG(info, "read available");

		read_result result;
		auto callback = process_read(result);

		if (!result.success)
		{
			__TACOPIE_LOG(warn, "read operation failure");
			disconnect();
		}

		if (callback) { callback(result); }

		if (!result.success) { call_disconnection_handler(); }
	}

	// io service write callback
	void tcp_client::on_write_available(fd_t) 
	{
		__TACOPIE_LOG(info, "write available");

		write_result result;
		auto callback = process_write(result);

		if (!result.success)
		{
			__TACOPIE_LOG(warn, "write operation failure");
			disconnect();
		}

		if (callback) { callback(result); }

		if (!result.success) { call_disconnection_handler(); }
	}

	// process read & write operations when available
	tcp_client::async_read_callback_t tcp_client::process_read(read_result& result) 
	{
		std::lock_guard<std::mutex> lock(m_read_requests_mtx);

		if (m_read_requests.empty()) { return nullptr; }

		const auto& request = m_read_requests.front();
		auto callback = request.async_read_callback;

		try
		{
			result.buffer = m_socket.recv(request.size);
			result.success = true;
		}
		catch (const tacopie::tacopie_error&)
		{
			result.success = false;
		}

		m_read_requests.pop();

		if (m_read_requests.empty()) { m_io_service->set_rd_callback(m_socket, nullptr); }

		return callback;
	}

	tcp_client::async_write_callback_t tcp_client::process_write(write_result& result)
	{
		std::lock_guard<std::mutex> lock(m_write_requests_mtx);

		if (m_write_requests.empty()) { return nullptr; }

		const auto& request = m_write_requests.front();
		auto callback = request.async_write_callback;

		try
		{
			result.size = m_socket.send(request.buffer, request.buffer.size());
			result.success = true;
		}
		catch (const tacopie::tacopie_error&)
		{
			result.success = false;
		}

		m_write_requests.pop();

		if (m_write_requests.empty()) { m_io_service->set_wr_callback(m_socket, nullptr); }

		return callback;
	}

	void tcp_client::async_read(const read_request& request) 
	{
		std::lock_guard<std::mutex> lock(m_read_requests_mtx);

		if (is_connected())
		{
			m_io_service->set_rd_callback(m_socket, std::bind(&tcp_client::on_read_available, this, std::placeholders::_1));
			m_read_requests.push(request);
		}
		else
		{
			__TACOPIE_THROW(warn, "tcp_client is disconnected");
		}
	}

	void tcp_client::async_write(const write_request& request) 
	{
		std::lock_guard<std::mutex> lock(m_write_requests_mtx);

		if (is_connected()) {
			m_io_service->set_wr_callback(m_socket, std::bind(&tcp_client::on_write_available, this, std::placeholders::_1));
			m_write_requests.push(request);
		}
		else
		{
			__TACOPIE_THROW(warn, "tcp_client is disconnected");
		}
	}

} // namespace tacopie
