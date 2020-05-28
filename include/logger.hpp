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

#include <memory>
#include <mutex>
#include <string>

namespace tacopie {

	//
	// logger_iface
	// should be inherited by any class intended to be used for logging
	//
	class logger_iface 
	{
	public:
		logger_iface() = default;
		virtual ~logger_iface() = default;

		// copy ctor
		logger_iface(const logger_iface&) = default;
		// assignment operator
		logger_iface& operator=(const logger_iface&) = default;

	public:
		// debug logging
		//
		// msg: message to be logged
		// file: file from which the message is coming
		// line: line in the file of the message
		virtual void debug(const std::string& msg, const std::string& file, std::size_t line) = 0;

		// info logging
		//
		// msg: message to be logged
		// file: file from which the message is coming
		// line: line in the file of the message
		virtual void info(const std::string& msg, const std::string& file, std::size_t line) = 0;

		// warn logging
		//
		// msg: message to be logged
		// file: file from which the message is coming
		// line: line in the file of the message
		virtual void warn(const std::string& msg, const std::string& file, std::size_t line) = 0;

		// error logging
		//
		// msg: message to be logged
		// file: file from which the message is coming
		// line: line in the file of the message
		virtual void error(const std::string& msg, const std::string& file, std::size_t line) = 0;
	};

	// default logger class provided by the library
	class logger : public logger_iface {
	public:

		enum class log_level
		{
			error = 0,
			warn  = 1,
			info  = 2,
			debug = 3
		};

	public:
		 logger(log_level level = log_level::info);
		~logger() = default;

		// copy ctor
		logger(const logger&) = default;
		// assignment operator
		logger& operator=(const logger&) = default;

	public:
		// debug logging
		//
		// msg: message to be logged
		// file: file from which the message is coming
		// line: line in the file of the message
		void debug(const std::string& msg, const std::string& file, std::size_t line);

		// info logging
		//
		// msg: message to be logged
		// file: file from which the message is coming
		// line: line in the file of the message
		void info(const std::string& msg, const std::string& file, std::size_t line);

		// warn logging
		//
		// msg: message to be logged
		// file: file from which the message is coming
		// line: line in the file of the message
		void warn(const std::string& msg, const std::string& file, std::size_t line);

		// error logging
		//
		// msg: message to be logged
		// file: file from which the message is coming
		// line: line in the file of the message
		void error(const std::string& msg, const std::string& file, std::size_t line);

	private:
		// current log level in use
		log_level m_level;

		// mutex used to serialize logs in multithreaded environment
		std::mutex m_mutex;
	};

	// variable containing the current logger
	// by default, not set (no logs)
	extern std::unique_ptr<logger_iface> active_logger;

	// debug logging
	// convenience function used internaly to call the logger
	//
	// msg: message to be logged
	// file: file from which the message is coming
	// line: line in the file of the message
	void debug(const std::string& msg, const std::string& file, std::size_t line);

	// info logging
	// convenience function used internaly to call the logger
	//
	// msg: message to be logged
	// file: file from which the message is coming
	// line: line in the file of the message
	void info(const std::string& msg, const std::string& file, std::size_t line);

	// warn logging
	// convenience function used internaly to call the logger
	//
	// msg: message to be logged
	// file: file from which the message is coming
	// line: line in the file of the message
	void warn(const std::string& msg, const std::string& file, std::size_t line);

	// error logging
	// convenience function used internaly to call the logger
	//
	// msg: message to be logged
	// file: file from which the message is coming
	// line: line in the file of the message
	void error(const std::string& msg, const std::string& file, std::size_t line);

	// convenience macro to log with file and line information
	#ifdef __TACOPIE_LOGGING_ENABLED
		#define __TACOPIE_LOG(level, msg) tacopie::level(msg, __FILE__, __LINE__);
	#else
		#define __TACOPIE_LOG(level, msg)
	#endif /* __TACOPIE_LOGGING_ENABLED */

} // namespace tacopie
