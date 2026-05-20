/*
	file       HTTPBasma.h
	author     Mohamad Mokbel (mfmokbel@netomize.ca)
	brief      HTTP-Basma v1.0

	details    Header file for the HTTPBasma.cpp file.

               See LICENSE file for details.

	copyright  Netomize. Copyright (c) 2026.  All rights reserved.
*/

#pragma once

#include <iostream>

#if defined(_WIN32)
	#include <windows.h>
	#define EXIT_CURRENT_THREAD() ExitThread(0)

#elif defined(__linux__)
	#include <unistd.h>
	#include <codecvt>  // deprecated in C++17 but still works; see note below
	#include <locale>

	#include <pthread.h>
	#define EXIT_CURRENT_THREAD() pthread_exit(nullptr)

#endif

#include <CkGlobal.h>
#include "CkHttp.h"
// HTTP-Basma requires CkHttpRequest class version 9.5.0.97 and above
#include "CkHttpRequest.h"
#include "CkHttpResponse.h"
#include <CkByteData.h>
#include <CkBinData.h>
#include <CkUrl.h>
#include <CkPrng.h>
#include <CkCsv.h>
#include <CkCrypt2.h>
#include <CkJsonObject.h>
#include <CkXml.h>

// https://github.com/jarro2783/cxxopts
#include <cxxopts.hpp>
// https://github.com/agauniyal/rang
#include <rang.hpp>

#include <memory>
#include <vector>
#include <string>
#include <string_view>
#include <algorithm>
#include <regex>
#include <sstream>
#include <fstream>
#include <array>
#include <map>
#include <format>
#include <iomanip>
#include <tuple>
#include <thread>
#include <mutex>
#include <atomic>
#include <execution>
#include <chrono>
#include <cassert>
#include <bitset>
#include <functional>
#include <variant>

#include "FP_Dissector.h"

namespace fingerprint
{
	namespace version
	{
		// version number is a one byte hex value
		const std::string verbosus = "01";
		const std::string pacto    = "02";
	};

	fp_dissected get_verbosus_dissected(const std::string& fp);

	std::string get_verbosus(const std::string& fp);
	std::string get_pacto(const std::string& fp);
};

// compact types names
namespace t
{
	// domain_tuple -> (domain, port_number, is_ssl, path)
	using domain_tuple = std::tuple<std::string, std::uint16_t, bool, std::string>;
	using fp_map = std::map<std::string, std::string>; // [version] = fp_value
	using conx_state_tuple = std::tuple<bool, bool>; // <keep-alive, close>

	enum d { domain = 0, port, ssl, path };
};

namespace domain
{
	void load_domains_file(const std::string& filename, std::vector<t::domain_tuple>& domains);
	t::domain_tuple setup_domain(const std::string& domain);
};

namespace probe_info
{
	class pinfo
	{
	public:

		std::string date;
		std::string time;
		std::string req_type;
		std::string req_status;
		std::string resp_status_line;
		std::string resp_headers;
		std::string status_line_fp;
		std::string content_length_fp;
		std::string response_headers_fp; // available only with p1
		t::conx_state_tuple conx_state;
		std::string fingerprint;
		std::string comment;             // not used (for reference only)

		std::uint16_t nb_headers = 0;    // not used (for reference in the output)
		//std::string nb_headers_fp;     // not used (for reference only)
	};

	void set_prologue(probe_info::pinfo* rinfo, const std::string& type);
	void set_payload(probe_info::pinfo* rinfo, CkHttpResponse* resp);
	void set_fingerprint(probe_info::pinfo* rinfo, const std::string& fp_sl, const std::string& fp_c_len,
		const std::string& fp_all, const t::conx_state_tuple& conx_s = std::tuple(false, false));
	void set_failure(probe_info::pinfo* rinfo, const std::string& ifp);
};

namespace request
{
	namespace stype
	{
		const std::string p1_get_normal               = "get_normal";
		const std::string p2_get_invalid_ver_nb       = "get_invalid_ver_nb";
		const std::string p3_get_rnd_resource         = "get_rnd_resource";
		const std::string p4_get_rnd_verb             = "get_rnd_verb";
		const std::string p5_get_lowercase_verb       = "get_lowercase_verb";
		const std::string p6_get_accept_encoding_full = "get_accept_encoding_full";
		const std::string p6_get_accept_encoding_less = "get_accept_encoding_less";
		const std::string p7_options_allow_hdr        = "options_allow_hdr";
	};
	// it has to start from 0; it is used as an index with the obj std::vector<probe_info::pinfo>
	enum etype { p1 = 0, p2, p3, p4, p5, p6f, p6l, p7a };

	// every request returns the fingerprint associated with it
	/* 1 */   std::string send_get_req_valid_probe_1(const t::domain_tuple& domain, probe_info::pinfo* rinfo = nullptr);
	/* 2 */   std::string send_get_req_invalid_ver_nb_probe_2(const t::domain_tuple& domain, probe_info::pinfo* rinfo = nullptr);
	/* 3 */   std::string send_get_req_rnd_resource_probe_3(const t::domain_tuple& domain, probe_info::pinfo* rinfo = nullptr);
	/* 4 */   std::string send_get_req_rnd_verb_probe_4(const t::domain_tuple& domain, probe_info::pinfo* rinfo = nullptr);
	/* 5 */   std::string send_get_req_lowercase_verb_probe_5(const t::domain_tuple& domain, probe_info::pinfo* rinfo = nullptr);
	/* 6-7 */ std::string send_get_req_accept_encoding_probe_6x(const t::domain_tuple& domain, bool less = false, probe_info::pinfo* rinfo = nullptr);
	/* 8 */   std::string send_options_req_probe_7x(const t::domain_tuple& domain, probe_info::pinfo* rinfo = nullptr);

	t::fp_map send_probes_get_fingerprint(const t::domain_tuple& domain, std::vector<probe_info::pinfo>* rinfo = nullptr);

	// setup HTTP socket connection
	void setup_http_connection(CkHttp& http, CkHttpRequest& http_req, const std::string& path);
	CkHttpResponse* synchronous_http_request(CkHttp& http, CkHttpRequest& http_req, const t::domain_tuple& domain);
	void wait(void);

	namespace header
	{
		CkPrng rnd_ae;
		std::string ae_grease_1 = std::string(rnd_ae.randomString(8, false, true, false));
		std::string ae_grease_2 = std::string(rnd_ae.randomString(10, true, true, false));

		// https://www.iana.org/assignments/http-parameters/http-parameters.xml#http-parameters-1
		std::array<std::string, 13> accept_encoding_v =
		{
			"aes128gcm",
			"br",
			ae_grease_1,
			"compress",
			"deflate",
			"exi",
			ae_grease_2,
			"gzip",
			"pack200-gzip",
			"x-compress",
			"x-gzip",
			"zstd",
			"identity"
		};

		std::array<std::string, 7> accept_encoding_v_less =
		{
			ae_grease_1,
			"compress",
			"deflate",
			ae_grease_2,
			"x-compress",
			"zstd",
			"br"
		};
	};
};

namespace response
{
	int does_header_exist(CkHttpResponse* resp, const std::string& header_n, const std::string& header_v = "", bool check_header_v = false);
	std::string get_fingerprint_nb_headers(CkHttpResponse* resp); // not used (for reference)
	std::string get_fingerprint_headers(CkHttpResponse* resp, bool lower_case = false, bool sort = false, bool unique = false);
	std::string get_fingerprint_content_encoding(CkHttpResponse* resp);
	std::string get_fingerprint_strict_transport_security_header(CkHttpResponse* resp);
	t::conx_state_tuple get_fingerprint_conx_hdr(CkHttpResponse* resp);

	template <typename T, char size> T fnv1a_hash(const std::string& hdata);

	namespace status_line
	{
		std::string get_fingerprint_status_code(CkHttpResponse* resp);
		std::string get_fingerprint_http_version(CkHttpResponse* resp);
		std::string get_fingerprint_http_reason(CkHttpResponse* resp, const std::string& del_str = {});
		std::string get_fingerprint(CkHttpResponse* resp, const std::string& del_str = {}); // calls above three funcs

		// This method is for going deep into the server response to get the respone raw, independent 
		// of whether it is std conformant or not. The CkHTTP flag VerboseLogging has to be set to true.
		// Chilkat library doesn't provide any means to get the server response raw, otherwise!
		std::string get_resp_deep_log(CkHttp& http);
		// a floating method
		void set_resp_deep_log(CkHttpResponse* resp, CkHttp& http);

		bool is_valid(CkHttpResponse* resp);

		std::string resp_raw_deep = {}; // update per probe

		// Allowed chars for the Reason-Phrase  = *( HTAB / SP / VCHAR / obs-text )
		// invoke in-place
		std::string achars = []()
			{
				std::string achars = {};
				// obs-text [0x80-0xff]
				for (unsigned char i = 0x00; i <= 0x7f; ++i) { achars += (0x80 + i); }
				// SP / VCHAR [0x20-0x7e]
				for (unsigned char i = 0x00; i <= 0x5e; ++i) { achars += (0x20 + i); }
				// HTAB
				achars += 0x09;
				return achars;
			}();

		std::map<std::uint16_t, std::string> status_code
		{
			// https://http.dev/status
			// Total: 102
			// 09 - Informational responses
			{100, "Continue"},
			{101, "Switching protocols"},
			{102, "Processing"},				// WebDAV
			{103, "Early Hints"},
			{110, "Response is Stale"},			// Unofficial and Deprecated
			{111, "Revalidation Failed"},		// Unofficial and Deprecated
			{112, "Disconnected Operation"},	// Unofficial and Deprecated
			{113, "Heuristic Expiration"},		// Unofficial and Deprecated
			{199, "Miscellaneous Warning"},		// Unofficial and Deprecated

			// 13 - Successful responses
			{200, "OK"},
			{201, "Created"},
			{202, "Accepted"},
			{203, "Non-Authoritative Information"},
			{204, "No Content"},
			{205, "Reset Content"},
			{206, "Partial Content"},
			{207, "Multi-Status"},						// WebDAV
			{208, "Already Reported"},					// WebDAV
			{214, "Transformation Applied"},			// Unofficial and Deprecated
			{218, "This is fine"},						// Unofficial
			{226, "IM Used"},							// HTTP Delta encoding
			{299, "Miscellaneous Persistent Warning"},	// Unofficial and Deprecated

			// 09 - Redirection messages
			{300, "Multiple Choices"},
			{301, "Moved Permanently"},
			{302, "Found"},					// "Found" but used to be "Moved Temporarily"
			{303, "See Other"},
			{304, "Not Modified"},
			{305, "Use Proxy"},				// deprecated		
			// the 306 status code was defined in a previous version of this specification, 
			// is no longer used, and the code is reserved.
			{306, "Switch Proxy"},			// "Unused" but used to be "Switch Proxy"
			{307, "Temporary Redirect"},
			{308, "Permanent Redirect"},

			// 44 - Client error responses
			{400, "Bad Request"},
			{401, "Unauthorized"},
			{402, "Payment Required"},							// Experimental
			{403, "Forbidden"},
			{404, "Not Found"},
			{405, "Method Not Allowed"},						// Some servers return "Not Allowed", "Not Allowed." (wired.com)
			{406, "Not Acceptable"},
			{407, "Proxy Authentication Required"},
			{408, "Request Timeout"},
			{409, "Conflict"},
			{410, "Gone"},
			{411, "Length Required"},
			{412, "Precondition Failed"},
			{413, "Content Too Large"},							// OR "Payload Too Large"
			{414, "URI Too Long"},
			{415, "Unsupported Media Type"},
			{416, "Range Not Satisfiable"},
			{417, "Expectation Failed"},
			// https://httpwg.org/specs/rfc9110.html#status.418
			{418, "I'm a teapot"},								// "Unused" but used to be "I'm a teapot"
			{419, "Page Expired"},								// Unofficial
			{420, "Method Failure"},							// OR "Enhance your calm" Unofficial 
			{421, "Misdirected Request"},
			{422, "Unprocessable Content"},						// OR "Unprocessable Entity" WebDAV
			{423, "Locked"},									// WebDAV
			{424, "Failed Dependency"},							// WebDAV
			{425, "Too Early"},									// Experimental
			{426, "Upgrade Required"},
			{428, "Precondition Required"},
			{429, "Too Many Requests"},
			{431, "Request Header Fields Too Large"},
			{440, "Login Time-Out"},							// Unofficial
			{444, "No Response"},								// Unofficial
			{449, "Retry With"},								// Unofficial
			{450, "Blocked by Windows Parental Controls"},		// Unofficial
			{451, "Unavailable For Legal Reasons"},
			{460, "Client Closed Connection Prematurely"},		// Unofficial
			{463, "Too Many Forwarded IP Addresses"},			// Unofficial
			{464, "Incompatible Protocol"},						// Unofficial
			{494, "Request Header Too Large"},					// Unofficial
			{495, "SSL Certificate Error"},						// Unofficial
			{496, "SSL Certificate Required"},					// Unofficial
			{497, "HTTP Request Sent to HTTPS Port"},			// Unofficial
			{498, "Invalid Token"},								// Unofficial
			{499, "Token Required or Client Closed Request"},	// Unofficial

			// 27 - Server error responses
			{500, "Internal Server Error"},
			{501, "Not Implemented"},
			{502, "Bad Gateway"},
			{503, "Service Unavailable"},
			{504, "Gateway Timeout"},
			{505, "HTTP Version Not Supported"},
			{506, "Variant Also Negotiates"},
			{507, "Insufficient Storage"},				// WebDAV
			{508, "Loop Detected"},						// WebDAV
			{509, "andwidth Limit Exceeded"},			// Unofficial
			{510, "Not Extended"},
			{511, "Network Authentication Required"},
			{520, "Connection Timed Out"},				// Unofficial
			{521, "Web Server Is Down"},				// Unofficial
			{522, "Origin Is Unreachable"},				// Unofficial
			{523, "Web Server Is Down"},				// Unofficial
			{524, "A Timeout Occurred"},				// Unofficial
			{525, "SSL Handshake Failed"},				// Unofficial
			{526, "Invalid SSL Certificate"},			// Unofficial
			{527, "Railgun Listener to Origin"},		// Unofficial
			{529, "The Service Is Overloaded"},			// Unofficial
			{530, "Site Frozen"},						// Unofficial
			{555, "User Defined Resource Error"},       // https://www.ietf.org/archive/id/draft-divilly-status-555-00.html
			{561, "Unauthorized" },						// Unofficial
			{598, "Network Read Timeout Error" },		// Unofficial
			{599, "Network Connect Timeout Error" },	// Unofficial
			{999, "Request Denied" }					// Unofficial
		};
	};
	bool chk_slv = true;
	bool chk_sl_validity(CkHttpResponse* resp);
	namespace content_length
	{
		std::string get_fingerprint_content_length(CkHttpResponse* resp);
		std::string encode_length(const std::uint32_t& length);
		std::string encode_content_length_name(const std::string& cl_name);
		std::string encode_transfer_encoding_name(const std::string& te_name);
	};

	namespace allow_header
	{
		// fingerprint - encoded length and header value
		class fp_len_hval
		{
		public:

			void set_allow_total_nb(void)
			{
				allow_total_nb.reset();

				std::size_t allow_total = allow_nb + allow_acam_nb + public_nb;

				if (allow_total >= 0 and allow_total < 31)
				{
					allow_total_nb = allow_total;
				}
				else if (allow_total > 30)
				{
					allow_total_nb = 31;
				}
			}
			void encode_size(void)
			{
				allow_key.reset();

				/*
						[1 1 1 1 1]  [1]   [1]   [1]
							size      p     ac    a
						   [1-31]    0|1   0|1   0|1
				*/
				if (is_allow) { allow_key.set(0, 1); }
				if (is_allow_acam) { allow_key.set(1, 1); }
				if (is_public) { allow_key.set(2, 1); }

				allow_key.set(3, allow_total_nb[0]);
				allow_key.set(4, allow_total_nb[1]);
				allow_key.set(5, allow_total_nb[2]);
				allow_key.set(6, allow_total_nb[3]);
				allow_key.set(7, allow_total_nb[4]);

			}
			std::string get_fingerprint(void)
			{
				std::string allow_v_hash = {}, allow_all_v_tmp = {}, allow_key_hash = {};

				allow_all_v_tmp = allow_values + allow_acam_values + public_values;

				if (allow_all_v_tmp.size() > 0)
				{
					allow_v_hash = std::format("{0:04x}", response::fnv1a_hash<std::uint16_t, 'h'>(allow_all_v_tmp));
				}
				else
				{
					allow_v_hash = "0000";
				}

				allow_key_hash = std::format("{0:02x}", allow_key.to_ulong());

				return (allow_key_hash + allow_v_hash);
			}

			bool is_allow = false;
			std::size_t allow_nb = 0;
			std::string allow_values = {};

			bool is_allow_acam = false;
			std::size_t allow_acam_nb = 0;
			std::string allow_acam_values = {};

			bool is_public = false;
			std::size_t public_nb = 0;
			std::string public_values = {};

			std::bitset<5> allow_total_nb;
			std::bitset<8> allow_key;
		};

		bool get_fingerprint_allow_header(CkHttpResponse* resp, const std::string& header_k, fp_len_hval& fp_struct);
	}
};

namespace helper
{
	std::string get_date(void);
	std::string get_time(void);
	void lowercase_str_in(std::string& str);
	std::string lowercase_str_out(const std::string& str);
	void check_args(int argc, char** argv);
	bool is_str_in_vec(const std::vector<std::string>& v, const std::string& str);
	void del_sstr(std::string& str, const std::string& del_str);
	// thread
	template <typename T>
	void update_title_realtime(std::string msg, T& cntr_var, T& total_var);

	void set_console_tite(std::wstring msg);

	void print_probing_domain_progress(const std::size_t& i, const std::string& d);
};

namespace csv
{
	bool write_header_to_file(CkCsv& csv);
	void write_data_to_file(CkCsv& csv, int r, std::vector<probe_info::pinfo>& rinfo, t::fp_map& fp, const t::domain_tuple& domain);
	std::string	generate_filename(void);

	std::string filename = {};
}

namespace json
{
	void build_prolog(CkJsonObject& json, const std::size_t domains_total);
	void write_epilog(CkJsonObject& json);
	void build_domain_payload(CkJsonObject& json, std::size_t i /*index*/, std::vector<probe_info::pinfo>& rinfo, t::fp_map& fp, const t::domain_tuple& domain);
	std::string generate_filename(void);

	std::string filename = {};
}

namespace compare
{
	void compare_verbosus(const std::string& fp1, const std::string& fp2);
}

namespace arg_opt
{
	bool check_dpath    = false;
	bool is_ssl         = false;
	std::uint16_t port  = 80;
	bool port_set       = false;

	int conxtn_timeout  = 1;   // 1 second
	int read_timeout    = 1;   // 1 second
	std::uint32_t sleep = 100; // sleep (in ms) delta between every request
	bool http_redirect  = true;

	std::vector<t::domain_tuple> domains_vec = {};
	bool domain_opt_set        = false;

	bool        print_json     = {};
	std::string file_domains   = {};
	bool file_opt_set          = false;

	bool save_to_csv_file      = false;
	bool save_to_json_file     = false;
	bool save_resp_headers     = false;

	bool scan_file_in_parallel = false;

	void parse_proxy_config(const std::vector<std::string>& prxy);
	struct proxy
	{
		// socks4, socks5, http
		std::string type   = {};
		std::string domain = {};
		std::string login  = {};
		std::string pass   = {};

		std::uint16_t port = 0;
		bool direct_tls    = false;
	}prxy_setup;
};

void print_msg_exit(const std::string& msg);
void attivare_chilka_lic(void);

namespace prog_about
{
	const std::string prog_name         = "HTTP-Basma";
	const std::string prog_full_name    = "HTTP-Basma";
	const std::string prog_version      = "1.0";
	const std::string prog_edition      = "Plasma";
	const std::string prog_release_date = "May 20, 2026";

#ifdef _M_IX86
	const std::string arch = "32-bit";
#else
	const std::string arch = "64-bit";
#endif

	const std::string author_name = "Mohamad Mokbel";
	const std::string author_email = "mfmokbel@netomize.ca";
}
