#include "HTTPBasma.h"
#include "Demangler.h"

/*
    file       HTTPBasma.cpp
    author     Mohamad Mokbel (mfmokbel@netomize.ca)
    brief      HTTP-Basma v1.0

    details    A novel active HTTP fingerprinting algorithm that unveils unique 
               server profiles through a multi-layered approach.

               See LICENSE file for details.

               * HTTP-Basma uses various C++ objects from the commercial library Chilkat Software
                    - A valid key is required to build the source code
                    - Netomize ships a release version of HTTPBasma

    copyright  Netomize. Copyright (c) 2026.  All rights reserved.
*/

int main(int argc, char* argv[])
{
    attivare_chilka_lic();

    helper::check_args(argc, argv);

    std::variant<std::execution::sequenced_policy, std::execution::parallel_policy> exec_policy;
    if (arg_opt::scan_file_in_parallel)
    {
        exec_policy = std::execution::par;
    }
    else
    {
        exec_policy = std::execution::seq;
    }

    if (arg_opt::domain_opt_set)
    {
        CkJsonObject json;
        if (arg_opt::print_json or arg_opt::save_to_json_file)
        {
            json::build_prolog(json, arg_opt::domains_vec.size());
        }

        CkCsv csvh;
        if (arg_opt::save_to_csv_file)
        {
            if (!csv::write_header_to_file(csvh))
            {
                print_msg_exit("failed to write the header to the csv file " + csv::filename);
            }
        }

        for (std::size_t i = 0, row_idx = 0; i < arg_opt::domains_vec.size(); ++i, ++row_idx)
        {
            std::vector<probe_info::pinfo> rinfo = {};
            t::fp_map fingerpints = request::send_probes_get_fingerprint(arg_opt::domains_vec.at(i), &rinfo);

            if (arg_opt::print_json or arg_opt::save_to_json_file)
            {
                json::build_domain_payload(json, i, rinfo, fingerpints, arg_opt::domains_vec.at(i));
            }
            else
            {
                std::cout << std::endl << "  [*] "
                    << helper::get_date() << " " << helper::get_time() << rang::fg::cyan << " -> " << rang::fg::reset
                    << std::get<t::d::domain>(arg_opt::domains_vec.at(i)) << ":"
                    << std::get<t::d::port>(arg_opt::domains_vec.at(i)) << ":"
                    << std::get<t::d::ssl>(arg_opt::domains_vec.at(i))
                    << std::endl << std::endl;

                std::cout << rang::fg::green << "  V: " << rang::fg::reset << fingerpints[fingerprint::version::verbosus] << std::endl;
                std::cout << rang::fg::red << "  P: " << rang::fg::reset << fingerpints[fingerprint::version::pacto] << std::endl;
            }

            if (arg_opt::save_to_csv_file)
            {
                csv::write_data_to_file(csvh, row_idx, rinfo, fingerpints, arg_opt::domains_vec.at(i));
            }
        }

        if (arg_opt::print_json or arg_opt::save_to_json_file)
        {
            json::write_epilog(json);

            if (arg_opt::print_json)
            {
                json.put_EmitCompact(false);
                std::cout << std::endl << json.emit() << std::endl;
            }
            if (arg_opt::save_to_json_file)
            {
                if (!json.WriteFile(json::filename.c_str()))
                {
                    print_msg_exit("failed to write to the json file " + json::filename);
                }
            }
        }
        std::exit(0);
    }

    if ((arg_opt::save_to_csv_file or arg_opt::save_to_json_file) and arg_opt::file_opt_set)
    {
        // domain, port_number, is_ssl
        std::vector<t::domain_tuple> domains;
        domain::load_domains_file(arg_opt::file_domains, domains);
        if (domains.empty())
        {
            print_msg_exit("the file " + arg_opt::file_domains + " with the list of domains is empty");
        }

        CkCsv csvh;
        if (arg_opt::save_to_csv_file)
        {
            if (!csv::write_header_to_file(csvh))
            {
                print_msg_exit("failed to write the header to the csv file " + csv::filename);
            }
        }

        CkJsonObject json;
        auto json_write_file = [&json]() -> void
            {
                if (!json.WriteFile(json::filename.c_str()))
                {
                    print_msg_exit("failed to write to the json file " + json::filename);
                }
            };

        if (arg_opt::save_to_json_file) { json::build_prolog(json, domains.size()); json_write_file(); }

        std::mutex json_mutex;
        std::mutex csv_mutex;

        std::uint64_t d_total = domains.size(), d_t_ctr(0);

        std::thread update_domain_fp_ctr
        (
            helper::update_title_realtime<std::uint64_t>, "[HTTP-Basma] -> Progress: ", std::ref(d_t_ctr), std::ref(d_total)
        );
        update_domain_fp_ctr.detach();

        std::cout << std::endl
            << rang::fg::green << "+" << rang::fg::reset << " Retreiving fingerprints for " << domains.size() << " domains" << std::endl << std::endl;

        std::cout << rang::fg::red << "  S" << rang::fg::reset << "tarted on : " << helper::get_date() << " " << helper::get_time() << std::endl << std::endl;

        std::cout << rang::fg::green << "  P"<< rang::fg::reset << "robing in " << (arg_opt::scan_file_in_parallel ? "parallel" : "sequence") << "...";

        std::atomic<std::size_t> row_idx(0);

        std::visit([&](auto&& policy) {

            std::for_each(policy, domains.begin(), domains.end(), [&](const t::domain_tuple& domain)
                {
                    std::size_t curr_row_idx = row_idx.fetch_add(1, std::memory_order_relaxed);

                    std::vector<probe_info::pinfo> rinfo = {};
                    t::fp_map fingerpints = request::send_probes_get_fingerprint(domain, &rinfo);

                    if (arg_opt::save_to_json_file)
                    {
                        std::lock_guard<std::mutex> lock(json_mutex);
                        json::build_domain_payload(json, curr_row_idx, rinfo, fingerpints, domain);
                        json_write_file();
                    }

                    if (arg_opt::save_to_csv_file)
                    {
                        std::lock_guard<std::mutex> lock(csv_mutex);
                        csv::write_data_to_file(csvh, curr_row_idx, rinfo, fingerpints, domain);
                    }

                    d_t_ctr++;
                });

            }, exec_policy);

        std::cout << std::endl << std::endl;
        std::cout << rang::fg::red << "  F" << rang::fg::reset << "inished on: " << helper::get_date() << " " << helper::get_time() << std::endl;

        if (arg_opt::save_to_json_file)
        {
            json::write_epilog(json);
            json_write_file();
        }
    }

    if (arg_opt::file_opt_set)
    {
        if (!arg_opt::save_to_csv_file and !arg_opt::save_to_json_file)
        {
            print_msg_exit("with the --file/-f option, you have to pass either of the options -c or -j");
        }
    }

    return 0;
}

template <typename T, char size>
T
response::fnv1a_hash(const std::string& hdata)
{
    static_assert
        (
            (size == 'f' or size == 'h'),
            "the second argument of the fnv1a_hash() function template must be either 'h' or 'f'"
        );

    static_assert
        (
            (std::is_same_v<T, std::uint16_t> or std::is_same_v<T, std::uint32_t>),
            "for the fnv1a_hash() template, the first argument is a std::uint16_t when the second is 'h', and a std::uint32_t when the second is 'f'"
        );

    std::uint32_t hash_v = 0x811c9dc5; // offset basis

    for (std::size_t i = 0; i < hdata.size(); ++i)
    {
        hash_v ^= hdata[i];
        hash_v *= 0x01000193; // prime
        hash_v &= 0xffffffff;
    }
    if (size == 'h')
    {
        return static_cast<std::uint16_t>((hash_v >> 16) & 0xFFFF);
    }
    if (size == 'f')
    {
        return hash_v;
    }
}

std::string
response::content_length::encode_length(const std::uint32_t& length)
{
    if (length == 0)
    {
        return "0";
    }
    else if (length == 1)
    {
        return "1";
    }
    else if (length > 1)
    {
        return "2";
    }
    else
    {
        // should never reach here
        return "f";
    }
}

std::string
response::content_length::encode_content_length_name(const std::string& cl_name)
{
    if (cl_name == "Content-Length")
    {
        return "2";
    }
    else if (cl_name == "content-length")
    {
        return "3";
    }
    else if (cl_name == "Content-length")
    {
        return "4";
    }
    else if (cl_name == "content-Length")
    {
        return "5";
    }
    else if (helper::lowercase_str_out(cl_name) == "content-length")
    {
        return "6";
    }
    else
    {
        return "f"; // you shound't get here!
    }
}

std::string
response::content_length::encode_transfer_encoding_name(const std::string& te_name)
{
    if (te_name == "Transfer-Encoding")
    {
        return "7";
    }
    else if (te_name == "transfer-encoding")
    {
        return "8";
    }
    else if (te_name == "Transfer-encoding")
    {
        return "9";
    }
    else if (te_name == "transfer-Encoding")
    {
        return "a";
    }
    else if (helper::lowercase_str_out(te_name) == "transfer-encoding")
    {
        return "b";
    }
    else
    {
        // return 'e' instead of 'f' as in encode_content_length_name() to make it specific to TE
        return "e"; // you shound't get here!
    }
}

std::string
response::content_length::get_fingerprint_content_length(CkHttpResponse* resp)
{
    if (!response::chk_sl_validity(resp))
    {
        return "99";
    }

    using namespace response;

    if (resp->getHeaderField("content-length") == nullptr and (response::does_header_exist(resp, "transfer-encoding", "chunked", true) == -1))
    {
        CkBinData body_data;
        resp->GetBodyBd(body_data);

        if (body_data.getSize() > 0)
        {
            return "1" + encode_length(body_data.getSize());
        }
        else
        {
            return "00";
        }
    }
    else
    {
        if (resp->getHeaderField("content-length") != nullptr)
        {
            // get the header name as it is, verbatim, from the server response
            std::string cl_name = resp->headerName(response::does_header_exist(resp, "content-length"));

            return (encode_content_length_name(cl_name) + encode_length(resp->get_ContentLength()));
        }

        if (response::does_header_exist(resp, "transfer-encoding", "chunked", true) != -1)
        {
            /* accessing chunked response body using any of the CkHttpResponse methods,
               you get the original full body without the chunck labels. */

               // get the header name as it is, verbatim, from the server response
            std::string te_name = resp->headerName(response::does_header_exist(resp, "transfer-encoding"));

            CkBinData body_data; 
            resp->GetBodyBd(body_data);
            return encode_transfer_encoding_name(te_name) + encode_length(body_data.getSize());
        }
    }
}

// in case of the same header used multiple times with different values
// returns the header's index to get the header field name in its original form
// returns (-1) if header not found
int
response::does_header_exist(CkHttpResponse* resp, const std::string& header_n, const std::string& header_v, bool check_header_v)
{
    int headers_total = resp->get_NumHeaderFields();

    for (int i = 0; i < headers_total; ++i)
    {
        // headerName() is case-sensitive
        if (std::string(helper::lowercase_str_out(resp->headerName(i))) == header_n)
        {
            if (check_header_v)
            {
                // normalize value
                std::string header_value_l = helper::lowercase_str_out(resp->headerValue(i));

                if (header_value_l.find(header_v) != std::string::npos)
                {
                    return i;
                }
            }
            else
            {
                return i;
            }
        }
    }
    return -1;
}

std::string
response::status_line::get_fingerprint_status_code(CkHttpResponse* resp)
{
    std::string status_line = resp->statusLine();

    if (status_line.empty()) { status_line = response::status_line::resp_raw_deep; }

    // this intentionally treats "HTTP/1.1 302.1" as a valid Status Line
    std::regex regexp("^HTTP/\\d\\.\\d (\\d{3})", std::regex_constants::icase);
    std::smatch matches;

    if (std::regex_search(status_line, matches, regexp))
    {
        auto itr = response::status_line::status_code.find(std::stoi(matches[1].str()));

        if (itr != response::status_line::status_code.end())
        {
            auto idx = std::distance(response::status_line::status_code.begin(), itr);
            return std::format("{0:02x}", idx + 1);
        }
        else
        {
            // if status code is present but not in the map
            return "ff";
        }
    }
    else
    {
        return "00";
    }
}

std::string
response::status_line::get_fingerprint_http_version(CkHttpResponse* resp)
{
    std::string http_version = resp->statusLine(); // HTTP/1.1 200 OK

    if (http_version.empty()) { http_version = response::status_line::resp_raw_deep; }

    std::string http_name = {}; // HTTP (case-insensitive)
    char major_ver, minor_ver;

    // I tolerate what comes after the status code!
    std::regex regexp("^(HTTP)/(\\d)\\.(\\d)", std::regex_constants::icase);
    std::smatch matches;

    if (std::regex_search(http_version, matches, regexp))
    {
        http_name = matches[1];
        major_ver = matches[2].str().back();
        minor_ver = matches[3].str().back();
    }
    else
    {
        return "00";
    }

    char fp_n = {};

    if (http_name == "HTTP")
    {
        fp_n = '1';
    }
    else if (http_name == "http")
    {
        fp_n = '2';
    }
    else if (http_name == "Http")
    {
        fp_n = '3';
    }
    else
    {
        // other casing
        fp_n = '4';
    }

    char fp_v = {};

    if (major_ver == '0' and minor_ver == '8')       // = 0.8
    {
        fp_v = '1';
    }
    else if (major_ver == '0' and minor_ver == '9')  // = 0.9
    {
        fp_v = '2';
    }
    else if (major_ver == '1' and minor_ver == '0')  // = 1.0
    {
        fp_v = '3';
    }
    else if (major_ver == '1' and minor_ver == '1')  // = 1.1
    {
        fp_v = '4';
    }
    else if (major_ver >= '2' and minor_ver >= '0')  // >= 2.0
    {
        fp_v = '7';
    }
    else if (major_ver == '1' and minor_ver > '1')   // = 1.(> 1)
    {
        fp_v = '8';
    }
    else if (major_ver == '0' and minor_ver < '8')   // = 0.(< 8)
    {
        fp_v = '9';
    }
    else
    {
        // it should never reach this case
        fp_v = 'f';
    }

    return std::string(1, fp_n) + fp_v;
}

std::string
response::status_line::get_fingerprint_http_reason(CkHttpResponse* resp, const std::string& del_str)
{
    std::string status_line = resp->statusLine();

    if (status_line.empty()) { status_line = response::status_line::resp_raw_deep; }

    /*
       To obtain the HTTP reason, there must be a successful match between the HTTP version and
       the status code. Deliberately allowing flexibility in parsing the reason phrase is necessary,
       as any discrepancies in the status line that do not adhere entirely to the standard will
       result in subsequent checks being rejected during probing.
    */

    /*
        HTTP/1.1 400Potato\ranother potato\r\n -> the reason phrase would be "potato"

        The statusText() method retrieves the reason phrase beginning from the first space
        after the status code. It continues searching, even if the status line ends with a
        newline, until it encounters a carriage return followed by a newline sequence.
        And, the same goes for the status code.
    */

    std::regex regexp("^HTTP/\\d\\.\\d \\d{3}([^]*)", std::regex_constants::icase);
    std::smatch matches;

    std::string reason = {};

    if (std::regex_search(status_line, matches, regexp))
    {
        reason = matches[1];

        if (reason.empty())
        {
            return "0000";
        }
        else
        {
            // if the reason phrase contains only chars from the std restricted achars, then proceed
            if (reason.find_first_not_of(response::status_line::achars) == std::string::npos)
            {
                // find 1st occurence of a SP
                if (auto it = reason.find_first_of(" "); it != std::string::npos)
                {
                    reason = reason.substr(it + 1);
                    if (reason.empty())
                    {
                        return "0000";
                    }
                }
                else
                {
                    // this is not valid "HTTP/1.1 200Potato", but I treat the reason as empty()
                    return "0000";
                }

                // delete the context-dependent variable part from the reason phrase (random resource & verb)
                helper::del_sstr(reason, del_str);
                // get the hash
                return std::format("{0:04x}", response::fnv1a_hash<std::uint16_t, 'h'>(reason));
            }
            // contains disallowed chars
            else
            {
                // to get to this block, it means, the reason is not empty()

                // tag it and don't hash it
                // the probability of collision with a valid hash is very minimal, considering the uniqueness
                // of the tags, 0001 and 0002 (no match with a million hash)

                // tag them differently
                // if the status code is followed by a space
                std::regex regexp("^HTTP/\\d\\.\\d \\d{3} ", std::regex_constants::icase);
                if (std::regex_search(status_line, regexp))
                {
                    return "0001";
                }
                else
                {
                    return "0002";
                }
            }
        }
    }
    else
    {
        return "0000";
    }
}

std::string
response::status_line::get_fingerprint(CkHttpResponse* resp, const std::string& del_str)
{
    return response::status_line::get_fingerprint_http_version(resp) +
           response::status_line::get_fingerprint_status_code(resp) +
           response::status_line::get_fingerprint_http_reason(resp, del_str);
}

std::string
response::status_line::get_resp_deep_log(CkHttp& http)
{
    CkXml logx;
    if (logx.LoadXml(http.lastErrorXml()))
    {
        std::string xml_presp = "SynchronousRequest|fullRequest|a_synchronousRequest|fullHttpRequest|readResponseHeader|responseHdr";
        std::string resp_raw = logx.getChildContent(xml_presp.c_str());

        if (resp_raw.data() != nullptr)
        {
            return resp_raw;
        }
        else
        {
            return "";
        }
    }
    else
    {
        return "";
    }
}

void
response::status_line::set_resp_deep_log(CkHttpResponse* resp, CkHttp& http)
{
    if (std::string(resp->statusLine()).empty())
    {
        response::status_line::resp_raw_deep = response::status_line::get_resp_deep_log(http);
    }
    else
    {
        response::status_line::resp_raw_deep = {};
    }
}

bool
response::status_line::is_valid(CkHttpResponse* resp)
{
    /*
         RFC 7231 (status-line = HTTP-version SP status-code SP reason-phrase CRLF)
         the method statusLine() will stop reading at the first \r\n.
         for example, HTTP/1.1 200 OK\nContent-Length: 0\n\n is not a valid HTTP server
         response, and the method statusLine() returns an empty string.

         The issue here is that, in a case like this, the code won't be even able to capture
         the HTTP version, and the status code for fp'ing.
         To solve this issue, I get the server response raw, after the synch HTTP req with
         get_resp_deep_log().
     */

    std::string status_line = resp->statusLine();

    // double check it is not "invalid"/empty
    if (status_line.empty()) { status_line = response::status_line::resp_raw_deep; }

    std::smatch matches;
    std::regex sl_rgx("^HTTP/\\d\\.\\d \\d{3}([^]*)", std::regex_constants::icase);

    if (!status_line.empty() and std::regex_search(status_line, matches, sl_rgx))
    {
        std::string reason = matches[1];

        // if the reason phrase contains any characters not specified in achars, then it does 
        // not conform to the standard.
        if (reason.find_first_not_of(response::status_line::achars) != std::string::npos)
        {
            return false;
        }
        else
        {
            return true;
        }
    }
    if (!status_line.empty() and !std::regex_search(status_line, matches, sl_rgx))
    {
        return false;
    }
    if (status_line.empty()) // simply, "valid"/empty
    {
        return true;
    }
}

bool
response::chk_sl_validity(CkHttpResponse* resp)
{
    // the is_valid func already checks the resp_raw_deep in case the SL is "invalid" empty
    if (response::chk_slv and response::status_line::is_valid(resp))
    {
        return true;
    }
    else
    {
        return false;
    }
}

// not used in the fp (for reference with the csv and json output)
std::string
response::get_fingerprint_nb_headers(CkHttpResponse* resp)
{
    const int nb_headers = resp->get_NumHeaderFields();

    if (nb_headers >= 255)
    {
        return "ff";
    }
    else
    {
        return std::format("{0:02x}", nb_headers);
    }
}

std::string
response::get_fingerprint_headers(CkHttpResponse* resp, bool lower_case, bool sort, bool unique)
{
    if (!response::chk_sl_validity(resp))
    {
        return std::string(8, '9');
    }

    auto hdr_val_exist = [&resp](const int hdr_idx, const std::string& hdr_name, const std::string& hdr_value) -> bool
        {
            if (std::string(helper::lowercase_str_out(resp->headerName(hdr_idx))) == hdr_name)
            {
                // normalize value
                std::string header_value_l = helper::lowercase_str_out(resp->headerValue(hdr_idx));

                if (header_value_l.find(hdr_value) != std::string::npos)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        };


    const int nb_of_headers = resp->get_NumHeaderFields();

    if (nb_of_headers > 0)
    {
        std::vector<std::string> headers_vec = {};

        for (int i = 0; i < nb_of_headers; ++i)
        {
            const std::string h_name = resp->headerName(i);

            if (hdr_val_exist(i, "connection", "keep-alive")) { continue; }
            if (hdr_val_exist(i, "connection", "close")) { continue; }
            if (helper::lowercase_str_out(h_name).starts_with("x-")) { continue; }

            if (unique)
            {
                if (!helper::is_str_in_vec(headers_vec, h_name))
                {
                    headers_vec.push_back((lower_case ? helper::lowercase_str_out(h_name) : h_name));
                }
            }
            else
            {
                headers_vec.push_back((lower_case ? helper::lowercase_str_out(h_name) : h_name));
            }
        }
        if (sort) { std::sort(headers_vec.begin(), headers_vec.end()); }

        std::string all_headers_n = {};

        // concatentate all headers
        std::for_each(headers_vec.begin(), headers_vec.end(), [&](const std::string& i) { all_headers_n += i; });

        return std::format("{0:08x}", response::fnv1a_hash<std::uint32_t, 'f'>(all_headers_n));
    }
    else
    {
        return std::string(8, '0');
    }
}

// this function always checks the complete accept_encoding_v array for a match, even in case of exercising 
// accept_encoding_v_less array. This is because the server might respond with an encoding that actually exists
// in the larger array accept_encoding_v.
std::string
response::get_fingerprint_content_encoding(CkHttpResponse* resp)
{
    if (!response::chk_sl_validity(resp))
    {
        return "99";
    }

    if (resp->getHeaderField("content-encoding") == nullptr)
    {
        return "00";
    }
    else
    {
        std::bitset<8> ce_fp_bit; ce_fp_bit.reset();

        /*
            Content-Encoding: gzip, br, compress, x-gzip
            Content-Encoding: deflate

            [0-3]: (max. 15/0x0f) idx into ae_array
                    if idx>13 -> [0-3] = 15/0x0f

            [4]  : '1' if value contains empty sequence, otherwise '0'

            [5-7]: (max. 07/0x07) nb of additional compression alg.
                    if nb>3 -> nb=7 ( it has to be >3, otherwise,
                    a collision happens when it is
                    99->10011001= idx(9) | SP(1)+(4)=9 )
        */

        const int headers_total = resp->get_NumHeaderFields();

        // the vector isn't sorted because the order matters; it has to be in the order received from the server
        std::vector<std::string> ce_vec = {};

        for (int i = 0; i < headers_total; ++i)
        {
            // headerName() is case-sensitive
            if (std::string(helper::lowercase_str_out(resp->headerName(i))) == "content-encoding")
            {
                std::string ce_v_norm(helper::lowercase_str_out(resp->headerValue(i)));

                if (ce_v_norm.empty()) { ce_vec.push_back(""); }

                ce_v_norm.erase(std::remove(ce_v_norm.begin(), ce_v_norm.end(), ' '), ce_v_norm.end());

                std::istringstream ss_ce_vn(ce_v_norm); std::string comp_alg = {};

                while (getline(ss_ce_vn, comp_alg, ',')) { ce_vec.push_back(comp_alg); }
            }
        }

        std::bitset<4> ce_alg_idx; ce_alg_idx.reset();
        std::bitset<3> ce_alg_nb; ce_alg_nb.reset();

        if (!ce_vec.empty())
        {
            // retreive the idx for the first value only
            auto it = std::find(std::begin(request::header::accept_encoding_v), std::end(request::header::accept_encoding_v), ce_vec.at(0));

            if (it != std::end(request::header::accept_encoding_v))
            {
                auto idx = std::distance(std::begin(request::header::accept_encoding_v), it) + 1;
                ce_alg_idx = idx;
            }
            else
            {
                // if it is not in the request::header::accept_encoding_v.
                // empty values are counted 
                ce_alg_idx = 15;
            }

            // > 1 & -1 to account only for the additional compression algs
            if (ce_vec.size() > 1)
            {
                if ((ce_vec.size() - 1) > 3)
                {
                    ce_alg_nb = 7;
                }
                else
                {
                    ce_alg_nb = ce_vec.size() - 1;
                }
            }
            else
            {
                ce_alg_nb = 0;
            }

            ce_fp_bit.set(0, ce_alg_idx[0]);
            ce_fp_bit.set(1, ce_alg_idx[1]);
            ce_fp_bit.set(2, ce_alg_idx[2]);
            ce_fp_bit.set(3, ce_alg_idx[3]);

            ce_fp_bit.set(4, std::any_of(ce_vec.begin(), ce_vec.end(), [](const std::string& i) { return i.empty(); }));

            ce_fp_bit.set(5, ce_alg_nb[0]);
            ce_fp_bit.set(6, ce_alg_nb[1]);
            ce_fp_bit.set(7, ce_alg_nb[2]);

            return std::format("{0:02x}", ce_fp_bit.to_ulong());
        }
    }
}

bool
response::allow_header::get_fingerprint_allow_header(CkHttpResponse* resp, const std::string& header_k, response::allow_header::fp_len_hval& fp_struct)
{
    // just return immediately in case of invalid response
    if (!response::chk_sl_validity(resp))
    {
        return false;
    }
    // getHeaderField() is case insensitive
    if (resp->getHeaderField(header_k.c_str()) == nullptr)
    {
        // the structure fp_struct will hold the default values
        return false;
    }
    else
    {
        const int headers_total = resp->get_NumHeaderFields();

        std::vector<std::string> allow_verbs_vec = {};

        // holds all the values of the "allow" header, concatenated verbatim.
        // in case of "Allow" or "Access-Control-Allow-Methods" used more than once in the same 
        // server response, the order is standardized by sorting them first (the whole header value), before hashing
        std::vector<std::string> allow_v_original_vec = {};

        for (int i = 0; i < headers_total; ++i)
        {
            // headerName() is case-sensitive
            if (std::string(helper::lowercase_str_out(resp->headerName(i))) == header_k.c_str())
            {
                std::string allow_v(resp->headerValue(i));

                allow_v_original_vec.push_back(allow_v);

                allow_v.erase(std::remove(allow_v.begin(), allow_v.end(), ' '), allow_v.end());

                std::istringstream ss_allow_v(allow_v);

                std::string verb = {};
                while (getline(ss_allow_v, verb, ',')) { allow_verbs_vec.push_back(verb); }
            }
        }
        // sort in ascending order
        std::sort(allow_v_original_vec.begin(), allow_v_original_vec.end());

        std::string all_allow_values = {};

        // the reason for taking the original values verbatim is so that I can capture the minor details such as, no spaces between
        // the comma separated methods, different spacing,...
        // concatentate all values
        std::for_each(allow_v_original_vec.begin(), allow_v_original_vec.end(), [&](const std::string& i) { all_allow_values += i; });

        std::string allow_size_fp = {};

        /*
           fp = <bit_set_encodedlength><fnv1a_hash_allow_values>

                   [1 1 1 1 1]  [1]   [1]   [1]
                       size      p     ac    a
                      [0-31]    0|1    0|1   0|1
        */

        if (header_k == "allow")
        {
            fp_struct.is_allow = true; // getting here implies that the header is set/used
            fp_struct.allow_nb = allow_verbs_vec.size();
            fp_struct.allow_values = all_allow_values;

            return true;
        }
        else if (header_k == "access-control-allow-methods")
        {
            fp_struct.is_allow_acam = true; // getting here implies that the header is set/used
            fp_struct.allow_acam_nb = allow_verbs_vec.size();
            fp_struct.allow_acam_values = all_allow_values;

            return true;
        }
        else if (header_k == "public")
        {
            fp_struct.is_public = true; // getting here implies that the header is set/used
            fp_struct.public_nb = allow_verbs_vec.size();
            fp_struct.public_values = all_allow_values;

            return true;
        }
        else
        {
            return false;
        }
    }
}

std::string
response::get_fingerprint_strict_transport_security_header(CkHttpResponse* resp)
{
    if (!response::chk_sl_validity(resp))
    {
        return "99";
    }
    // getHeaderField() is case insensitive (STS)
    if (resp->getHeaderField("strict-transport-security") == nullptr)
    {
        return "00";
    }
    else
    {
        std::bitset<7> sts_options; sts_options.reset();

        /*
            Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

            0    exist(max-age)
            1    if(max-age == 0)
            2	 if(max-age).empty()
            3    exist(includeSubDomains)
            4    exist(preload)
            5    if(more than three fields/attributes)
            6    if(attribute is empty. for ex., ;;;)
        */

        const int headers_total = resp->get_NumHeaderFields();
        std::vector<std::string> sts_attribs_vec = {};

        for (int i = 0; i < headers_total; ++i)
        {
            // headerName() is case-sensitive
            if (std::string(helper::lowercase_str_out(resp->headerName(i))) == "strict-transport-security")
            {
                // The method "getHeaderFieldAttr" picks only the first occurence and doesn't advance the ptr, 
                // and there's no other Ck method that provides field attribute access at the index level!
                // std::string max_age = resp->getHeaderFieldAttr("strict-transport-security", "max-age");

                std::string sts_v(helper::lowercase_str_out(resp->headerValue(i)));
                sts_v.erase(std::remove(sts_v.begin(), sts_v.end(), ' '), sts_v.end());

                std::istringstream ss_sts_v(sts_v);
                std::string attrib = {};

                while (getline(ss_sts_v, attrib, ';'))
                {
                    // It goes through all the occurrences of the "strict-transport-security" header, checking every
                    // instance of the "max-age" attribute that satisfies the condition this fingerprint checks for

                    if (attrib.find("max-age=") != std::string::npos)
                    {
                        sts_options.set(0);

                        if (std::regex_search(attrib, std::regex("^max-age=0+$"))) { sts_options.set(1); }
                        if (attrib == "max-age=") { sts_options.set(2); }
                    }
                    // If there's at least one empty attribute (max-age=253764;<empty>;<empty>;)
                    if (attrib.empty()) { sts_options.set(6); }

                    sts_attribs_vec.push_back(attrib);
                }
            }

            if (helper::is_str_in_vec(sts_attribs_vec, "includesubdomains")) { sts_options.set(3); }
            if (helper::is_str_in_vec(sts_attribs_vec, "preload")) { sts_options.set(4); }
            // the only valid attributes are (max-age, includeSubDomains, preload)
            if (sts_attribs_vec.size() > 3) { sts_options.set(5); }
        }

        std::string sts_lyzer = std::format("{0:02x}", sts_options.to_ulong());

        if (sts_lyzer == "00") { return "ff"; }
        else { return sts_lyzer; }
    }
}

t::conx_state_tuple
response::get_fingerprint_conx_hdr(CkHttpResponse* resp)
{
    if (!response::chk_sl_validity(resp))
    {
        return std::make_tuple(false, false);
    }

    bool keep_alive = false, close = false;

    // government.bg -> p1/p2/p3/p4/p5/p6/!p7a: (Connection: keep-alive, close)
    // alice.it      -> p5: Connection: keep-alive, close
    // islamweb.net  -> p4:(Connection: keep-alive AND Connection: close)

    if (response::does_header_exist(resp, "connection", "keep-alive", true) != -1)
    {
        keep_alive = true;
    }
    if (response::does_header_exist(resp, "connection", "close", true) != -1)
    {
        close = true;
    }

    return std::make_tuple(keep_alive, close);
}

void
probe_info::set_prologue(probe_info::pinfo* rinfo, const std::string& type)
{
    rinfo->date = helper::get_date();
    rinfo->time = helper::get_time();
    rinfo->req_type = type;
}

void
probe_info::set_payload(probe_info::pinfo* rinfo, CkHttpResponse* resp)
{
    rinfo->req_status = "success";
    rinfo->resp_status_line = resp->statusLine();
    rinfo->nb_headers = resp->get_NumHeaderFields();
    if (arg_opt::save_resp_headers)
    {
        rinfo->resp_headers = resp->header();
    }
    else
    {
        rinfo->resp_headers = {};
    }
}

void
probe_info::set_fingerprint(probe_info::pinfo* rinfo, const std::string& fp_sl,
    const std::string& fp_c_len, const std::string& fp_all,
    const t::conx_state_tuple& conx_s)
{
    rinfo->status_line_fp = fp_sl;
    rinfo->content_length_fp = fp_c_len;
    rinfo->fingerprint = fp_all;
    rinfo->conx_state = conx_s;
}

void
probe_info::set_failure(probe_info::pinfo* rinfo, const std::string& ifp)
{
    rinfo->req_status = "failure";
    rinfo->fingerprint = ifp;
    rinfo->response_headers_fp = std::string(8, '0');
}

void
request::wait(void)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(arg_opt::sleep));
}

t::fp_map
request::send_probes_get_fingerprint(const t::domain_tuple& domain, std::vector<probe_info::pinfo>* rinfo)
{
    std::mutex probing_mutex;
    std::lock_guard<std::mutex> probing(probing_mutex);

    std::string p1, p2, p3, p4, p5, p6f, p6l, p7a, keep_alive_all_fp, conx_close_all_fp = {};

    std::bitset<5> keep_alive, conx_close; keep_alive.reset(), conx_close.reset();

    auto set_conx = [&](const probe_info::pinfo& prinfo, const std::size_t& i) -> void
        {
            if (std::get<0>(prinfo.conx_state)) { keep_alive.set(i); }
            if (std::get<1>(prinfo.conx_state)) { conx_close.set(i); }
        };

    probe_info::pinfo prinfo = {};

    p1 = request::send_get_req_valid_probe_1(domain, &prinfo);
    rinfo->push_back(prinfo); prinfo = {}; request::wait();

    p2 = request::send_get_req_invalid_ver_nb_probe_2(domain, &prinfo);
    set_conx(prinfo, 0);
    rinfo->push_back(prinfo); prinfo = {}; request::wait();

    p3 = request::send_get_req_rnd_resource_probe_3(domain, &prinfo);
    set_conx(prinfo, 1);
    rinfo->push_back(prinfo); prinfo = {}; request::wait();

    p4 = request::send_get_req_rnd_verb_probe_4(domain, &prinfo);
    set_conx(prinfo, 2);
    rinfo->push_back(prinfo); prinfo = {}; request::wait();

    p5 = request::send_get_req_lowercase_verb_probe_5(domain, &prinfo);
    set_conx(prinfo, 3);
    rinfo->push_back(prinfo); prinfo = {}; request::wait();

    p6f = request::send_get_req_accept_encoding_probe_6x(domain, false, &prinfo);
    rinfo->push_back(prinfo); prinfo = {}; request::wait();

    p6l = request::send_get_req_accept_encoding_probe_6x(domain, true, &prinfo);
    rinfo->push_back(prinfo); prinfo = {}; request::wait();

    p7a = request::send_options_req_probe_7x(domain, &prinfo);
    set_conx(prinfo, 4);
    rinfo->push_back(prinfo); prinfo = {}; request::wait();

    keep_alive_all_fp = std::format("{0:02x}", keep_alive.to_ulong());
    conx_close_all_fp = std::format("{0:02x}", conx_close.to_ulong());

    std::string fp = (p1 + p2 + p3 + p4 + p5 + p6f + p6l + p7a + keep_alive_all_fp + conx_close_all_fp);

    t::fp_map fp_all = {};

    fp_all[fingerprint::version::verbosus] = fingerprint::get_verbosus(fp); // 38b
    fp_all[fingerprint::version::pacto] = fingerprint::get_pacto(fp);    // 16b

    return fp_all;
}

CkHttpResponse*
request::synchronous_http_request(CkHttp& http, CkHttpRequest& http_req, const t::domain_tuple& domain)
{
    // this feature is supported in a pre-release version of the CkHttp class shared by Chilkat privately
    http.put_UncommonOptions("no-zero-content-length-header");

    return http.SynchronousRequest
    (
        std::get<t::d::domain>(domain).c_str(),
        std::get<t::d::port>(domain),
        std::get<t::d::ssl>(domain), http_req
    );
}

std::string
request::send_get_req_valid_probe_1(const t::domain_tuple& domain, probe_info::pinfo* rinfo)
{
    CkHttpRequest http_req;
    CkHttp http;
    request::setup_http_connection(http, http_req, std::get<t::d::path>(domain));
    http_req.put_HttpVerb("GET");
    http_req.put_HttpVersion("1.1");

    if (rinfo) { probe_info::set_prologue(rinfo, request::stype::p1_get_normal); }

    CkHttpResponse* resp = request::synchronous_http_request(http, http_req, domain);

    if (!http.get_LastMethodSuccess())
    {
        if (rinfo) { probe_info::set_failure(rinfo, std::string(10, '0')); }

        return std::string(10, '0');
    }
    else
    {
        if (rinfo) { probe_info::set_payload(rinfo, resp); }

        response::status_line::set_resp_deep_log(resp, http);

        std::string fp_status_line = response::status_line::get_fingerprint(resp);

        std::string fp_sts = response::get_fingerprint_strict_transport_security_header(resp);
        std::string fp_c_len = response::content_length::get_fingerprint_content_length(resp);

        std::string fp = fp_status_line + fp_sts;

        if (rinfo)
        {
            rinfo->response_headers_fp = response::get_fingerprint_headers(resp, false, true, true);
            probe_info::set_fingerprint(rinfo, fp_status_line, fp_c_len, fp, response::get_fingerprint_conx_hdr(resp));
        }
        http.CloseAllConnections();
        delete resp;
        return fp;
    }
}

std::string
request::send_get_req_invalid_ver_nb_probe_2(const t::domain_tuple& domain, probe_info::pinfo* rinfo)
{
    CkHttpRequest http_req;
    CkHttp http;
    request::setup_http_connection(http, http_req, std::get<t::d::path>(domain));
    http_req.put_HttpVerb("GET");
    http_req.put_HttpVersion("4.2");

    if (rinfo) { probe_info::set_prologue(rinfo, request::stype::p2_get_invalid_ver_nb); }

    CkHttpResponse* resp = request::synchronous_http_request(http, http_req, domain);

    if (!http.get_LastMethodSuccess())
    {
        if (rinfo) { probe_info::set_failure(rinfo, std::string(10, '0')); }

        return std::string(10, '0');
    }
    else
    {
        if (rinfo) { probe_info::set_payload(rinfo, resp); }

        response::status_line::set_resp_deep_log(resp, http);

        std::string fp_status_line = response::status_line::get_fingerprint(resp);
        std::string fp_content_length = response::content_length::get_fingerprint_content_length(resp);

        std::string fp = fp_status_line + fp_content_length;

        if (rinfo)
        {
            rinfo->response_headers_fp = response::get_fingerprint_headers(resp, false, true, true);
            probe_info::set_fingerprint(rinfo, fp_status_line, fp_content_length, fp, response::get_fingerprint_conx_hdr(resp));
        }
        http.CloseAllConnections();
        delete resp;
        return fp;
    }
}

std::string
request::send_get_req_rnd_resource_probe_3(const t::domain_tuple& domain, probe_info::pinfo* rinfo)
{
    CkHttpRequest http_req;
    CkHttp http;
    request::setup_http_connection(http, http_req, std::get<t::d::path>(domain));
    http_req.put_HttpVerb("GET");
    http_req.put_HttpVersion("1.1");

    CkPrng rnd_uri;
    const std::string ruri = rnd_uri.randomString(16, true, true, true);
    http_req.put_Path(ruri.c_str());

    if (rinfo) { probe_info::set_prologue(rinfo, request::stype::p3_get_rnd_resource); }

    CkHttpResponse* resp = request::synchronous_http_request(http, http_req, domain);

    if (!http.get_LastMethodSuccess())
    {
        if (rinfo) { probe_info::set_failure(rinfo, std::string(10, '0')); }

        return std::string(10, '0');
    }
    else
    {
        if (rinfo) { probe_info::set_payload(rinfo, resp); }

        response::status_line::set_resp_deep_log(resp, http);

        std::string fp_status_line = response::status_line::get_fingerprint(resp, ruri);
        std::string fp_content_length = response::content_length::get_fingerprint_content_length(resp);

        std::string fp = fp_status_line + fp_content_length;

        if (rinfo)
        {
            rinfo->response_headers_fp = response::get_fingerprint_headers(resp, false, true, true);
            probe_info::set_fingerprint(rinfo, fp_status_line, fp_content_length, fp, response::get_fingerprint_conx_hdr(resp));
        }
        http.CloseAllConnections();
        delete resp;
        return fp;
    }
}

std::string
request::send_get_req_rnd_verb_probe_4(const t::domain_tuple& domain, probe_info::pinfo* rinfo)
{
    CkHttpRequest http_req;
    CkHttp http;

    request::setup_http_connection(http, http_req, std::get<t::d::path>(domain));

    CkPrng rnd_verb;
    const std::string rverb = rnd_verb.randomString(10, false, false, true);
    http_req.put_HttpVerb(rverb.c_str());
    http_req.put_HttpVersion("1.1");

    if (rinfo) { probe_info::set_prologue(rinfo, request::stype::p4_get_rnd_verb); }

    CkHttpResponse* resp = request::synchronous_http_request(http, http_req, domain);

    if (!http.get_LastMethodSuccess())
    {
        if (rinfo) { probe_info::set_failure(rinfo, std::string(10, '0')); }

        return std::string(10, '0');
    }
    else
    {
        if (rinfo) { probe_info::set_payload(rinfo, resp); }

        response::status_line::set_resp_deep_log(resp, http);

        std::string fp_status_line = response::status_line::get_fingerprint(resp, rverb);
        std::string fp_content_length = response::content_length::get_fingerprint_content_length(resp);

        std::string fp = fp_status_line + fp_content_length;

        if (rinfo)
        {
            rinfo->response_headers_fp = response::get_fingerprint_headers(resp, false, true, true);
            probe_info::set_fingerprint(rinfo, fp_status_line, fp_content_length, fp, response::get_fingerprint_conx_hdr(resp));
        }
        http.CloseAllConnections();
        delete resp;
        return fp;
    }
}

std::string
request::send_get_req_lowercase_verb_probe_5(const t::domain_tuple& domain, probe_info::pinfo* rinfo)
{
    CkHttpRequest http_req;
    CkHttp http;
    request::setup_http_connection(http, http_req, std::get<t::d::path>(domain));

    http_req.put_HttpVerb("get");
    http_req.put_HttpVersion("1.1");

    if (rinfo) { probe_info::set_prologue(rinfo, request::stype::p5_get_lowercase_verb); }

    CkHttpResponse* resp = request::synchronous_http_request(http, http_req, domain);

    if (!http.get_LastMethodSuccess())
    {
        if (rinfo) { probe_info::set_failure(rinfo, std::string(10, '0')); }

        return std::string(10, '0');
    }
    else
    {
        if (rinfo) { probe_info::set_payload(rinfo, resp); }

        response::status_line::set_resp_deep_log(resp, http);

        std::string fp_status_line = response::status_line::get_fingerprint(resp);
        std::string fp_content_length = response::content_length::get_fingerprint_content_length(resp);

        std::string fp = fp_status_line + fp_content_length;

        if (rinfo)
        {
            rinfo->response_headers_fp = response::get_fingerprint_headers(resp, false, true, true);
            probe_info::set_fingerprint(rinfo, fp_status_line, fp_content_length, fp, response::get_fingerprint_conx_hdr(resp));
        }
        http.CloseAllConnections();
        delete resp;
        return fp;
    }
}

std::string
request::send_get_req_accept_encoding_probe_6x(const t::domain_tuple& domain, bool less, probe_info::pinfo* rinfo)
{
    CkHttpRequest http_req;
    CkHttp http;
    request::setup_http_connection(http, http_req, std::get<t::d::path>(domain));

    http_req.put_HttpVerb("GET");
    http_req.put_HttpVersion("1.1");

    std::ostringstream ae_h_v = {};

    // build Accept-Encoding header list of values from the arrays defined in 
    // request::header::accept_encoding_v OR request::header::accept_encoding_v_less

    auto build_ae_h_v = [&ae_h_v](const auto& ae_array) -> void
        {
            for (std::size_t i = 0; i < ae_array.size(); ++i)
            {
                ae_h_v << ae_array.at(i) << (i != ae_array.size() - 1 ? ", " : "");
            }
        };

    if (!less)
    {
        build_ae_h_v(request::header::accept_encoding_v);
    }
    else
    {
        build_ae_h_v(request::header::accept_encoding_v_less);
    }

    http_req.AddHeader("Accept-Encoding", ae_h_v.str().c_str());

    if (rinfo)
    {
        probe_info::set_prologue(rinfo, (less) ? request::stype::p6_get_accept_encoding_less : request::stype::p6_get_accept_encoding_full);
    }

    CkHttpResponse* resp = request::synchronous_http_request(http, http_req, domain);

    if (!http.get_LastMethodSuccess())
    {
        if (rinfo) { probe_info::set_failure(rinfo, "00"); }

        return "00"; // fp_content_encoding only
    }
    else
    {
        if (rinfo) { probe_info::set_payload(rinfo, resp); }

        response::status_line::set_resp_deep_log(resp, http);

        std::string fp_content_encoding = response::get_fingerprint_content_encoding(resp);
        std::string fp_status_line = response::status_line::get_fingerprint(resp);
        std::string fp_c_len = response::content_length::get_fingerprint_content_length(resp);

        // no need to account for the response::status_line::get_fingerprint() since the request is pretty 
        // much the same as p1, and results prove the similarity            

        if (rinfo)
        {
            rinfo->response_headers_fp = response::get_fingerprint_headers(resp, false, true, true);
            probe_info::set_fingerprint(rinfo, fp_status_line, fp_c_len, fp_content_encoding, response::get_fingerprint_conx_hdr(resp));
        }
        http.CloseAllConnections();
        delete resp;
        return fp_content_encoding;
    }
}

std::string
request::send_options_req_probe_7x(const t::domain_tuple& domain, probe_info::pinfo* rinfo)
{
    CkHttpRequest http_req;
    CkHttp http;
    request::setup_http_connection(http, http_req, std::get<t::d::path>(domain));

    http_req.put_HttpVerb("OPTIONS");
    http_req.put_HttpVersion("1.1");

    if (rinfo) { probe_info::set_prologue(rinfo, request::stype::p7_options_allow_hdr); }

    CkHttpResponse* resp = request::synchronous_http_request(http, http_req, domain);

    if (!http.get_LastMethodSuccess())
    {
        if (rinfo) { probe_info::set_failure(rinfo, std::string(16, '0')); }

        return std::string(16, '0');
    }
    else
    {
        if (rinfo) { probe_info::set_payload(rinfo, resp); }

        response::status_line::set_resp_deep_log(resp, http);

        std::string fp_g = {};

        std::string fp_status_line = response::status_line::get_fingerprint(resp);
        std::string fp_content_length = response::content_length::get_fingerprint_content_length(resp);

        fp_g = fp_status_line + fp_content_length; // 5 bytes

        response::allow_header::fp_len_hval fp_allow;

        response::allow_header::get_fingerprint_allow_header(resp, "allow", fp_allow);
        response::allow_header::get_fingerprint_allow_header(resp, "access-control-allow-methods", fp_allow);
        response::allow_header::get_fingerprint_allow_header(resp, "public", fp_allow);

        fp_allow.set_allow_total_nb();
        fp_allow.encode_size();

        std::string fp_allow_final;

        if (!response::chk_sl_validity(resp))
        {
            fp_allow_final = "999999"; // 3 bytes
        }
        else
        {
            fp_allow_final = fp_allow.get_fingerprint(); // 3 bytes
        }

        if (rinfo)
        {
            rinfo->response_headers_fp = response::get_fingerprint_headers(resp, false, true, true);
            probe_info::set_fingerprint(rinfo, fp_status_line, fp_content_length, (fp_g + fp_allow_final), response::get_fingerprint_conx_hdr(resp));
        }
        http.CloseAllConnections();
        delete resp;
        return (fp_g + fp_allow_final);
    }
}

std::string
fingerprint::get_pacto(const std::string& fp)
{
    CkCrypt2 crypt;
    crypt.put_EncodingMode("hexlower");
    crypt.put_HashAlgorithm("sha-256");

    std::string pacto_hash = {};

    if (std::all_of(fp.begin(), fp.end(), [](char c) {return c == '0'; }))
    {
        pacto_hash = std::string(30, '0');
    }
    else
    {
        pacto_hash = std::string(crypt.hashStringENC(fp.c_str())).substr(0, 30);
    }

    return (fingerprint::version::pacto + pacto_hash);
}

fp_dissected
fingerprint::get_verbosus_dissected(const std::string& fp)
{
    std::string p1 = fp.substr(2, 10);  // p1
    std::string p2 = fp.substr(12, 10); // p2
    std::string p3 = fp.substr(22, 10); // p3
    std::string p4 = fp.substr(32, 10); // p4
    std::string p5 = fp.substr(42, 10); // p5
    std::string p6 = fp.substr(52, 2);  // p6
    std::string p7 = fp.substr(54, 2);  // p7
    std::string p8 = fp.substr(56, 16); // p8
    std::string cn = fp.substr(72, 4);  // Cn

    const auto dissect_sl = [](const std::string& px, status_line& sl) -> void
        {
            sl.sl_version = px.substr(0, 2); // 1 byte
            sl.sl_status_code = px.substr(2, 2); // 1 byte
            sl.sl_reason_phrase = px.substr(4, 4); // 2 byte
        };

    const auto dissect_c_len = [](const std::string& px, content_length& cl) -> void
        {
            cl.name = px.substr(8, 1).at(0);
            cl.length = px.substr(9, 1).at(0);
        };

    fp_dissected fp_d = {};

    dissect_sl(p1, fp_d.p1_sl);
    fp_d.p1_sts = p1.substr(8, 2); // 1 byte

    dissect_sl(p2, fp_d.p2_sl);
    dissect_c_len(p2, fp_d.p2_clen);

    dissect_sl(p3, fp_d.p3_sl);
    dissect_c_len(p3, fp_d.p3_clen);

    dissect_sl(p4, fp_d.p4_sl);
    dissect_c_len(p4, fp_d.p4_clen);

    dissect_sl(p5, fp_d.p5_sl);
    dissect_c_len(p5, fp_d.p5_clen);

    fp_d.p6f_cenc = p6;
    fp_d.p6l_cenc = p7;

    dissect_sl(p8, fp_d.p7a_sl);
    dissect_c_len(p8, fp_d.p7a_clen);

    fp_d.p7a_allow_len = p8.substr(10, 2);
    fp_d.p7a_allow_hash = p8.substr(12, 4);

    fp_d.cn_keep_alive = cn.substr(0, 2);
    fp_d.cn_close = cn.substr(2, 2);

    return fp_d;
}

std::string
fingerprint::get_verbosus(const std::string& fp)
{
    return (fingerprint::version::verbosus + fp);
}

void
request::setup_http_connection(CkHttp& http, CkHttpRequest& http_req, const std::string& path)
{
    // this is needed to get the raw server response
    http.put_VerboseLogging(true);

    http.put_ConnectTimeout(arg_opt::conxtn_timeout);
    http.put_ReadTimeout(arg_opt::read_timeout);
    http.DnsCacheClear();
    http.put_FollowRedirects(arg_opt::http_redirect);

    using namespace arg_opt;

    if (prxy_setup.type == "http")
    {
        http.put_ProxyDomain(prxy_setup.domain.c_str());
        http.put_ProxyPort(prxy_setup.port);
        http.put_ProxyDirectTls(prxy_setup.direct_tls);

        if (!prxy_setup.login.empty())
        {
            http.put_Login(prxy_setup.login.c_str());
        }
        if (!prxy_setup.pass.empty())
        {
            http.put_Password(prxy_setup.login.c_str());
        }
    }

    if (prxy_setup.type == "socks4")
    {
        http.put_SocksVersion(4);
    }
    if (prxy_setup.type == "socks5")
    {
        http.put_SocksVersion(5);
    }

    if (prxy_setup.type == "socks4" or prxy_setup.type == "socks5")
    {
        http.put_SocksHostname(prxy_setup.domain.c_str());
        http.put_SocksPort(prxy_setup.port);

        if (!prxy_setup.login.empty())
        {
            http.put_SocksUsername(prxy_setup.login.c_str());
        }
        if (!prxy_setup.pass.empty())
        {
            http.put_SocksPassword(prxy_setup.login.c_str());
        }
    }

    if (arg_opt::check_dpath and !path.empty())
    {
        http_req.put_Path(path.c_str());
    }
}

t::domain_tuple
domain::setup_domain(const std::string& domain)
{
    CkUrl url;
    if (url.ParseUrl(domain.c_str()))
    {
        std::uint16_t port;

        if (arg_opt::port_set) 
        { 
            port = arg_opt::port; 
        }
        else
        {
            if (url.get_Port() == 0) 
            { 
                port = 80; 
            }
            else 
            { 
                port = url.get_Port(); 
            }
        }
        bool is_ssl_d = false;

        if (arg_opt::is_ssl) 
        { 
            is_ssl_d = true; 
        }
        else 
        { 
            is_ssl_d = url.get_Ssl(); 
        }

        std::string qpath = {};
        if (arg_opt::check_dpath)
        {
            // this is to get the valid path
            CkHttpRequest http_req; http_req.SetFromUrl(domain.c_str());

            if (http_req.path() != nullptr) 
            { 
                qpath = http_req.path(); 
            }
            else 
            { 
                qpath = {}; 
            }
        }

        return (std::make_tuple(url.host(), port, is_ssl_d, qpath));
    }
    else
    {
        return (std::make_tuple("", 0, false, ""));
    }
}

std::string
helper::get_date(void)
{
    time_t sys_time = time(nullptr);
    struct tm* local_time = localtime(&sys_time);

    std::stringstream put_time;
    put_time << std::put_time(local_time, "%F");

    return put_time.str();
}

std::string
helper::get_time(void)
{
    time_t sys_time = time(nullptr);
    struct tm* local_time = localtime(&sys_time);

    std::stringstream put_time;
    put_time << std::put_time(local_time, "%I:%M:%S %p");

    return put_time.str();
}

void
helper::lowercase_str_in(std::string& str)
{
    std::transform(std::begin(str), std::end(str), std::begin(str), ::tolower);
}

std::string
helper::lowercase_str_out(const std::string& str)
{
    std::string lowered_st = {};
    std::transform(std::begin(str), std::end(str), std::back_inserter(lowered_st), ::tolower);

    return lowered_st;
}

bool
helper::is_str_in_vec(const std::vector<std::string>& v, const std::string& str)
{
    if (std::find(v.begin(), v.end(), str) != v.end())
    {
        return true;
    }
    else
    {
        return false;
    }
}

void
helper::del_sstr(std::string& str, const std::string& del_str)
{
    if (!del_str.empty())
    {
        for (auto i = str.find(del_str); i != std::string::npos; i = str.find(del_str))
        {
            str.erase(i, del_str.size());
        }
    }
}

void
helper::print_probing_domain_progress(const std::size_t& i, const std::string& d)
{
    std::cout << "\r\033[K" << rang::fg::green << "  P" << rang::fg::reset << "robing(" << rang::fg::blue << (i + 1) << rang::fg::reset << ") -> " << d;
    std::cout.flush();
}

void
domain::load_domains_file(const std::string& filename, std::vector<t::domain_tuple>& domains)
{
    std::ifstream f_domain;

    f_domain.open(filename, std::ios::in);

    if (!f_domain.is_open())
    {
        print_msg_exit("file \"" + filename + "\" could not be opened");
    }

    std::string entry = {};
    t::domain_tuple dt = {};

    while (std::getline(f_domain, entry))
    {
        // skip over such lines and do not consume them
        if (entry.empty() or entry.starts_with(";") or entry.starts_with("//") or entry.starts_with("#"))
        {
            continue;
        }
        else
        {
            // skip invalid/non-parsable domains
            dt = domain::setup_domain(entry);

            if (!std::get<t::d::domain>(dt).empty())
            {
                domains.push_back(dt);
            }
        }
    }
}

void
attivare_chilka_lic(void)
{
    if (CkGlobal glob; glob.UnlockBundle("30-day-trial") != true)
    {
        print_msg_exit("failed to unlock chilkat library using provided license");
    }
}

void
print_msg_exit(const std::string& msg)
{
    std::cerr << rang::fg::green << "* " 
              << rang::fg::reset << helper::get_date() << "  " << helper::get_time() 
              << rang::fg::red << " -> " << rang::fg::reset << msg << std::endl;

    std::exit(1);
}

std::string
csv::generate_filename(void)
{
    std::string s_time = std::regex_replace(helper::get_time(), std::regex(":"), "-");
    s_time = helper::lowercase_str_out(std::regex_replace(s_time, std::regex(" "), "_"));

    return ("hb_results_" + helper::get_date() + "_" + s_time + ".csv");
}

bool
csv::write_header_to_file(CkCsv& csv)
{
    bool srh = arg_opt::save_resp_headers;

    auto in_col_upd_idx = [&csv](int& idx, const std::string& col_name) -> void
        {
            csv.InsertColumn(idx + 1);
            csv.SetColumnName(idx + 1, col_name.c_str());
            idx = csv.GetIndex(col_name.c_str());
        };

    csv.put_HasColumnNames(true);
    csv.put_Delimiter("|");
    csv.put_Crlf(true);
    csv.put_EnableQuotes(true);
    csv.put_Utf8(true);

    if (!csv.SetColumnName(0, "date"))
    {
        return false;
    }
    csv.SetColumnName(1, "time");
    csv.SetColumnName(2, "domain");
    csv.SetColumnName(3, "port");
    csv.SetColumnName(4, "is_ssl");

    csv.SetColumnName(5, "fp_verbosus");
    csv.SetColumnName(6, "fp_pacto");

    csv.SetColumnName(7, "p1_fp"); // fingerprint
    csv.SetColumnName(8, "p1_sl"); // status line
    csv.SetColumnName(9, "p1_nh"); // number of headers

    int i = csv.GetIndex("p1_nh"); if (srh) { in_col_upd_idx(i, "p1_rh"); } // response headers

    csv.SetColumnName(i + 1, "p1_rh_fp"); // response headers fp (not part of the final fp)

    csv.SetColumnName(i + 2, "p2_fp");
    csv.SetColumnName(i + 3, "p2_sl");
    csv.SetColumnName(i + 4, "p2_nh");

    i = csv.GetIndex("p2_nh"); if (srh) { in_col_upd_idx(i, "p2_rh"); }

    csv.SetColumnName(i + 1, "p3_fp");
    csv.SetColumnName(i + 2, "p3_sl");
    csv.SetColumnName(i + 3, "p3_nh");

    i = csv.GetIndex("p3_nh"); if (srh) { in_col_upd_idx(i, "p3_rh"); }

    csv.SetColumnName(i + 1, "p4_fp");
    csv.SetColumnName(i + 2, "p4_sl");
    csv.SetColumnName(i + 3, "p4_nh");

    i = csv.GetIndex("p4_nh"); if (srh) { in_col_upd_idx(i, "p4_rh"); }

    csv.SetColumnName(i + 1, "p5_fp");
    csv.SetColumnName(i + 2, "p5_sl");
    csv.SetColumnName(i + 3, "p5_nh");

    i = csv.GetIndex("p5_nh"); if (srh) { in_col_upd_idx(i, "p5_rh"); }

    csv.SetColumnName(i + 1, "p6f_fp");
    csv.SetColumnName(i + 2, "p6f_sl");
    csv.SetColumnName(i + 3, "p6f_nh");

    i = csv.GetIndex("p6f_nh"); if (srh) { in_col_upd_idx(i, "p6f_rh"); }

    csv.SetColumnName(i + 1, "p6l_fp");

    csv.SetColumnName(i + 2, "p7a_fp");
    csv.SetColumnName(i + 3, "p7a_sl");
    csv.SetColumnName(i + 4, "p7a_nh");

    i = csv.GetIndex("p7a_nh"); if (srh) { in_col_upd_idx(i, "p7a_rh"); }

    if (!csv.SaveFile2(csv::filename.c_str(), "utf-8"))
    {
        return false;
    }
    else
    {
        return true;
    }
}

void
csv::write_data_to_file(CkCsv& csv, int r /*row*/, std::vector<probe_info::pinfo>& rinfo, t::fp_map& fp, const t::domain_tuple& domain)
{
    bool srh = arg_opt::save_resp_headers;

    using namespace request;

    csv.SetCellByName(r, "date", rinfo.at(p1).date.c_str());
    csv.SetCellByName(r, "time", rinfo.at(p1).time.c_str());
    csv.SetCellByName(r, "domain", std::get<0>(domain).c_str());
    csv.SetCellByName(r, "port", std::to_string(std::get<1>(domain)).c_str());
    csv.SetCellByName(r, "is_ssl", std::to_string(std::get<2>(domain)).c_str());

    csv.SetCellByName(r, "fp_verbosus", fp[fingerprint::version::verbosus].c_str());
    csv.SetCellByName(r, "fp_pacto", fp[fingerprint::version::pacto].c_str());

    csv.SetCellByName(r, "p1_fp", rinfo.at(p1).fingerprint.c_str());
    csv.SetCellByName(r, "p1_sl", rinfo.at(p1).resp_status_line.c_str());
    csv.SetCellByName(r, "p1_nh", std::to_string(rinfo.at(p1).nb_headers).c_str());
    if (srh) { csv.SetCellByName(r, "p1_rh", rinfo.at(p1).resp_headers.c_str()); }

    csv.SetCellByName(r, "p1_rh_fp", rinfo.at(p1).response_headers_fp.c_str());

    csv.SetCellByName(r, "p2_fp", rinfo.at(p2).fingerprint.c_str());
    csv.SetCellByName(r, "p2_sl", rinfo.at(p2).resp_status_line.c_str());
    csv.SetCellByName(r, "p2_nh", std::to_string(rinfo.at(p2).nb_headers).c_str());
    if (srh) { csv.SetCellByName(r, "p2_rh", rinfo.at(p2).resp_headers.c_str()); }

    csv.SetCellByName(r, "p3_fp", rinfo.at(p3).fingerprint.c_str());
    csv.SetCellByName(r, "p3_sl", rinfo.at(p3).resp_status_line.c_str());
    csv.SetCellByName(r, "p3_nh", std::to_string(rinfo.at(p3).nb_headers).c_str());
    if (srh) { csv.SetCellByName(r, "p3_rh", rinfo.at(p3).resp_headers.c_str()); }

    csv.SetCellByName(r, "p4_fp", rinfo.at(p4).fingerprint.c_str());
    csv.SetCellByName(r, "p4_sl", rinfo.at(p4).resp_status_line.c_str());
    csv.SetCellByName(r, "p4_nh", std::to_string(rinfo.at(p4).nb_headers).c_str());
    if (srh) { csv.SetCellByName(r, "p4_rh", rinfo.at(p4).resp_headers.c_str()); }

    csv.SetCellByName(r, "p5_fp", rinfo.at(p5).fingerprint.c_str());
    csv.SetCellByName(r, "p5_sl", rinfo.at(p5).resp_status_line.c_str());
    csv.SetCellByName(r, "p5_nh", std::to_string(rinfo.at(p5).nb_headers).c_str());
    if (srh) { csv.SetCellByName(r, "p5_rh", rinfo.at(p5).resp_headers.c_str()); }

    csv.SetCellByName(r, "p6f_fp", rinfo.at(p6f).fingerprint.c_str());
    csv.SetCellByName(r, "p6f_sl", rinfo.at(p6f).resp_status_line.c_str());
    csv.SetCellByName(r, "p6f_nh", std::to_string(rinfo.at(p6f).nb_headers).c_str());
    if (srh) { csv.SetCellByName(r, "p6f_rh", rinfo.at(p6f).resp_headers.c_str()); }

    csv.SetCellByName(r, "p6l_fp", rinfo.at(p6l).fingerprint.c_str());

    csv.SetCellByName(r, "p7a_fp", rinfo.at(p7a).fingerprint.c_str());
    csv.SetCellByName(r, "p7a_sl", rinfo.at(p7a).resp_status_line.c_str());
    csv.SetCellByName(r, "p7a_nh", std::to_string(rinfo.at(p7a).nb_headers).c_str());
    if (srh) { csv.SetCellByName(r, "p7a_rh", rinfo.at(p7a).resp_headers.c_str()); }

    if (!csv.SaveFile2(csv::filename.c_str(), "utf-8"))
    {
        print_msg_exit("failed to write data to the csv file " + csv::filename);
    }
}

std::string
json::generate_filename(void)
{
    std::string s_time = std::regex_replace(helper::get_time(), std::regex(":"), "-");
    s_time = helper::lowercase_str_out(std::regex_replace(s_time, std::regex(" "), "_"));

    return ("hb_results_" + helper::get_date() + "_" + s_time + ".json");
}

void
json::build_prolog(CkJsonObject& json, const std::size_t domains_total)
{
    json.UpdateString("title", "Fingerprints Dissection");
    json.UpdateString("author", "HTTP-Basma");

    std::string ver = prog_about::prog_version + " (" + prog_about::arch + ") - rel: " +
        prog_about::prog_edition + " - " +
        prog_about::prog_release_date;

    json.UpdateString("version", ver.c_str());
    json.UpdateString("starting_date", helper::get_date().c_str());
    json.UpdateString("starting_time", helper::get_time().c_str());
    json.UpdateUInt("domains_total", domains_total);
}

void
json::build_domain_payload(CkJsonObject& json, std::size_t i /*index*/, std::vector<probe_info::pinfo>& rinfo, t::fp_map& fp, const t::domain_tuple& domain)
{
    using namespace request;

    bool srh = arg_opt::save_resp_headers;

    std::string dp = ("domains[" + std::to_string(i) + "].");
    // json domain path: domains[<idx>].<key>
    auto jp = [&dp](const std::string& k)-> const char* { static std::string t; t = (dp + k);  return t.c_str(); };

    json.UpdateString(jp("domain.target"), std::get<0>(domain).c_str());
    json.UpdateInt(jp("domain.port"), std::get<1>(domain));
    json.UpdateBool(jp("domain.ssl"), std::get<2>(domain));

    json.UpdateString(jp("fp.verbosus"), fp[fingerprint::version::verbosus].c_str());
    json.UpdateString(jp("fp.pacto"), fp[fingerprint::version::pacto].c_str());

    auto preq = [&](const std::string& p, const request::etype& t) -> void
        {
            json.UpdateString(jp(p + ".req.type"), rinfo.at(t).req_type.c_str());
            json.UpdateString(jp(p + ".req.date"), rinfo.at(t).date.c_str());
            json.UpdateString(jp(p + ".req.time"), rinfo.at(t).time.c_str());
            json.UpdateString(jp(p + ".req.status"), rinfo.at(t).req_status.c_str());
        };

    auto presp = [&](const std::string& p, const request::etype& t) -> void
        {
            json.UpdateString(jp(p + ".resp.status_line"), rinfo.at(t).resp_status_line.c_str());
            json.UpdateInt(jp(p + ".resp.hdrs_total"), rinfo.at(t).nb_headers);

            if (srh) { json.UpdateString(jp(p + ".resp.hdrs"), rinfo.at(t).resp_headers.c_str()); }

            json.UpdateBool(jp(p + ".resp.cnx.ka"), std::get<0>(rinfo.at(t).conx_state));
            json.UpdateBool(jp(p + ".resp.cnx.c"), std::get<1>(rinfo.at(t).conx_state));
        };

    auto pfp = [&](const std::string& p, const request::etype& t) -> void
        {
            json.UpdateString(jp(p + ".fp.final"), rinfo.at(t).fingerprint.c_str());
            json.UpdateString(jp(p + ".fp.resp_hdrs"), rinfo.at(t).response_headers_fp.c_str());

            if (t == request::etype::p1)
            {
                json.UpdateString(jp(p + ".fp.sts"), rinfo.at(t).fingerprint.substr(8, 2).c_str());
            }
            if (t == request::etype::p7a)
            {
                json.UpdateString(jp(p + ".fp.allow"), rinfo.at(t).fingerprint.substr(10, 6).c_str());
            }
        };

    preq("p1", p1); presp("p1", p1); pfp("p1", p1);
    preq("p2", p2); presp("p2", p2); pfp("p2", p2);
    preq("p3", p3); presp("p3", p3); pfp("p3", p3);
    preq("p4", p4); presp("p4", p4); pfp("p4", p4);
    preq("p5", p5); presp("p5", p5); pfp("p5", p5);
    preq("p6f", p6f); presp("p6f", p6f); pfp("p6f", p6f);
    preq("p6l", p6l); presp("p6l", p6l); pfp("p6l", p6l);
    preq("p7a", p7a); presp("p7a", p7a); pfp("p7a", p7a);
}

void
json::write_epilog(CkJsonObject& json)
{
    json.UpdateString("ending_date", helper::get_date().c_str());
    json.UpdateString("ending_time", helper::get_time().c_str());
}

void
helper::check_args(int argc, char** argv)
{
    try
    {
        cxxopts::Options options
        (
            prog_about::prog_name,
            "\n" + prog_about::prog_name + " is a fingerprinting tool for identifying HTTP servers\n\n" + // REWORD
            prog_about::author_name + "(" + prog_about::author_email + ")" + "\nver: " +
            prog_about::prog_version + " (" + prog_about::arch + ") - rel: " + prog_about::prog_edition + " - " +
            prog_about::prog_release_date + "\n"
        );

        options.set_width(120)
            .add_options()
            ("d,domain", "domains/IPs (you may query multiple domains, comma separated)",
                cxxopts::value<std::vector<std::string>>())
            ("p,port", "port number",
                cxxopts::value<std::uint16_t>(arg_opt::port))
            ("s,ssl", "does the HTTP connection have to be carried over SSL/TLS?",
                cxxopts::value<bool>(arg_opt::is_ssl)->default_value("false"))
            ("q,qpath", "check domain with url path included (not recommended)",
                cxxopts::value<bool>(arg_opt::check_dpath)->default_value("false"))
            ("w,redirect", "enable/disable HTTP redirects. If disabled/false, only the next redirect is followed, otherwise, all redirects are followed",
                cxxopts::value<bool>(arg_opt::http_redirect)->default_value("true"))
            ("t,ctimeout", "socket connection timeout value in seconds",
                cxxopts::value<int>(arg_opt::conxtn_timeout)->default_value("1"))
            ("g,rtimeout", "socket read (from the server) timeout value in seconds",
                cxxopts::value<int>(arg_opt::read_timeout)->default_value("1"))
            ("e,sleep", "the duration (in milliseconds) to pause between each request",
                cxxopts::value<std::uint32_t>(arg_opt::sleep)->default_value("100"))
            ("x,proxy", "proxy config: <\"socks4|socks5|http\">,<domain>,<port>,<bool:direct_tls>,<login>,<pass>\n\
              all values are comma-separated. <direct_tls> is ignored with a non-http proxy",
                cxxopts::value<std::vector<std::string>>())
            ("f,file", "file with list of domains/IPs (requires \"-c/--csv\" or \"-j/--json\")",
                cxxopts::value<std::string>(arg_opt::file_domains))
            ("P,parallel", "Scan list of domains passed via the \"-f/--file\" option in parallel",
                cxxopts::value<bool>(arg_opt::scan_file_in_parallel)->default_value("false"))
            ("c,csv", "save to csv file; if the option 'n' is not specified, the CSV filename will be auto generated",
                cxxopts::value<bool>(arg_opt::save_to_csv_file)->default_value("false"))
            ("n,csvfile", "name of the CSV file",
                cxxopts::value<std::string>(csv::filename))
            ("j,json", "save to json file; if the option 'l' is not specified, the JSON filename will be auto generated",
                cxxopts::value<bool>(arg_opt::save_to_json_file)->default_value("false"))
            ("l,jsonfile", "name of the JSON file",
                cxxopts::value<std::string>(json::filename))
            ("r,saveh", "save request response headers",
                cxxopts::value<bool>(arg_opt::save_resp_headers)->default_value("false"))
            ("o,pjson", "display fingerprint dissection to the console as a JSON object",
                cxxopts::value<bool>(arg_opt::print_json)->default_value("false"))
            ("i,demangle_json", "demangle a fingerprint into a detailed json format (you can have more than one, comma separated)",
                cxxopts::value<std::vector<std::string>>())
            ("u,demangle_txt", "output a concise text format of the fingerprint, comma-separated for multiple results",
                cxxopts::value<std::vector<std::string>>())
            ("C,compare", "compare two verbosus fingerprints (comma-separated)",
                cxxopts::value<std::vector<std::string>>())
            ("a,pacto", "obtain the Pacto fingerprint using Verbosus",
                cxxopts::value<std::vector<std::string>>())
            ("h,help", "print usage");

        auto result = options.parse(argc, argv);

        if (result.count("help"))
        {
            std::cout << options.help() << std::endl;
            std::exit(0);
        }

        if (result.count("pacto"))
        {
            auto validate_vrbos = [](const std::string& fp) -> auto
                {
                    std::vector<std::string> err_msg = {};

                    if (std::find_if(fp.begin(), fp.end(), [](const char& c) { return !isxdigit(c); }) != fp.end())
                    {
                        err_msg.push_back("contains non-hex digits");
                    }
                    if (!fp.starts_with(fingerprint::version::verbosus))
                    {
                        err_msg.push_back("doesn't start with \"01\"");
                    }
                    if (fp.size() != 76)
                    {
                        err_msg.push_back("length is not 76");
                    }
                    return err_msg;
                };

            auto fpvrbos = result["pacto"].as<std::vector<std::string>>();

            std::cout << std::endl;

            for (std::size_t i = 0; i < fpvrbos.size(); ++i)
            {
                auto err_msg = validate_vrbos(fpvrbos.at(i));
                if (err_msg.empty())
                {
                    std::cout << "[" << i << "]" << " Verbosus: " << fpvrbos.at(i) << std::endl;
                    std::cout << "[" << i << "]" << " Pacto   : " << fingerprint::get_pacto(fpvrbos.at(i).substr(2));
                }
                else
                {
                    std::cout << "[" << i << "]" << " Verbosus: " << fpvrbos.at(i) << std::endl;
                    std::cout << "[" << i << "]" << " Pacto   : ";

                    std::cout << "{ ";
                    for (std::size_t i = 0; i < err_msg.size(); ++i)
                    {
                        std::cout << err_msg.at(i) << ((i < err_msg.size() - 1) ? ", " : "");
                    }
                    std::cout << " }";
                }
                std::cout << std::endl << std::endl;
            }
            std::cout << std::endl;
        }

        if (result.count("demangle_json"))
        {
            if (demangler::csv::load_options_hashes(demangler::csv::opt_file))
            {
                demangler::load_options = true;
            }

            if (demangler::csv::load_status_line_db(demangler::csv::sl_file))
            {
                demangler::load_status_line = true;
            }

            CkJsonObject json;
            auto fpvec = result["demangle_json"].as<std::vector<std::string>>();

            demangler::json::build_prolog(json, fpvec.size());

            for (std::size_t i = 0; i < fpvec.size(); ++i)
            {
                demangler::demangle(json, i, fpvec.at(i));
            }
            demangler::json::emit_to_console(json);
        }

        if (result.count("demangle_txt"))
        {
            auto fpvec = result["demangle_txt"].as<std::vector<std::string>>();

            if (fpvec.size() > 1) { std::cout << std::endl; }

            for (std::size_t i = 0; i < fpvec.size(); ++i)
            {
                std::cout << "fp: " << fpvec.at(i) << std::endl;
                demangler::demangle_txt(fpvec.at(i));
                if (i < fpvec.size() - 1) { std::cout << std::endl; }
            }
        }

        if (result.count("compare"))
        {
            auto fpvec = result["compare"].as<std::vector<std::string>>();

            if (fpvec.size() != 2)
            {
                print_msg_exit("the compare option takes only two verbosus fingerprints");
            }

            compare::compare_verbosus(fpvec.at(0), fpvec.at(1));
        }

        if (result.count("proxy"))
        {
            arg_opt::parse_proxy_config(result["proxy"].as<std::vector<std::string>>());
        }

        if (result.count("port"))
        {
            arg_opt::port_set = true;
        }

        if (result.count("domain"))
        {
            for (const auto& d : result["domain"].as<std::vector<std::string>>())
            {
                if (auto dt = domain::setup_domain(d); !std::get<t::d::domain>(dt).empty())
                {
                    arg_opt::domains_vec.push_back(dt);
                }
            }
            if (!arg_opt::domains_vec.empty())
            {
                arg_opt::domain_opt_set = true;
            }
        }

        if (result.count("file"))
        {
            arg_opt::file_opt_set = true;
        }

        if (result.count("csv"))
        {
            if (!result.count("csvfile"))
            {
                csv::filename = csv::generate_filename();
            }
        }

        if (result.count("json"))
        {
            if (!result.count("jsonfile"))
            {
                json::filename = json::generate_filename();
            }
        }
    }
    catch (const cxxopts::exceptions::exception& e)
    {
        std::cerr << "error parsing options: " << e.what() << std::endl;
        std::exit(0);
    }
}

void
arg_opt::parse_proxy_config(const std::vector<std::string>& prxy)
{
    using namespace arg_opt;

    // <type:\"socks4|socks5|http\">,<domain>,<port>,<direct_tls:"\"true|false\">,<login>,<pass>

    if (prxy.size() < 3)
    {
        print_msg_exit("for the proxy configuration, the type, domain and port are required");
    }

    // type
    if (prxy.at(0).empty())
    {
        print_msg_exit("proxy type value is empty");
    }
    else if (prxy.at(0) == "http" or prxy.at(0) == "socks4" or prxy.at(0) == "socks5")
    {
        prxy_setup.type = prxy.at(0);
    }
    else
    {
        print_msg_exit("proxy type value \"" + prxy.at(0) + "\" is not valid. Only the types: \"http\", \"socks4\" or \"socks5\" are valid");
    }

    // domain
    if (!prxy.at(1).empty())
    {
        prxy_setup.domain = prxy.at(1);
    }
    else
    {
        print_msg_exit("proxy domain/ip is empty");
    }

    // port
    if (!prxy.at(2).empty())
    {
        prxy_setup.port = static_cast<std::uint16_t>(std::stoi(prxy.at(2)));
    }
    else
    {
        print_msg_exit("proxy domain/ip is empty");
    }

    if (prxy.size() > 3)
    {
        // is direct TLS
        if (!prxy.at(3).empty())
        {
            if (prxy.at(3) == "true" or prxy.at(3) == "1")
            {
                prxy_setup.direct_tls = true;
            }
            else if (prxy.at(3) == "false" or prxy.at(3) == "0")
            {
                prxy_setup.direct_tls = false;
            }
            else
            {
                print_msg_exit("proxy is direct TLS value is incorrect. It takes either of the following bool values: (\"true|1|false|0\")");
            }
        }
        else
        {
            print_msg_exit("proxy is direct TLS value is not defined");
        }
    }

    if (prxy.size() == 6)
    {
        // login
        if (!prxy.at(4).empty())
        {
            prxy_setup.login = prxy.at(4);
        }
        else
        {
            print_msg_exit("proxy login user is empty");
        }
        // password
        if (!prxy.at(5).empty())
        {
            prxy_setup.pass = prxy.at(5);
        }
        else
        {
            print_msg_exit("proxy login password is empty");
        }
    }
}

// thread
template <typename T>
void
helper::update_title_realtime(std::string msg, T& cntr_var, T& total_var)
{
    for (;;)
    {
        std::wstringstream st_str;
        st_str << msg.c_str() << cntr_var << "/" << total_var << " (" << (cntr_var * 100) / total_var << "%)" << '\00';
        helper::set_console_tite(st_str.str());
        if (cntr_var == total_var) { break; }
    }
    // return; doesn't really terminate the thread!
    // safe to call EXIT_CURRENT_THREAD() here since the code is not allocating anything on the stack
    // nothing else needs to be cleaned
    EXIT_CURRENT_THREAD();
}

// Linux and Windows versions
void
helper::set_console_tite(std::wstring msg)
{
#if defined(_WIN32)
    SetConsoleTitle(msg.c_str());
#elif defined(__linux__)
    if (!isatty(STDOUT_FILENO)) return;

    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> conv;
    std::string utf8 = conv.to_bytes(msg);

    std::printf("\033]0;%s\007", utf8.c_str());
    std::fflush(stdout);
#endif
}

void
compare::compare_verbosus(const std::string& fp1, const std::string& fp2)
{
    if (!demangler::validate(fp1))
    {
        std::exit(1);
    }
    if (!demangler::validate(fp2))
    {
        std::exit(1);
    }
    if (!fp1.starts_with(fingerprint::version::verbosus) or !fp2.starts_with(fingerprint::version::verbosus))
    {
        std::cerr << "the fingerprints must be of the Verbosus type" << std::endl;
        std::exit(1);
    }

    if (fp1 == fp2)
    {
        std::cerr << "the fingerprints are identical" << std::endl;
        std::exit(1);
    }

    const auto fp1_d = fingerprint::get_verbosus_dissected(fp1);
    const auto fp2_d = fingerprint::get_verbosus_dissected(fp2);

    std::cout << std::endl << " < FPrnt-1 Vs. FPrnt-2 >" << std::endl << std::endl;

    // P1
    std::cout << " [ P1 ]" << std::endl;
    if (fp1_d.p1_sl != fp2_d.p1_sl)
    {
        std::cout << "    {Status-Line}" << std::endl << std::endl;
        compare_sl(fp1_d.p1_sl, fp2_d.p1_sl);
        std::cout << std::endl;
    }

    if (fp1_d.p1_sts != fp2_d.p1_sts)
    {
        std::cout << "    {Strict-Transport-Security}" << std::endl;

        std::cout << "      sts header: " << fp1_d.p1_sts << " != " << fp2_d.p1_sts << std::endl << std::endl;
    }

    // P2
    std::cout << " [ P2 ]" << std::endl;
    if (fp1_d.p2_sl != fp2_d.p2_sl)
    {
        std::cout << "    {Status-Line}" << std::endl << std::endl;
        compare_sl(fp1_d.p2_sl, fp2_d.p2_sl);
        std::cout << std::endl;
    }
    if (fp1_d.p2_clen != fp2_d.p2_clen)
    {
        std::cout << "    {Content-Length}" << std::endl << std::endl;
        compare_cl(fp1_d.p2_clen, fp2_d.p2_clen);
        std::cout << std::endl;
    }

    // P3
    std::cout << " [ P3 ]" << std::endl;
    if (fp1_d.p3_sl != fp2_d.p3_sl)
    {
        std::cout << "    {Status-Line}" << std::endl << std::endl;
        compare_sl(fp1_d.p3_sl, fp2_d.p3_sl);
        std::cout << std::endl;
    }
    if (fp1_d.p3_clen != fp2_d.p3_clen)
    {
        std::cout << "    {Content-Length}" << std::endl << std::endl;
        compare_cl(fp1_d.p3_clen, fp2_d.p3_clen);
        std::cout << std::endl;
    }

    // P4
    std::cout << " [ P4 ]" << std::endl;
    if (fp1_d.p4_sl != fp2_d.p4_sl)
    {
        std::cout << "    {Status-Line}" << std::endl << std::endl;
        compare_sl(fp1_d.p4_sl, fp2_d.p4_sl);
        std::cout << std::endl;
    }
    if (fp1_d.p4_clen != fp2_d.p4_clen)
    {
        std::cout << "    {Content-Length}" << std::endl << std::endl;
        compare_cl(fp1_d.p4_clen, fp2_d.p4_clen);
        std::cout << std::endl;
    }

    // P5
    std::cout << " [ P5 ]" << std::endl;
    if (fp1_d.p5_sl != fp2_d.p5_sl)
    {
        std::cout << "    {Status-Line}" << std::endl << std::endl;
        compare_sl(fp1_d.p5_sl, fp2_d.p5_sl);
        std::cout << std::endl;
    }
    if (fp1_d.p5_clen != fp2_d.p5_clen)
    {
        std::cout << "    {Content-Length}" << std::endl << std::endl;
        compare_cl(fp1_d.p5_clen, fp2_d.p5_clen);
        std::cout << std::endl;
    }

    // P6 Full
    std::cout << " [ P6F ]" << std::endl;
    if (fp1_d.p6f_cenc != fp2_d.p6f_cenc)
    {
        std::cout << "    {Content-Encoding}" << std::endl << std::endl;

        std::cout << "      cenc header: " << fp1_d.p6f_cenc << " != " << fp2_d.p6f_cenc << std::endl << std::endl;
    }

    // P6 Less
    std::cout << " [ P6L ]" << std::endl;
    if (fp1_d.p6l_cenc != fp2_d.p6l_cenc)
    {
        std::cout << "    {Content-Encoding}" << std::endl << std::endl;

        std::cout << "      cenc header: " << fp1_d.p6l_cenc << " != " << fp2_d.p6l_cenc << std::endl << std::endl;
    }

    // P7a
    std::cout << " [ P7a ]" << std::endl;
    if (fp1_d.p7a_sl != fp2_d.p7a_sl)
    {
        std::cout << "    {Status-Line}" << std::endl << std::endl;
        compare_sl(fp1_d.p7a_sl, fp2_d.p7a_sl);
        std::cout << std::endl;
    }
    if (fp1_d.p7a_clen != fp2_d.p7a_clen)
    {
        std::cout << "    {Content-Length}" << std::endl << std::endl;
        compare_cl(fp1_d.p7a_clen, fp2_d.p7a_clen);
        std::cout << std::endl;
    }

    if (fp1_d.p7a_allow_len != fp2_d.p7a_allow_len)
    {
        std::cout << "    {Allow Header(s) Size}" << std::endl << std::endl;
        std::cout << "      allow header: " << fp1_d.p7a_allow_len << " != " << fp2_d.p7a_allow_len << std::endl << std::endl;
    }
    if (fp1_d.p7a_allow_hash != fp2_d.p7a_allow_hash)
    {
        std::cout << "    {Allow Header(s) Hash}" << std::endl << std::endl;
        std::cout << "      allow header: " << fp1_d.p7a_allow_hash << " != " << fp2_d.p7a_allow_hash << std::endl << std::endl;
    }

    if (fp1_d.cn_keep_alive != fp2_d.cn_keep_alive)
    {
        std::cout << "    {Connection Keep-Alive}" << std::endl << std::endl;
        std::cout << "      cnx header: " << fp1_d.cn_keep_alive << " != " << fp2_d.cn_keep_alive << std::endl << std::endl;
    }

    if (fp1_d.cn_close != fp2_d.cn_close)
    {
        std::cout << "    {Connection Close}" << std::endl << std::endl;
        std::cout << "      cnx header: " << fp1_d.cn_close << " != " << fp2_d.cn_close << std::endl << std::endl;
    }
}
