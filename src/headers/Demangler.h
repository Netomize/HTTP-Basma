/*
	file       Demangler.h
	author     Mohamad Mokbel (mfmokbel@netomize.ca)
	brief      HTTP-Basma v1.0

	details    Takes a verbosus fingerprint and reconstructs the attributes of 
               each probe, outputting a comprehensive JSON object.

			   See LICENSE file for details.

	copyright  Netomize. Copyright (c) 2026.  All rights reserved.
*/

#pragma once

namespace demangler
{
	bool validate(const std::string& fp);
	void demangle(CkJsonObject& json, std::size_t i /*index*/, const std::string& fp);
	void demangle_txt(const std::string& fp);

	namespace status_line
	{
		std::string get_http_version(const char& n, const char& v);
		std::string get_status_code(const std::string& sc);
		std::string get_reason(const std::string& sc, const std::string& hash);
	};

	void get_strict_transport_security_header
	(
		CkJsonObject& json, const std::string& p, const std::string& sts, std::function<const char* (const std::string&)> jf
	);

	void get_content_length
	(
		CkJsonObject& json, const std::string& p, const std::string& cl, std::function<const char* (const std::string&)> jf
	);

	void get_allow_header
	(
		CkJsonObject& json, const std::string& p, const std::string& ah, std::function<const char* (const std::string&)> jf
	);

	void get_content_encoding(CkJsonObject& json, const std::string& p, const std::string& ce, std::function<const char* (const std::string&)> jf);

	namespace json
	{
		void build_prolog(CkJsonObject& json, const std::size_t t);
		void emit_to_console(CkJsonObject& json);
	};

	namespace csv
	{
		CkCsv opt_file;
		CkCsv sl_file;

		struct allow_hdrs
		{
			std::vector<std::string> allow_h;
			std::vector<std::string> acam_h;
			std::vector<std::string> public_h;
		};
		namespace opt_c
		{
			const std::string hash    = "hash";
			const std::string allow   = "allow_h";
			const std::string acam    = "acam_h";
			const std::string hpublic = "public_h";
		};

		namespace sl_c
		{
			const std::string hash   = "sl_hash";
			const std::string ver    = "sl_ver";
			const std::string code   = "sl_code";
			const std::string reason = "sl_reason";
		};

		bool load_options_hashes(CkCsv& csv);
		demangler::csv::allow_hdrs get_opt_values(CkCsv& csv, const std::string& hash);

		bool load_status_line_db(CkCsv& csv);
		std::tuple<std::string, std::string, std::string> get_status_line(CkCsv& csv, const std::string& hash);
		std::vector<std::uint16_t> get_status_code(const std::string& scode);
	};
	bool load_options = false;
	bool load_status_line = false;
};

std::string
demangler::status_line::get_http_version(const char& n, const char& v)
{
	std::string name = {};

	switch (n)
	{
	case '1':
		name = "HTTP";
		break;
	case '2':
		name = "http";
		break;
	case '3':
		name = "Http";
		break;
	case '4':
		name = "HTTP (different casing)";
		break;
	}

	std::string version = {};

	switch (v)
	{
	case '1':
		version = "0.8";
		break;
	case '2':
		version = "0.9";
		break;
	case '3':
		version = "1.0";
		break;
	case '4':
		version = "1.1";
		break;
	case '7':
		version = ">=(2.0)";
		break;
	case '8':
		version = "1.(>1)";
		break;
	case '9':
		version = "0.(<8)";
		break;
	case 'f':
		// it should never reach this case
		version = "something else";
		break;
	}

	return (name + "/" + version);
}

std::string
demangler::status_line::get_status_code(const std::string& sc)
{
	if (sc == "ff")
	{
		return "the status code is not in the list";
	}
	else if (sc == "00")
	{
		return "no status code";
	}
	else
	{
		auto it = response::status_line::status_code.begin();
		std::advance(it, std::stoi(sc, nullptr, 16) - 1);

		return std::to_string(it->first);
	}
}

std::string
demangler::status_line::get_reason(const std::string& sc, const std::string& hash)
{
	if (hash == "0000")
	{
		return "reason phrase is empty";
	}
	else if (hash == "0001")
	{
		return "reason phrase contains disallowed chars, with a space after the status code";
	}
	else if (hash == "0002")
	{
		return "reason phrase contains disallowed chars, with no space after the status code";
	}
	else
	{
		if (sc != "ff" and sc != "00")
		{
			auto itr = response::status_line::status_code.begin();
			std::advance(itr, std::stoi(sc, nullptr, 16) - 1);

			if (hash == std::format("{0:04x}", response::fnv1a_hash<std::uint16_t, 'h'>(itr->second)))
			{
				return (itr->second);
			}
			else
			{
				return "reason phrase is not in the list";
			}
		}
		else
		{
			if (sc == "ff")
			{
				return "reason phrase is not in the list";
			}
			if (sc == "00")
			{
				return "reason phrase is not defined since no status code exist";
			}
		}
	}
}

void
demangler::get_content_length
(
	CkJsonObject& json, const std::string& p, const std::string& cl, std::function<const char* (const std::string&)> jf
)
{
	json.UpdateString(jf(p + ".cont_len_hdr.fp"), cl.c_str());

	const char n = cl[0]; const char l = cl[1];

	if (cl == "00")
	{
		json.UpdateString(jf(p + ".cont_len_hdr.name"), "not used");
		json.UpdateString(jf(p + ".cont_len_hdr.value"), "not used");
		json.UpdateString(jf(p + ".cont_len_hdr.cmt"), "no content-length/transfer-encoding:chunked header");
		return;
	}
	if (cl == "99")
	{
		json.UpdateString(jf(p + ".cont_len_hdr.cmt"), "the HTTP status line is not std conformant/not valid");
		return;
	}

	if (n == '1')
	{
		if (l == '1')
		{
			json.UpdateString(jf(p + ".cont_len_hdr.name"), "not used");
			json.UpdateString(jf(p + ".cont_len_hdr.value"), "not used");
			json.UpdateString(jf(p + ".cont_len_hdr.cmt"), "no content-length/transfer-encoding:chunked header, but body exists with a (size=1)");
			return;
		}
		else if (l == '2')
		{
			json.UpdateString(jf(p + ".cont_len_hdr.name"), "not used");
			json.UpdateString(jf(p + ".cont_len_hdr.value"), "not used");
			json.UpdateString(jf(p + ".cont_len_hdr.cmt"), "no content-length/transfer-encoding:chunked header, but body exists with a (size>1)");
			return;
		}
		else
		{
			json.UpdateString(jf(p + ".cont_len_hdr.name"), "not used");
			json.UpdateString(jf(p + ".cont_len_hdr.value"), "not used");
			json.UpdateString(jf(p + ".cont_len_hdr.cmt"), "no content-length/transfer-encoding:chunked header, with unknown length value");
			return;
		}
	}

	// content-length/transfer-encoding:chunked header exist

	std::string name = {};

	switch (n)
	{
	case '2':
		name = "Content-Length";
		break;
	case '3':
		name = "content-length";
		break;
	case '4':
		name = "Content-length";
		break;
	case '5':
		name = "content-Length";
		break;
	case '6':
		name = "Content-Length with different casing";
		break;
	case '7':
		name = "Transfer-Encoding";
		break;
	case '8':
		name = "transfer-encoding";
		break;
	case '9':
		name = "Transfer-encoding";
		break;
	case 'a':
		name = "transfer-Encoding";
		break;
	case 'b':
		name = "Transfer-Encoding with different casing";
		break;
	default:
		name = "unknown header";
		break;
	}

	std::string value = {};

	switch (l)
	{
	case '0':
		value = "0";
		break;
	case '1':
		value = "1";
		break;
	case '2':
		value = ">1";
		break;
	default:
		value = "unknown size";
		break;
	}

	json.UpdateString(jf(p + ".cont_len_hdr.name"), name.c_str());
	json.UpdateString(jf(p + ".cont_len_hdr.value"), value.c_str());
	json.UpdateString(jf(p + ".cont_len_hdr.cmt"), "content-length/transfer-encoding:chunked header is present with either of the size values: [0,1,>1]");
}

void
demangler::get_strict_transport_security_header
(
	CkJsonObject& json, const std::string& p, const std::string& sts, std::function<const char* (const std::string&)> jf
)
{
	json.UpdateString(jf(p + ".sts_hdr.fp"), sts.c_str());

	if (sts == "00")
	{
		json.UpdateString(jf(p + ".sts_hdr.cmt"), "this header is not used");
		return;
	}
	if (sts == "ff")
	{
		json.UpdateString(jf(p + ".sts_hdr.cmt"), "this header has no value");
		return;
	}
	if (sts == "99")
	{
		json.UpdateString(jf(p + ".sts_hdr.cmt"), "the HTTP status line is not std conformant/not valid");
		return;
	}

	std::bitset<7> sts_opt; sts_opt.reset(); sts_opt = std::stoi(sts, nullptr, 16);

	/*
	Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

	0    exist(max-age)
	1    if(max-age == 0)
	2	 if(max-age).empty()
	3    exist(includeSubDomains)
	4    exist(preload)
	5    if(more than three fields)
	6    if(attribute is empty. for ex., ;;;)
	*/

	std::vector<std::string> opt = {};

	if (sts_opt.test(0)) { opt.push_back("max-age"); }
	if (sts_opt.test(3)) { opt.push_back("includeSubDomains"); }
	if (sts_opt.test(4)) { opt.push_back("preload"); }

	for (std::size_t i = 0; i < opt.size(); ++i)
	{
		json.UpdateString(jf(p + ".sts_hdr.attrbs.options[" + std::to_string(i) + "]"), opt[i].c_str());
	}

	json.UpdateBool(jf(p + ".sts_hdr.attrbs.gt_3"), sts_opt.test(5) ? true : false);
	json.UpdateBool(jf(p + ".sts_hdr.attrbs.max_age_eq_0"), sts_opt.test(1) ? true : false);
	json.UpdateBool(jf(p + ".sts_hdr.attrbs.max_age_no_val"), sts_opt.test(2) ? true : false);
	json.UpdateBool(jf(p + ".sts_hdr.attrbs.empty_exist"), sts_opt.test(6) ? true : false);
}

void
demangler::get_content_encoding
(
	CkJsonObject& json, const std::string& p, const std::string& ce, std::function<const char* (const std::string&)> jf
)
{
	if (ce == "00")
	{
		json.UpdateString(jf(p + ".cont_enc_hdr.cmt[0]"), "no response from the server or the content-encoding header is not present");
		return;
	}
	if (ce == "99")
	{
		json.UpdateString(jf(p + ".cont_enc_hdr.cmt[0]"), "the HTTP status line is not std conformant/not valid");
		return;
	}

	std::bitset<8> ce_bit; ce_bit.reset(); ce_bit = std::stoi(ce, nullptr, 16);
	std::bitset<4> ce_idx; ce_idx.reset();

	// Content-Encoding Idx into the array
	ce_idx[0] = ce_bit[0];
	ce_idx[1] = ce_bit[1];
	ce_idx[2] = ce_bit[2];
	ce_idx[3] = ce_bit[3];

	// is there an empty value in the list of values/compression algorithms
	bool is_empty_value = ce_bit[4];

	std::bitset<3> total_plus; total_plus.reset();

	// total number of additional values up to 3
	total_plus[0] = ce_bit[5];
	total_plus[1] = ce_bit[6];
	total_plus[2] = ce_bit[7];

	std::vector<std::string> comment = {};

	if (ce_idx.to_ulong() == 15)
	{
		comment.push_back("the content-encoding header value is not in the list");
	}
	else
	{
		std::size_t idx = ce_idx.to_ulong() - 1;

		if (idx == 2)
		{
			comment.push_back("a <ae_grease_1> value was selected by the server");
		}
		else if (idx == 6)
		{
			comment.push_back("a <ae_grease_2> value was selected by the server");
		}
		else
		{
			if (p == "p6f")
			{
				json.UpdateString(jf(p + ".cont_enc_hdr.value"), request::header::accept_encoding_v.at(idx).c_str());
			}
			if (p == "p6l")
			{
				using namespace request::header;

				std::string ae_val = request::header::accept_encoding_v.at(idx); // full list

				auto it = std::find(std::begin(accept_encoding_v_less), std::end(accept_encoding_v_less), ae_val);

				if (it == std::end(accept_encoding_v_less))
				{
					comment.push_back("this chosen content-encoding value is not in the list sent to the server");
				}
				else
				{
					json.UpdateString(jf(p + ".cont_enc_hdr.value"), ae_val.c_str());
				}
			}
		}
	}

	json.UpdateBool(jf(p + ".cont_enc_hdr.empty_value"), is_empty_value);

	if (is_empty_value and (total_plus.to_ulong() > 0))
	{
		comment.push_back("at least one empty value exist");
	}

	// empty header value
	if (is_empty_value and (total_plus.to_ulong() == 0) and (ce_idx.to_ulong() == 15))
	{
		comment.push_back("the content-encoding header exist but with empty/no value");
	}

	if (total_plus.to_ulong() > 3)
	{
		comment.push_back("more than 3 additional compression algorithms are specified");
	}
	if ((total_plus.to_ulong() > 0) and (total_plus.to_ulong() < 4) and !is_empty_value)
	{
		comment.push_back("additional compression algorithm(s) are specified");
	}

	json.UpdateInt(jf(p + ".cont_enc_hdr.total_plus"), total_plus.to_ulong());

	for (std::size_t n = 0; n < comment.size(); ++n)
	{
		json.UpdateString(jf(p + ".cont_enc_hdr.cmt[" + std::to_string(n) + "]"), comment.at(n).c_str());
	}
}

void
demangler::get_allow_header
(
	CkJsonObject& json, const std::string& p, const std::string& ah, std::function<const char* (const std::string&)> jf
)
{
	json.UpdateString(jf(p + ".allow_hdr.fp"), ah.c_str());

	if (ah == "000000")
	{
		json.UpdateString(jf(p + ".allow_hdr.cmt"), "this header is not used");
		return;
	}
	if (ah == "999999")
	{
		json.UpdateString(jf(p + ".allow_hdr.cmt"), "the HTTP status line is not std conformant/not valid");
		return;
	}

	// allow header (size + type) fp
	std::string ah_sz_ty_fp = ah.substr(0, 2);

	json.UpdateString(jf(p + ".allow_hdr.hdr.fp"), ah_sz_ty_fp.c_str());

	std::bitset<8> ah_enc; ah_enc.reset(); ah_enc = std::stoi(ah_sz_ty_fp, nullptr, 16);

	std::bitset<5> allow_mthd_nb = {};

	allow_mthd_nb[0] = ah_enc[3]; allow_mthd_nb[1] = ah_enc[4];
	allow_mthd_nb[2] = ah_enc[5]; allow_mthd_nb[3] = ah_enc[6];
	allow_mthd_nb[4] = ah_enc[7];

	json.UpdateInt(jf(p + ".allow_hdr.hdr.methods.total"), allow_mthd_nb.to_ulong());

	// total number of allow headers values (across the three headers' types)
	std::string total_cmt = {};

	if (allow_mthd_nb.to_ulong() == 31)
	{
		total_cmt = "number of allowed methods chosen by the server is greater than 31";
	}
	else if (allow_mthd_nb.to_ulong() == 0)
	{
		total_cmt = "no allowed methods were chosen by the server";
	}
	else
	{
		total_cmt = "total number of allowed methods across all allow headers' types";
	}

	json.UpdateString(jf(p + ".allow_hdr.hdr.methods.total_cmt"), total_cmt.c_str());

	std::vector<std::string> ahs_v = {};

	if (ah_enc.test(0)) { ahs_v.push_back("allow"); }
	if (ah_enc.test(1)) { ahs_v.push_back("access-control-allow-methods"); }
	if (ah_enc.test(2)) { ahs_v.push_back("public"); }

	for (std::size_t i = 0; i < ahs_v.size(); ++i)
	{
		json.UpdateString(jf(p + ".allow_hdr.hdr.hdrs[" + std::to_string(i) + "]"), ahs_v[i].c_str());
	}

	const std::string hash = ah.substr(2, 4);
	json.UpdateString(jf(p + ".allow_hdr.hdr.methods.hash"), hash.c_str());

	if (demangler::load_options)
	{
		auto opt_htype = demangler::csv::get_opt_values(demangler::csv::opt_file, hash);

		for (std::size_t i = 0; i < opt_htype.allow_h.size(); ++i)
		{
			json.UpdateString(jf(p + ".allow_hdr.hdrs_value.allow[" + std::to_string(i) + "]"), opt_htype.allow_h[i].c_str());
		}

		for (std::size_t i = 0; i < opt_htype.acam_h.size(); ++i)
		{
			json.UpdateString(jf(p + ".allow_hdr.hdrs_value.access-control-allow-methods[" + std::to_string(i) + "]"), opt_htype.acam_h[i].c_str());
		}

		for (std::size_t i = 0; i < opt_htype.public_h.size(); ++i)
		{
			json.UpdateString(jf(p + ".allow_hdr.hdrs_value.public[" + std::to_string(i) + "]"), opt_htype.public_h[i].c_str());
		}
	}
}

bool
demangler::validate(const std::string& fp)
{
	bool verbosus_t = false;
	bool pacto_t = false;

	if (fp.starts_with(fingerprint::version::verbosus))
	{
		verbosus_t = true;
	}
	else if (fp.starts_with(fingerprint::version::pacto))
	{
		pacto_t = true;
	}
	else
	{
		std::cout << "+ The fp: \"" << fp << "\" is neither of the types: verbosus or pacto." << std::endl;
		return false;
	}

	bool pass = true;

	if (verbosus_t)
	{
		if (fp.length() != 76)
		{
			std::cout << "+ The verbosus fp: \"" << fp << "\" length of " << fp.length() << " is not valid. It should be 76." << std::endl;
			pass = false;
		}

		if (std::find_if(fp.begin(), fp.end(), [](const char& c) { return !isxdigit(c); }) != fp.end())
		{
			std::cout << "+ The verbosus fp: \"" << fp << "\" contains non-hex digits." << std::endl;
			pass = false;
		}
	}

	if (pacto_t)
	{
		if (fp.length() != 32)
		{
			std::cout << "+ The pacto fp: \"" << fp << "\" length of " << fp.length() << " is not valid. It should be 32." << std::endl;
			pass = false;
		}

		if (std::find_if(fp.begin(), fp.end(), [](const char& c) { return !isxdigit(c); }) != fp.end())
		{
			std::cout << "+ The pacto fp: \"" << fp << "\" contains non-hex digits." << std::endl;
			pass = false;
		}
	}
	return pass;
}

void
demangler::demangle(CkJsonObject& json, std::size_t i /*index*/, const std::string& fp)
{
	using namespace fingerprint;

	std::string fi = ("fingerprints[" + std::to_string(i) + "].");

	auto all_zero = [](const std::string& s) -> bool
		{
			return std::all_of(s.begin(), s.end(), [](const char& c) {return (c == '0'); });
		};

	if (!validate(fp)) { return; }

	if (fp.starts_with(fingerprint::version::verbosus))
	{
		using namespace demangler::status_line;

		// json fingerprint path: fingerprints[<idx>].<key>
		auto jf = [&fi](const std::string& k)-> const char* { static std::string t; t = (fi + k);  return t.c_str(); };

		auto type_fp = [&](const std::string& p, const std::string& t, const std::string& fp) -> void
			{
				json.UpdateString(jf(p + ".type"), t.c_str());
				json.UpdateString(jf(p + ".fp"), fp.c_str());
			};

		json.UpdateString(jf("type"), "verbosus");
		json.UpdateString(jf("fp"), fp.c_str());

		auto status_line = [&](const std::string& p, const std::string& s) -> void
			{
				json.UpdateString(jf(p + ".status_line.http_version.fp"), s.substr(0, 2).c_str());
				json.UpdateString(jf(p + ".status_line.http_version.val_cmt"), get_http_version(s[0], s[1]).c_str());
				json.UpdateString(jf(p + ".status_line.status_code.fp"), s.substr(2, 2).c_str());
				json.UpdateString(jf(p + ".status_line.status_code.val_cmt"), get_status_code(s.substr(2, 2)).c_str());
				json.UpdateString(jf(p + ".status_line.http_reason.fp"), s.substr(4, 4).c_str());
				json.UpdateString(jf(p + ".status_line.http_reason.val_cmt"), get_reason(s.substr(2, 2), s.substr(4, 4)).c_str());

				// add sl_reversed_db path
				std::string reason_hash = s.substr(4, 4);

				if (demangler::load_status_line)
				{
					if (reason_hash != "0000" and reason_hash != "0001" and reason_hash != "0002")
					{
						auto [ver, scode, reason] = demangler::csv::get_status_line(demangler::csv::sl_file, reason_hash);

						json.UpdateString(jf(p + ".status_line.sl_reversed_db.http_version"), ver.c_str());

						auto scodes_v = demangler::csv::get_status_code(scode);

						for (std::size_t i = 0; i < scodes_v.size(); ++i)
						{
							json.UpdateInt(jf(p + ".status_line.sl_reversed_db.status_code[" + std::to_string(i) + "]"), scodes_v.at(i));
						}
						json.UpdateString(jf(p + ".status_line.sl_reversed_db.http_reason"), reason.c_str());
					}
				}
			};

		// check in case the fp is all zeros
		if (all_zero(fp.substr(2, fp.size() - 2)))
		{
			json.UpdateString(jf("cmt"), "no response from the server, or something went wrong");
			return;
		}

		// ------ connection ------
		const std::string cnx_fp = fp.substr(72, 4);
		std::bitset<5> keep_alive, conx_close; keep_alive.reset(), conx_close.reset();

		keep_alive = std::stoi(cnx_fp.substr(0, 2), nullptr, 16);
		conx_close = std::stoi(cnx_fp.substr(2, 2), nullptr, 16);

		auto check_cnx = [&](const std::string& p, const std::size_t& i, const std::string& fp) -> void
			{
				json.UpdateBool(jf(p + ".cnx.ka"), keep_alive.test(i) ? true : false);
				json.UpdateBool(jf(p + ".cnx.c"), conx_close.test(i) ? true : false);
			};
		// ------ connection ------

		// P1
		std::string p1_fp = fp.substr(2, 10);

		type_fp("p1", request::stype::p1_get_normal, p1_fp);

		if (all_zero(p1_fp))
		{
			json.UpdateString(jf("p1.cmt"), "no response from the server or something went wrong");
		}
		else
		{
			status_line("p1", p1_fp);
			demangler::get_strict_transport_security_header(json, "p1", p1_fp.substr(8, 2), jf);
		}

		// P2
		std::string p2_fp = fp.substr(12, 10);

		type_fp("p2", request::stype::p2_get_invalid_ver_nb, p2_fp);
		if (all_zero(p2_fp))
		{
			json.UpdateString(jf("p2.cmt"), "no response from the server or something went wrong");
		}
		else
		{
			status_line("p2", p2_fp);
			demangler::get_content_length(json, "p2", p2_fp.substr(8, 2), jf);
			check_cnx("p2", 0, cnx_fp);
		}

		// P3
		std::string p3_fp = fp.substr(22, 10);

		type_fp("p3", request::stype::p3_get_rnd_resource, p3_fp);
		if (all_zero(p3_fp))
		{
			json.UpdateString(jf("p3.cmt"), "no response from the server or something went wrong");
		}
		else
		{
			status_line("p3", p3_fp);
			demangler::get_content_length(json, "p3", p3_fp.substr(8, 2), jf);
			check_cnx("p3", 1, cnx_fp);
		}

		// P4
		std::string p4_fp = fp.substr(32, 10);

		type_fp("p4", request::stype::p4_get_rnd_verb, p4_fp);

		if (all_zero(p4_fp))
		{
			json.UpdateString(jf("p4.cmt"), "no response from the server or something went wrong");
		}
		else
		{
			status_line("p4", p4_fp);
			demangler::get_content_length(json, "p4", p4_fp.substr(8, 2), jf);
			check_cnx("p4", 2, cnx_fp);
		}

		// P5
		std::string p5_fp = fp.substr(42, 10);

		type_fp("p5", request::stype::p5_get_lowercase_verb, p5_fp);
		if (all_zero(p5_fp))
		{
			json.UpdateString(jf("p5.cmt"), "no response from the server or something went wrong");
		}
		else
		{
			status_line("p5", p5_fp);
			demangler::get_content_length(json, "p5", p5_fp.substr(8, 2), jf);
			check_cnx("p5", 3, cnx_fp);
		}

		// P6f
		std::string p6f_fp = fp.substr(52, 2);
		type_fp("p6f", request::stype::p6_get_accept_encoding_full, p6f_fp);
		demangler::get_content_encoding(json, "p6f", p6f_fp, jf);

		// P6l
		std::string p6l_fp = fp.substr(54, 2);
		type_fp("p6l", request::stype::p6_get_accept_encoding_less, p6l_fp);
		demangler::get_content_encoding(json, "p6l", p6f_fp, jf);

		// P7a
		std::string p7a_fp = fp.substr(56, 16);

		type_fp("p7a", request::stype::p7_options_allow_hdr, p7a_fp);
		if (all_zero(p7a_fp))
		{
			json.UpdateString(jf("p7a.cmt"), "no response from the server or something went wrong");
		}
		else
		{
			status_line("p7a", p7a_fp);
			demangler::get_content_length(json, "p7a", p7a_fp.substr(8, 2), jf);
			demangler::get_allow_header(json, "p7a", p7a_fp.substr(10, 6), jf);
			check_cnx("p7a", 4, cnx_fp);
		}
		return;
	}
	if (fp.starts_with(fingerprint::version::pacto))
	{
		json.UpdateString((fi + "type").c_str(), "pacto");
		json.UpdateString((fi + "fp").c_str(), fp.c_str());
		if (all_zero(fp.substr(2, fp.size() - 2)))
		{
			json.UpdateString((fi + "cmt").c_str(), "no response from the server, or something went wrong");
		}
		return;
	}
}

void
demangler::demangle_txt(const std::string& fp)
{
	if (!demangler::validate(fp))
	{
		std::exit(1);
	}

	if (fp.starts_with(fingerprint::version::verbosus))
	{
		std::cout << "P1: " << fp.substr(2, 10) << std::endl;
		std::cout << "P2: " << fp.substr(12, 10) << std::endl;
		std::cout << "P3: " << fp.substr(22, 10) << std::endl;
		std::cout << "P4: " << fp.substr(32, 10) << std::endl;
		std::cout << "P5: " << fp.substr(42, 10) << std::endl;

		std::cout << "P6: " << fp.substr(52, 2) << std::endl;
		std::cout << "P7: " << fp.substr(54, 2) << std::endl;
		std::cout << "P8: " << fp.substr(56, 16) << std::endl;

		std::cout << "Cn: " << fp.substr(72, 4) << std::endl;
	}
}

void
demangler::json::build_prolog(CkJsonObject& json, const std::size_t t)
{
	json.UpdateString("title", "Fingerprints Demangler");
	json.UpdateString("author", "HTTP-Basma");

	std::string ver = prog_about::prog_version + " (" + prog_about::arch + ") - rel: " +
		prog_about::prog_edition + " - " +
		prog_about::prog_release_date;

	json.UpdateString("version", ver.c_str());
	json.UpdateString("starting_date", helper::get_date().c_str());
	json.UpdateString("starting_time", helper::get_time().c_str());
	json.UpdateUInt("fingerprints_total", t);
}

void
demangler::json::emit_to_console(CkJsonObject& json)
{
	json.put_EmitCompact(false);
	std::cout << json.emit() << std::endl;
}

bool
demangler::csv::load_options_hashes(CkCsv& csv)
{
	// domain,allow_fp,hash,allow_h,acam_h,public_h	
	csv.put_HasColumnNames(true);
	csv.put_Delimiter(",");
	csv.put_EnableQuotes(true);
	csv.put_Utf8(true);

	if (!csv.LoadFile2("options.csv", "utf-8"))
	{
		std::cout << "failed to load \"options.csv\" file. turning off p7a options header demangling feature" << std::endl;
		return false;
	}
	else
	{
		return true;
	}
}

bool
demangler::csv::load_status_line_db(CkCsv& csv)
{
	// domain,sl_hash,sl_ver,sl_code,sl_reason
	csv.put_HasColumnNames(true);
	csv.put_Delimiter(",");
	csv.put_EnableQuotes(true);
	csv.put_Utf8(true);

	if (!csv.LoadFile2("status_line_db.csv", "utf-8"))
	{
		std::cout << "failed to load \"status_line_db.csv\" file. turning off HTTP status line demangling feature" << std::endl;
		return false;
	}
	else
	{
		return true;
	}
}

demangler::csv::allow_hdrs
demangler::csv::get_opt_values(CkCsv& csv, const std::string& hash)
{
	auto get_m_val = [](const std::string& opt_hv, auto& hdr_v) -> void
		{
			std::istringstream mlist(opt_hv);
			std::string hval = {};

			while (std::getline(mlist, hval, ';'))
			{
				if (hval.back() == '\r')
				{
					hval.erase(hval.size() - 1);
				}
				// hval holds the list of methods, verbatim
				hdr_v.push_back(hval);
			}
		};

	int nb_rows = csv.get_NumRows();

	using namespace demangler::csv;

	allow_hdrs hdr_type;

	for (int i = 0; i < nb_rows; ++i)
	{
		if (hash == csv.getCellByName(i, opt_c::hash.c_str()))
		{
			get_m_val(csv.getCellByName(i, opt_c::allow.c_str()), hdr_type.allow_h);
			get_m_val(csv.getCellByName(i, opt_c::acam.c_str()), hdr_type.acam_h);
			get_m_val(csv.getCellByName(i, opt_c::hpublic.c_str()), hdr_type.public_h);

			return hdr_type;
		}
	}
	return allow_hdrs{};
}

std::tuple<std::string, std::string, std::string>
demangler::csv::get_status_line(CkCsv& csv, const std::string& hash)
{
	int nb_rows = csv.get_NumRows();

	using namespace demangler::csv;

	std::string ver, scode, reason;

	for (int i = 0; i < nb_rows; ++i)
	{
		if (hash == csv.getCellByName(i, sl_c::hash.c_str()))
		{
			ver = csv.getCellByName(i, sl_c::ver.c_str());
			scode = csv.getCellByName(i, sl_c::code.c_str());
			reason = csv.getCellByName(i, sl_c::reason.c_str());

			return { ver,scode,reason };
		}
	}
	return {};
}

std::vector<std::uint16_t>
demangler::csv::get_status_code(const std::string& scode)
{
	std::vector<std::uint16_t> scodes;

	std::istringstream scodes_list(scode);
	std::string sc = {};

	while (std::getline(scodes_list, sc, ','))
	{
		if (!sc.empty()) { scodes.push_back(std::stoi(sc)); }
	}
	return scodes;
}
