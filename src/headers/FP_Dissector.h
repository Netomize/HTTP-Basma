/*
	file       FP_Dissector.h
	author     Mohamad Mokbel (mfmokbel@netomize.ca)
	brief      HTTP-Basma v1.0

	details    structures for the dissection of the fingerprint

			   See LICENSE file in top level directory for details.

	copyright  Netomize. Copyright (c) 2026.  All rights reserved.
*/

#pragma once

struct status_line
{
	std::string sl_version;
	std::string sl_status_code;
	std::string sl_reason_phrase;

	bool operator==(const status_line& other) const
	{
		return (sl_version == other.sl_version and sl_status_code == other.sl_status_code and sl_reason_phrase == other.sl_reason_phrase);
	}
	bool operator!=(const status_line& other) const
	{
		return !(*this == other);
	}
};

struct content_length
{
	char name;
	char length;

	bool operator==(const content_length& other) const
	{
		return (name == other.name and length == other.length);
	}
	bool operator!=(const content_length& other) const
	{
		return !(*this == other);
	}
};

struct fp_dissected
{
	status_line p1_sl;
	std::string p1_sts;

	status_line p2_sl;
	content_length p2_clen;

	status_line p3_sl;
	content_length p3_clen;

	status_line p4_sl;
	content_length p4_clen;

	status_line p5_sl;
	content_length p5_clen;

	std::string p6f_cenc;

	std::string p6l_cenc;

	status_line p7a_sl;
	content_length p7a_clen;
	std::string p7a_allow_len;
	std::string p7a_allow_hash;

	std::string cn_keep_alive;
	std::string cn_close;
};

void
compare_sl(const status_line& sl1, const status_line& sl2)
{
	if (sl1.sl_version != sl2.sl_version)
	{
		std::cout << "      sl_version: " << sl1.sl_version << " != " << sl2.sl_version << std::endl;
	}
	if (sl1.sl_status_code != sl2.sl_status_code)
	{
		std::cout << "      sl_status_code: " << sl1.sl_status_code << " != " << sl2.sl_status_code << std::endl;
	}
	if (sl1.sl_reason_phrase != sl2.sl_reason_phrase)
	{
		std::cout << "      sl_reason_phrase: " << sl1.sl_reason_phrase << " != " << sl2.sl_reason_phrase << std::endl;
	}
}

void
compare_cl(const content_length& cl1, const content_length& cl2)
{
	if (cl1.name != cl2.name)
	{
		std::cout << "      cl_name: " << cl1.name << " != " << cl2.name << std::endl;
	}
	if (cl1.length != cl2.length)
	{
		std::cout << "      cl_length: " << cl1.length << " != " << cl2.length << std::endl;
	}
}
