<div align="center">
  <img src="Logo/logo.png" alt="HTTP-Basma Logo" width="200" height="200">
</div>

# Adaptive Fingerprinting: HTTP-Basma's Multi-Stage Probing for Granular Server Differentiation

# Introduction

In the realm of cybersecurity, accurately identifying and characterizing web servers is crucial for threat detection, vulnerability assessment, and network mapping. We introduce **HTTP-Basma**, a novel active fingerprinting algorithm that unveils unique server profiles through a multi-layered approach, thereby addressing this challenge.

Key Features:
Crafted Requests, Revealing Responses: HTTP-Basma sends 8 meticulously designed HTTP probes, eliciting distinctive responses that reflect server configurations.
Dual Hashing for Versatility. The algorithm generates two hashes:

  -	A 38-byte fuzzy hash, "<ins>verbosus</ins>", offering reversibility
  -	A 16-byte one-way hash, "<ins>pacto</ins>", derived from verbosus, enhancing privacy and security

Clustering and Hunting: These hashes empower server clustering, identification of unique and similar servers, and the pursuit of malicious actors with heightened confidence.

Modular Design for Expansion: The algorithm's architecture fosters the addition of new hashing variants, encouraging collaboration and adaptability.
In this paper, we first survey notable existing work on HTTP fingerprinting and then explore the algorithm's functionality, design, architecture, and outcomes. Additionally, we will showcase compelling findings from [scanning the top 1 million Majestic websites](https://github.com/Netomize/HTTP-Basma/releases/download/v1.0/majestic_1_million_http_basma_fingerprints_csv.zip), including the identification and clustering of C&C HTTP servers for various malware families.

---

HTTP-Basma’s algorithm's core idea centers on sending 8 specially crafted HTTP requests with varying requirements to elicit different responses from the server. Once the server response is retrieved, the HTTP status line is surgically dissected for all elements and encoded optimally. Additionally, select headers from the server response are checked for encoding as well.

The requests it sends are of these types:

  1. **P1** - GET Normal - Valid Request
  2. **P2** - GET Invalid HTTP Version Request
  3. **P3** - GET Random Resource Request
  4. **P4** - Random Verb Request
  5. **P5** - get Lowercase Verb
  6. **P6** - GET Request - Accept-Encoding - Full
  7. **P7** - GET Request - Accept-Encoding - Less
  8. **P8** - OPTIONS Request

Following each request, the server's response is analyzed to extract specific headers and their values. This extracted data undergoes further processing, including dissection and encoding, to generate a reversible fingerprint.

The full technical details of how the algorithm works are in the attached [paper](https://github.com/Netomize/HTTP-Basma/blob/main/http-basma_paper_mfmokbel_v1.pdf).

Sample of fingerprints:

[**CobaltStrike**](https://www.cobaltstrike.com/)
```
  - verbosus fp: 011420958a0014514bd5221420958a221420958a221420958a2200001420958a22000000001f
  - pacto fp: 02464ae8b7d86f82c9918e2c2b9d6b91
  - note: false-positive rate (72/986,910)
```
[**Havoc**](https://github.com/HavocFramework/Havoc)
```
  - verbosus fp: 01142494d60914514bd522142494d6221420958a701420958a220000140e04922032c37f1609
  - pacto fp: 020769322f3d94ac2f258ddf5ce08502
  - note-1: false-positive rate 0
  - note-2: tevedadav.site/43.209.165.126:443 (TLS)
    - sample-(sha-256): 9aa1dec8dd12f8adc7fc1274e1958f3613450109ee8b4ec6442a0fcf06df0972
```

[**BruteRatel**](https://bruteratel.com/)
```
  - verbosus fp: 01140a85e40014512f3612140a85e422140a85e422140a85e4220000140a85e4220000000001
  - pacto fp: 0207292309a7a7e798e417d69df5f2a5
  - note: false-positive rate (73/986,910)
```

[**Google**](https://google.com/)
```
  - verbosus fp: 01140a85e4001320958a22142494d62214254c5e2214254c5e22080014254c5e220000000000
  - pacto fp: 0202be780e1eaae0eaa6184e20c909b6
  - note: false-positive rate (4/986,910)
```

[**YouTube**](https://youtube.com/)
```
  - verbosus fp: 01140a85e4011320958a22142494d67214254c5e2214254c5e22080014254c5e220000000000
  - pacto fp: 02cc5be6d05192e17de041538508bc22
  - note: false-positive rate (38/986,910)
```

[**X**](https://x.com/)
```
  - verbosus fp: 01140a85e40914514bd522140a85e4721420958a701420958a220800140a85e4720000001609
  - pacto fp: 0221b4e46bbd0e5c037f5a852ca3fdc0
  - note: false-positive rate (6/986,910)
```

# HTTP-Basma Tool

HTTP-Basma is a C++ tool I developed to showcase the practicality and viability of this algorithm. It leverages Chilkat's library for all HTTP socket interactions and utilizes other supporting classes within the library. Additionally, the tool includes a demangler feature that can dissect and reverse the verbosus fuzzy-hash, outputting a comprehensive JSON object, and a comparator function that outputs the differences between two verbosus fingerprints. 

Be aware that some output of the tool might use slightly different probe numbers, but the underlying order remains consistent: `P1->P1, P2->P2, P3->P3, P4->P4, P->P5, P6->P6F, P7->P6L, P8->P7a`.

## Tool's Options

<details>
<summary>click to expand</summary>
	
```	
Usage:
  HTTP-Basma [OPTION...]

  -d, --domain arg         domains/IPs (you may query multiple domains, comma separated)
  -p, --port arg           port number
  -s, --ssl                does the HTTP connection have to be carried over SSL/TLS?
  -q, --qpath              check domain with url path included (not recommended)
  -w, --redirect           enable/disable HTTP redirects. If disabled/false, only the next redirect is followed,
                           otherwise, all redirects are followed (default: true)
  -t, --ctimeout arg       socket connection timeout value in seconds (default: 1)
  -g, --rtimeout arg       socket read (from the server) timeout value in seconds (default: 1)
  -e, --sleep arg          the duration (in milliseconds) to pause between each request (default: 100)
  -x, --proxy arg          proxy config: <"socks4|socks5|http">,<domain>,<port>,<bool:direct_tls>,<login>,<pass>
                                         all values are comma-separated. <direct_tls> is ignored with a non-HTTP proxy
  -f, --file arg           file with list of domains/IPs (requires "-c/--csv" or "-j/--json")
  -P, --parallel           Scan list of domains passed via the "-f/--file" option in parallel
  -c, --csv                save to csv file; if the option 'n' is not specified, the CSV filename will be auto
                           generated
  -n, --csvfile arg        name of the CSV file
  -j, --json               save to json file; if the option 'l' is not specified, the JSON filename will be auto
                           generated
  -l, --jsonfile arg       name of the JSON file
  -r, --saveh              save request response headers
  -o, --pjson              display fingerprint dissection to the console as a JSON object
  -i, --demangle_json arg  demangle a fingerprint into a detailed json format (you can have more than one, comma
                           separated)
  -u, --demangle_txt arg   output a concise text format of the fingerprint, comma-separated for multiple results
  -C, --compare arg        compare two verbosus fingerprints (comma-separated)
  -a, --pacto arg          obtain the Pacto fingerprint using Verbosus
  -h, --help               print usage	
```

</details>

## Detailed Output

When requesting a given domain/IP, the response could be saved to a CSV or JSON file with a plethora of information about the server response headers and each probe’s unique fingerprint.

For example, to get the fingerprint of the server https://google.com, and save the results to a JSON and CSV file, while saving the HTTP response headers of every probe:

```
HTTPBasma.exe -d https://google.com --json --csv --saveh
```

In the folder `Output`, you'll find the CSV file [google_hb_results_2026-05-19_08-35-38_am.csv](https://github.com/Netomize/HTTP-Basma/blob/main/Output/google_hb_results_2026-05-19_08-35-38_am.csv) and the JSON file [google_hb_results_2026-05-19_08-35-38_am.json](https://github.com/Netomize/HTTP-Basma/blob/main/Output/google_hb_results_2026-05-19_08-35-38_am.json).

## The Demangler

The tool's demangler function "-i/--demangle_json" takes a verbosus fingerprint and reconstructs the attributes of each probe, outputting a comprehensive JSON object. Notably, when attempting to reverse the FNV-1a hashes, the demangler utilizes two local databases: `options.csv` for allowed HTTP methods and `status_line_db.csv` for status-line reason phrases. If either of these database files is missing, the corresponding hash reversal feature is automatically disabled. These databases were compiled from a scan of the top 1 million Majestic websites.

The demangling of the verbosus’s fingerprint, for the domain example.com:

```
HTTPBasma.exe --demangle_json 01140a85e40014514bd522142494d67214254c5e721420958a22020214254c5e720000001609
```

<details>
<summary>Demangler Output (click to expand)</summary>
  
```json
{
  "type": "verbosus",
  "fp": "01140a85e40014514bd522142494d67214254c5e721420958a22020214254c5e720000001609",
  "p1": {
    "type": "get_normal",
    "fp": "140a85e400",
    "status_line": {
      "http_version": {
        "fp": "14",
        "val_cmt": "HTTP/1.1"
      },
      "status_code": {
        "fp": "0a",
        "val_cmt": "200"
      },
      "http_reason": {
        "fp": "85e4",
        "val_cmt": "OK"
      },
      "sl_reversed_db": {
        "http_version": "HTTP/1.1",
        "status_code": [
          200,
          404,
          403,
          500,
          204,
          999,
          888,
          603
        ],
        "http_reason": "OK"
      }
    },
    "sts_hdr": {
      "fp": "00",
      "cmt": "this header is not used"
    }
  },
  "p2": {
    "type": "get_invalid_ver_nb",
    "fp": "14514bd522",
    "status_line": {
      "http_version": {
        "fp": "14",
        "val_cmt": "HTTP/1.1"
      },
      "status_code": {
        "fp": "51",
        "val_cmt": "505"
      },
      "http_reason": {
        "fp": "4bd5",
        "val_cmt": "HTTP Version Not Supported"
      },
      "sl_reversed_db": {
        "http_version": "HTTP/1.1",
        "status_code": [
          505
        ],
        "http_reason": "HTTP Version Not Supported"
      }
    },
    "cont_len_hdr": {
      "fp": "22",
      "name": "Content-Length",
      "value": ">1",
      "cmt": "content-length/transfer-encoding:chunked header is present with either of the size values: [0,1,>1]"
    },
    "cnx": {
      "ka": false,
      "c": true
    }
  },
  "p3": {
    "type": "get_rnd_resource",
    "fp": "142494d672",
    "status_line": {
      "http_version": {
        "fp": "14",
        "val_cmt": "HTTP/1.1"
      },
      "status_code": {
        "fp": "24",
        "val_cmt": "404"
      },
      "http_reason": {
        "fp": "94d6",
        "val_cmt": "Not Found"
      },
      "sl_reversed_db": {
        "http_version": "HTTP/1.1",
        "status_code": [
          404,
          403,
          501,
          410,
          204,
          400,
          200,
          418
        ],
        "http_reason": "Not Found"
      }
    },
    "cont_len_hdr": {
      "fp": "72",
      "name": "Transfer-Encoding",
      "value": ">1",
      "cmt": "content-length/transfer-encoding:chunked header is present with either of the size values: [0,1,>1]"
    },
    "cnx": {
      "ka": true,
      "c": false
    }
  },
  "p4": {
    "type": "get_rnd_verb",
    "fp": "14254c5e72",
    "status_line": {
      "http_version": {
        "fp": "14",
        "val_cmt": "HTTP/1.1"
      },
      "status_code": {
        "fp": "25",
        "val_cmt": "405"
      },
      "http_reason": {
        "fp": "4c5e",
        "val_cmt": "Method Not Allowed"
      },
      "sl_reversed_db": {
        "http_version": "HTTP/1.1",
        "status_code": [
          405,
          403,
          204,
          418,
          404
        ],
        "http_reason": "Method Not Allowed"
      }
    },
    "cont_len_hdr": {
      "fp": "72",
      "name": "Transfer-Encoding",
      "value": ">1",
      "cmt": "content-length/transfer-encoding:chunked header is present with either of the size values: [0,1,>1]"
    },
    "cnx": {
      "ka": true,
      "c": false
    }
  },
  "p5": {
    "type": "get_lowercase_verb",
    "fp": "1420958a22",
    "status_line": {
      "http_version": {
        "fp": "14",
        "val_cmt": "HTTP/1.1"
      },
      "status_code": {
        "fp": "20",
        "val_cmt": "400"
      },
      "http_reason": {
        "fp": "958a",
        "val_cmt": "Bad Request"
      },
      "sl_reversed_db": {
        "http_version": "HTTP/1.1",
        "status_code": [
          400,
          422,
          405,
          401
        ],
        "http_reason": "Bad Request"
      }
    },
    "cont_len_hdr": {
      "fp": "22",
      "name": "Content-Length",
      "value": ">1",
      "cmt": "content-length/transfer-encoding:chunked header is present with either of the size values: [0,1,>1]"
    },
    "cnx": {
      "ka": false,
      "c": true
    }
  },
  "p6f": {
    "type": "get_accept_encoding_full",
    "fp": "02",
    "cont_enc_hdr": {
      "value": "br",
      "empty_value": false,
      "total_plus": 0
    }
  },
  "p6l": {
    "type": "get_accept_encoding_less",
    "fp": "02",
    "cont_enc_hdr": {
      "value": "br",
      "empty_value": false,
      "total_plus": 0
    }
  },
  "p7a": {
    "type": "options_allow_hdr",
    "fp": "14254c5e72000000",
    "status_line": {
      "http_version": {
        "fp": "14",
        "val_cmt": "HTTP/1.1"
      },
      "status_code": {
        "fp": "25",
        "val_cmt": "405"
      },
      "http_reason": {
        "fp": "4c5e",
        "val_cmt": "Method Not Allowed"
      },
      "sl_reversed_db": {
        "http_version": "HTTP/1.1",
        "status_code": [
          405,
          403,
          204,
          418,
          404
        ],
        "http_reason": "Method Not Allowed"
      }
    },
    "cont_len_hdr": {
      "fp": "72",
      "name": "Transfer-Encoding",
      "value": ">1",
      "cmt": "content-length/transfer-encoding:chunked header is present with either of the size values: [0,1,>1]"
    },
    "allow_hdr": {
      "fp": "000000",
      "cmt": "this header is not used"
    },
    "cnx": {
      "ka": true,
      "c": false
    }
  }
}
```
</details>

Observe that the "status_code" array contains multiple HTTP status codes. This occurs because different servers might use the same reason phrase for different status codes, resulting in identical FNV-1a hashes.

## The Comparator Option

The comparator option "-C/--compare" compares two verbosus fingerprints and prints out the differences across the major components for each of the probes.

For example, comparing the following two fingerprints for Google and YouTube:

```
HTTPBasma.exe --compare 01140a85e4001320958a22142494d62214254c5e2214254c5e22080014254c5e220000000000,01140a85e4011320958a22142494d67214254c5e2214254c5e22080014254c5e220000000000
```

Results in this output:

```
 < FPrnt-1 Vs. FPrnt-2 >

 [ P1 ]
    {Strict-Transport-Security}
      sts header: 00 != 01

 [ P2 ]
 [ P3 ]
    {Content-Length}

      cl_name: 2 != 7

 [ P4 ]
 [ P5 ]
 [ P6F ]
 [ P6L ]
 [ P7a ]
```

The output reveals differences specifically in the hash component of the P1 probe, where the STS header is present in the first fp and not the other. Moreover, the encoding of the "Content-Length" is different between the two fingerprints for probe P3.

---

# Release

Netomize provides compiled Windows and Linux x64 versions of the public code in this repository. Moreover, the [majestic 1-million HTTP-Basma fingerprints CSV File - data set](https://github.com/Netomize/HTTP-Basma/releases/download/v1.0/majestic_1_million_http_basma_fingerprints_csv.zip) is shipped in the first release.

# Third-party libraries used

- [Chilkat v11.4.0](https://www.chilkatsoft.com/)
- [rang: for console coloring](https://github.com/agauniyal/rang)
- [cxxopts (v3.3.1)](https://github.com/jarro2783/cxxopts)

# Contributing

Open for pull requests and issues. Comments and suggestions are greatly appreciated.
