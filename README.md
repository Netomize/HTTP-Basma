<div align="center">
  <img src="Logo/logo.png" alt="HTTP-Basma Logo" width="200" height="200">
</div>

# Adaptive Fingerprinting: HTTP-Basma's Multi-Stage Probing for Granular Server Differentiation

# Introduction

In the realm of cybersecurity, accurately identifying and characterizing web servers is crucial for threat detection, vulnerability assessment, and network mapping. We introduce HTTP-Basma, a novel active fingerprinting algorithm that unveils unique server profiles through a multi-layered approach, thereby addressing this challenge.

Key Features:
Crafted Requests, Revealing Responses: HTTP-Basma sends 8 meticulously designed HTTP probes, eliciting distinctive responses that reflect server configurations.
Dual Hashing for Versatility. The algorithm generates two hashes:

  -	A 38-byte fuzzy hash, "verbosus", offering reversibility
  -	A 16-byte one-way hash, "pacto", derived from verbosus, enhancing privacy and security

Clustering and Hunting: These hashes empower server clustering, identification of unique and similar servers, and the pursuit of malicious actors with heightened confidence.

Modular Design for Expansion: The algorithm's architecture fosters the addition of new hashing variants, encouraging collaboration and adaptability.
In this paper, we first survey notable existing work on HTTP fingerprinting and then explore the algorithm's functionality, design, architecture, and outcomes. Additionally, we will showcase some compelling findings from scanning the top 1 million Majestic websites, including the identification and clustering of various malware families' C&C HTTP servers. The source code and supporting data will be made available.

---

HTTP-Basma’s algorithm's core idea centers on sending 8 specially crafted HTTP requests with different requirements to solicit different responses from the server. Once the server response is retrieved, the HTTP status line is surgically dissected for all elements and encoded optimally. Additionally, select headers from the server response are checked for encoding as well.

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

The full technical details of how the algorithm works are in the attached paper.

Sample of fingerprints:

[**CobaltStrike**](https://www.cobaltstrike.com/)
```
  - verbosus fp: 011420958a0014514bd5221420958a221420958a221420958a2200001420958a22000000001f
  - pacto fp: 02464ae8b7d86f82c9918e2c2b9d6b91
  - note: false-positive rate 0.0072 (72/1-million)
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
  - note: false-positive rate 0.0073 (73/1-million)
```

---

# Release

Netomize ships a Windows x64 compiled version of the public code in this repo.

# Third-party libraries used

- [Chilkat v11.4.0](https://www.chilkatsoft.com/)
- [Color Console: for console coloring](https://github.com/imfl/color-console)
- [cxxopts (v3.3.1)](https://github.com/jarro2783/cxxopts)

# Contributing

Open for pull requests and issues. Comments and suggestions are greatly appreciated.
