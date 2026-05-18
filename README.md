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
