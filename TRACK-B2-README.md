# Track B-2: Aircrack-ng WiFi Security Auditing Extensions

This document describes the implementation of Track B-2 extensions to Aircrack-ng, adding three new features for WiFi security auditing.

## Features Implemented

### 1. RSN IE Extractor (`--rsn-csv`)

Extracts Robust Security Network (RSN) Information Elements from beacon and probe response frames and outputs them in CSV format.

**Usage:**
```bash
./aircrack-ng --rsn-csv output.csv capture.pcap
```

**Output Format:**
- BSSID: Access Point MAC address
- SSID: Network name 
- Channel: WiFi channel number
- GroupCipher: Group cipher suite (hex format)
- PairwiseCiphers: Pairwise cipher suites (semicolon separated)
- AKMSuites: Authentication and Key Management suites (semicolon separated)
- MFPC: Management Frame Protection Capable (0/1)
- MFPR: Management Frame Protection Required (0/1)

**Example Output:**
```csv
BSSID,SSID,Channel,GroupCipher,PairwiseCiphers,AKMSuites,MFPC,MFPR
00:11:22:33:44:55,"TestNetwork",6,000FAC02,"000FAC04","000FAC02",1,0
```

### 2. EAP/EAPOL Flow Summarizer (`--eap-summary`)

Analyzes EAP (Extensible Authentication Protocol) and EAPOL (EAP over LAN) flows per client and outputs detailed analysis in JSON format.

**Usage:**
```bash
./aircrack-ng --eap-summary analysis.json capture.pcap
```

**Analysis Includes:**
- EAP Identity presence and extraction
- EAP method detection (PEAP, EAP-TLS, TTLS, etc.)
- Outer TLS tunnel detection
- 4-way handshake presence
- Packet counts and timestamps

**Example Output:**
```json
{
  "eap_clients": [
    {
      "client_mac": "AA:BB:CC:DD:EE:FF",
      "ap_mac": "00:11:22:33:44:55",
      "first_seen_us": 1634567890000000,
      "last_seen_us": 1634567900000000,
      "has_eap_identity": true,
      "eap_identity": "user@domain.com",
      "eap_method": 25,
      "has_outer_tls": true,
      "has_fourway_handshake": true,
      "eap_packets": 15,
      "eapol_packets": 20
    }
  ],
  "summary": {
    "total_clients": 1
  }
}
```

### 3. PCAP Sanitizer/Anonymizer (`--anonymize`)

Creates anonymized versions of packet capture files with deterministic MAC address pseudonyms and redacted EAP identity strings.

**Usage:**
```bash
./aircrack-ng --anonymize anonymized.pcap capture.pcap
```

**Features:**
- Deterministic MAC address pseudonymization (consistent across runs)
- EAP identity string redaction (replaced with 'X' characters)
- Automatic generation of MAC mapping file (`anonymized.pcap.mapping`)
- Preserves packet structure and timing

**Mapping File Format:**
```
# MAC Address Mapping File
# Original MAC -> Anonymized MAC
00:11:22:33:44:55 -> 02:AB:CD:EF:12:34
AA:BB:CC:DD:EE:FF -> 02:12:34:56:78:9A
```

## Implementation Details

### Code Changes

#### Header File Changes (`include/aircrack-ng/aircrack-ng.h`)
- Added new options structure fields for Track B-2 features
- Added file path storage for output files
- Added feature flags for each extension

#### Main Implementation (`src/aircrack-ng/aircrack-ng.c`)
- **RSN IE Extraction**: Added `extract_rsn_ie()` function that parses IEEE 802.11 Information Elements
- **EAP Analysis**: Added `analyze_eap_packet()` and related functions for EAP/EAPOL flow tracking
- **Anonymization**: Added complete PCAP processing pipeline with MAC mapping and identity redaction
- **Command Line Interface**: Extended getopt handling for new long options
- **File I/O**: Added proper file handling, CSV/JSON output formatting

### Technical Approach

1. **Packet Processing Integration**: Leveraged existing packet parsing infrastructure
2. **Memory Management**: Proper allocation/deallocation of data structures
3. **Standards Compliance**: Followed IEEE 802.11 and EAP RFC specifications
4. **Error Handling**: Comprehensive error checking and resource cleanup
5. **Performance**: Minimal impact on existing functionality

## Building and Testing

### Requirements
- Standard Aircrack-ng build dependencies
- No additional libraries required

### Build Process
```bash
# Generate configure script (if needed)
./autogen.sh

# Configure build
./configure --enable-maintainer-mode

# Build
make -j6

# Test (requires sample PCAP files)
make check
```

### Testing Commands

```bash
# Test RSN extraction
./aircrack-ng --rsn-csv test-rsn.csv sample-wpa.pcap

# Test EAP analysis  
./aircrack-ng --eap-summary test-eap.json sample-eap.pcap

# Test anonymization
./aircrack-ng --anonymize anonymized.pcap sample.pcap
```

## File Structure

```
track-b2-aircrack-ng-extensions.patch  # Complete diff patch
include/aircrack-ng/aircrack-ng.h      # Modified header
src/aircrack-ng/aircrack-ng.c          # Modified main implementation
TRACK-B2-README.md                     # This documentation
```

## Compliance and Standards

- **IEEE 802.11**: RSN IE parsing follows IEEE 802.11-2016 standard
- **RFC 3748**: EAP packet analysis follows RFC 3748 specifications
- **RFC 5216**: EAP-TLS detection per RFC 5216
- **Privacy**: Anonymization provides k-anonymity while preserving analysis utility

## Future Enhancements

Potential improvements for future versions:
- Support for additional EAP methods
- Advanced RSN capability parsing
- Configurable anonymization strategies
- Integration with other Aircrack-ng tools
- Performance optimizations for large captures

## Author

Implemented as part of Track B-2 WiFi Security Auditing Extensions project.

## License

Same as Aircrack-ng: GNU General Public License v2.0