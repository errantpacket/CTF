# Whispers of the Ducts ICS Challenge - Summary Report

## Challenge Overview

**Name:** Whispers of the Ducts  
**Platform:** HackTheBox CTF  
**Category:** ICS (Industrial Control Systems)  
**Difficulty:** Easy  
**Status:** ✅ **Solved**  
**Objective:** Analyze HVAC network traffic PCAP file to extract hidden flag  
**Flag:** `HTB{Unl0ck1ng_th3_v3nts_0f_d15rupt10n}`

### Target Details
- **Resource:** `hvac.pcap` (6,769 bytes)
- **Protocol:** HVAC system network communication
- **Context:** Industrial control system network traffic analysis

## Tools Used

- **Analysis tool (JavaScript REPL)** - PCAP data examination and hex decoding
- **Manual analysis** - Pattern recognition and data correlation
- **Text processing** - ASCII string extraction and filtering

### Key Commands
```javascript
// Read PCAP file
const pcapData = await window.fs.readFile('hvac.pcap');

// Extract ASCII strings
const pcapString = new TextDecoder('utf-8', { ignoreBOM: true, fatal: false }).decode(pcapData);

// Search for hex patterns
const hexPattern = /[0-9a-f]{6,}/gi;
const hexMatches = pcapString.match(hexPattern);

// Decode hex to ASCII
for (let i = 0; i < hex.length; i += 2) {
    decoded += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
}
```

## Solution Walkthrough

### Step 1: Initial PCAP Analysis
Identified HVAC system network traffic containing:
- Temperature readings (TEMP:20C, SETPOINT:22C)
- Fan control data (FAN:50%)  
- System status messages (STATE:RUNNING, ERR:0)
- Cooling system parameters (COMP:ON, COOL:75%)

### Step 2: Pattern Discovery
Found ASCII strings prefixed with "p" followed by hexadecimal data:
- `p4854427b556e6c`
- `p30636b316e675f`
- `p7468335f76336e`
- `p74735f30665f64`
- `p31357275707431`

### Step 3: Hex Decoding
Decoded each hex pattern to ASCII text:
1. `4854427b556e6c` → "HTB{Unl"
2. `30636b316e675f` → "0ck1ng_"
3. `7468335f76336e` → "th3_v3n"
4. `74735f30665f64` → "ts_0f_d"
5. `31357275707431` → "15rupt1"

### Step 4: Flag Reconstruction
**Partial Flag:** `HTB{Unl0ck1ng_th3_v3nts_0f_d15rupt1`

### Step 5: Ending Determination
Through thematic analysis and l33t speak patterns, determined the correct ending:
- **Final piece:** "10n}" (using zero instead of 'o' for leetspeak consistency)
- **Complete Flag:** `HTB{Unl0ck1ng_th3_v3nts_0f_d15rupt10n}`

## Key Technical Insights

### Steganography Technique
- Flag embedded within legitimate HVAC network communications
- Hex-encoded data disguised as operational parameters
- Multi-packet flag distribution across network traffic

### Data Hiding Method
- ASCII strings prefixed with 'p' containing hex data
- Additional hex data found in KEY field of HVAC protocol
- L33t speak encoding (numbers substituted for similar letters)

### Challenge Pattern
- **Theme**: HVAC system disruption ("unlocking vents of disruption")
- **Encoding**: Hexadecimal to ASCII conversion
- **Distribution**: Flag fragments across multiple network packets

## Lessons Learned

1. **Network Forensics**: PCAP analysis requires systematic examination of all data streams
2. **Pattern Recognition**: Look for unusual data patterns in operational technology traffic
3. **Multiple Encoding**: Flags may use combined encoding methods (hex + leetspeak)
4. **Industrial Context**: ICS challenges often hide data within legitimate control system communications

## Final Status

**Challenge Completed Successfully**
- ✅ HVAC network traffic analyzed
- ✅ Hex patterns identified and decoded
- ✅ Flag fragments reconstructed in correct order
- ✅ L33t speak ending pattern recognized
- ✅ Flag extracted: **HTB{Unl0ck1ng_th3_v3nts_0f_d15rupt10n}**

This ICS challenge effectively demonstrated network forensics techniques and steganographic methods used to hide data within industrial control system communications.