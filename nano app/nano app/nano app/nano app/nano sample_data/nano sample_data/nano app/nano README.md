# CDR/IPDR Examination & Analysis Tool

A comprehensive tool for parsing, analyzing, visualizing, and reporting on **Call Detail Records (CDR)** and **Internet Protocol Detail Records (IPDR)**.

## Features

- **Auto-format detection** — CDR vs IPDR detection from column headers
- **Multi-format support** — CSV, JSON, TSV, XLSX, Parquet
- **Statistical analysis** — volumes, durations, top talkers, busy hours
- **Pattern analysis** — frequent contacts, hourly/daily/weekly patterns
- **Anomaly detection** — duration anomalies, off-hours activity, burst windows
- **Device tracking** — IMEI change (device swap) and IMSI change (SIM swap) detection
- **Geo mapping** — Interactive Folium maps for cell towers and session data
- **Network graph** — Caller↔Callee connection visualization
- **IPDR-specific** — Protocol distribution, port/service analysis, bandwidth estimation
- **HTML reports** — Comprehensive reports with embedded charts
- **Web dashboard** — Interactive Flask-based UI

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/cdr-ipdr-analyzer.git
cd cdr-ipdr-analyzer
