#!/usr/bin/env python3
"""
CDR / IPDR Examination & Analysis Engine
----------------------------------------
Core analysis engine for Call Detail Records (CDR) and
Internet Protocol Detail Records (IPDR).

Part of the CDR/IPDR Analyzer project.
"""

import os
import re
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set

import pandas as pd
import numpy as np

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger('cdr_ipdr_analyzer')


# ═══════════════════════════════════════════════════════════════════════════════
# 1. FIELD SIGNATURES
# ═══════════════════════════════════════════════════════════════════════════════

CDR_FIELD_SIGNATURES = {
    'caller': ['caller', 'a_party', 'calling_number', 'calling_party',
               'source_number', 'originating', 'cli', 'calling_msisdn',
               'caller_id', 'calling_phone'],
    'callee': ['callee', 'b_party', 'called_number', 'called_party',
               'destination_number', 'terminating', 'called_msisdn',
               'called_phone', 'dialed_number'],
    'start_time': ['start_time', 'starttime', 'call_start', 'setup_time',
                   'call_time', 'init_time', 'timestamp', 'start_date',
                   'call_date', 'date_start', 'cdr_started_at'],
    'end_time': ['end_time', 'endtime', 'call_end', 'release_time',
                 'cdr_ended_at', 'end_date', 'stop_time'],
    'duration': ['duration', 'call_duration', 'dur', 'billing_duration',
                 'call_time_ms', 'talk_time', 'bill_sec', 'call_sec'],
    'call_type': ['call_type', 'calltype', 'type', 'service_type',
                  'call_category', 'call_class'],
    'disposition': ['disposition', 'status', 'answer_status', 'call_status',
                    'result', 'release_cause', 'termination_cause',
                    'disconnect_reason'],
    'imei': ['imei', 'imei_sv', 'device_id'],
    'imsi': ['imsi', 'subscriber_id'],
    'msisdn': ['msisdn', 'phone_number', 'subscriber'],
    'cell_id': ['cell_id', 'cellid', 'cgi', 'location_area', 'lac',
                'tower_id', 'bts_id', 'enodeb_id'],
    'call_id': ['call_id', 'callid', 'call_uuid', 'unique_id', 'session_id',
                'connection_id'],
    'cost': ['cost', 'charge', 'rate', 'price', 'billing_amount', 'debit'],
}

IPDR_FIELD_SIGNATURES = {
    'src_ip': ['src_ip', 'source_ip', 'srcip', 'sip', 'ip_src',
               'source_address', 'local_ip', 'client_ip'],
    'dst_ip': ['dst_ip', 'dest_ip', 'destination_ip', 'dstip', 'dip',
               'ip_dst', 'destination_address', 'remote_ip', 'server_ip'],
    'src_port': ['src_port', 'source_port', 'srcport', 'sport',
                 'local_port', 'client_port'],
    'dst_port': ['dst_port', 'dest_port', 'destination_port', 'dstport',
                 'dport', 'remote_port', 'server_port'],
    'protocol': ['protocol', 'proto', 'ip_protocol', 'transport'],
    'start_time': ['start_time', 'starttime', 'session_start', 'flow_start',
                   'timestamp', 'first_seen', 'start_date'],
    'end_time': ['end_time', 'endtime', 'session_end', 'flow_end',
                 'last_seen', 'end_date'],
    'duration': ['duration', 'flow_duration', 'session_duration', 'dur'],
    'bytes_sent': ['bytes_sent', 'bytes_up', 'uplink_bytes', 'tx_bytes',
                   'upload_bytes', 'octets_sent'],
    'bytes_recv': ['bytes_recv', 'bytes_down', 'downlink_bytes', 'rx_bytes',
                   'download_bytes', 'octets_recv'],
    'total_bytes': ['total_bytes', 'bytes', 'total_octets', 'data_volume',
                    'volume'],
    'packets_sent': ['packets_sent', 'pkts_up', 'tx_packets'],
    'packets_recv': ['packets_recv', 'pkts_down', 'rx_packets'],
    'total_packets': ['total_packets', 'packets', 'packet_count'],
    'subscriber_id': ['subscriber_id', 'user_id', 'subscriber', 'username',
                      'customer_id', 'aaa_username'],
    'nas_ip': ['nas_ip', 'router_ip', 'gateway_ip', 'cmts_ip', 'olt_ip',
               'bng_ip', 'aggregator_ip'],
    'session_id': ['session_id', 'flow_id', 'connection_id', 'call_id',
                   'tunnel_id'],
}

PORT_SERVICES = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
    123: 'NTP', 137: 'NetBIOS-NS', 138: 'NetBIOS-DGM',
    139: 'NetBIOS-SSN', 143: 'IMAP', 161: 'SNMP',
    389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    500: 'ISAKMP', 514: 'Syslog', 587: 'SMTP-Submit',
    636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 1521: 'Oracle', 2049: 'NFS',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 5985: 'WinRM-HTTP', 5986: 'WinRM-HTTPS',
    6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    9090: 'Prometheus', 27017: 'MongoDB', 32400: 'Plex',
}


def detect_record_type(df):
    """Auto-detect CDR vs IPDR from column headers."""
    cols_lower = [c.lower().replace(' ', '_').replace('-', '_') for c in df.columns]
    cdr_score = 0
    ipdr_score = 0

    for _, aliases in CDR_FIELD_SIGNATURES.items():
        for col in cols_lower:
            for alias in aliases:
                if alias in col:
                    cdr_score += 1
                    break

    for _, aliases in IPDR_FIELD_SIGNATURES.items():
        for col in cols_lower:
            for alias in aliases:
                if alias in col:
                    ipdr_score += 1
                    break

    for col in df.columns[:min(10, len(df.columns))]:
        sample = df[col].dropna().astype(str).head(100)
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if sample.str.match(ip_pattern).mean() > 0.3:
            ipdr_score += 3
            break

    if cdr_score > ipdr_score and cdr_score >= 2:
        return 'cdr'
    elif ipdr_score >= cdr_score and ipdr_score >= 2:
        return 'ipdr'
    return 'unknown'


def load_data(filepath, encoding='utf-8', **kwargs):
    """Load data from CSV, JSON, TSV, XLSX, or Parquet."""
    ext = Path(filepath).suffix.lower()
    log.info(f"Loading data from: {filepath} ({ext})")

    if ext == '.csv':
        df = pd.read_csv(filepath, encoding=encoding, low_memory=False, **kwargs)
    elif ext in ('.tsv', '.txt'):
        df = pd.read_csv(filepath, encoding=encoding, sep='\t', low_memory=False, **kwargs)
    elif ext == '.json':
        df = pd.read_json(filepath, encoding=encoding, **kwargs)
    elif ext in ('.xlsx', '.xls'):
        df = pd.read_excel(filepath, engine='openpyxl', **kwargs)
    elif ext == '.parquet':
        df = pd.read_parquet(filepath, **kwargs)
    else:
        df = pd.read_csv(filepath, encoding=encoding, low_memory=False, **kwargs)

    log.info(f"Loaded {len(df):,} records with {len(df.columns)} columns")
    return df


def normalize_timestamps(df, record_type=None):
    """Normalize timestamp columns to datetime."""
    if record_type is None:
        record_type = detect_record_type(df)
    ts_fields = {
        'cdr': ['start_time', 'end_time', 'call_start', 'call_end', 'timestamp'],
        'ipdr': ['start_time', 'end_time', 'session_start', 'session_end',
                 'first_seen', 'last_seen', 'timestamp'],
    }.get(record_type, ['start_time', 'end_time', 'timestamp'])
    cols_lower = {c.lower().replace(' ', '_').replace('-', '_'): c for c in df.columns}
    for field in ts_fields:
        if field in cols_lower:
            col = cols_lower[field]
            if df[col].dtype == 'object':
                try:
                    df[col] = pd.to_datetime(df[col], errors='coerce', infer_datetime_format=True)
                except Exception:
                    pass
    return df


def normalize_numeric(df):
    """Convert numeric-like strings to numbers."""
    for col in df.columns:
        if df[col].dtype == 'object':
            try:
                frac = pd.to_numeric(df[col], errors='coerce').notna().mean()
                if frac > 0.7:
                    df[col] = pd.to_numeric(df[col], errors='coerce')
            except Exception:
                pass
    return df


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ANALYZER CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

class CDRAnalyzer:
    """Analysis engine for CDR (phone call) records."""

    def __init__(self, df):
        self.df = normalize_numeric(normalize_timestamps(df.copy()))
        self.record_type = detect_record_type(self.df)
        self.cols = self._map_columns()
        log.info(f"CDR Analyzer: {len(df):,} records, {len(self.cols)} fields mapped")

    def _map_columns(self):
        cols_lower = {c.lower().replace(' ', '_').replace('-', '_'): c
                      for c in self.df.columns}
        mapping = {}
        sigs = CDR_FIELD_SIGNATURES if self.record_type == 'cdr' else IPDR_FIELD_SIGNATURES
        for canonical, aliases in sigs.items():
            for alias in aliases:
                if alias in cols_lower:
                    mapping[canonical] = cols_lower[alias]
                    break
        return mapping

    def summary(self):
        stats = {
            'record_type': self.record_type.upper(),
            'total_records': len(self.df),
            'total_columns': len(self.df.columns),
            'columns': list(self.df.columns),
            'date_range': {},
        }
        dur_col = self.cols.get('duration')
        if dur_col and dur_col in self.df:
            dur = self.df[dur_col].dropna()
            if len(dur) > 0:
                stats['duration'] = {
                    'min': float(dur.min()), 'max': float(dur.max()),
                    'mean': float(dur.mean()), 'median': float(dur.median()),
                    'std': float(dur.std()), 'total': float(dur.sum()),
                }
        ts_col = self.cols.get('start_time')
        if ts_col and ts_col in self.df:
            ts = self.df[ts_col].dropna()
            if len(ts) > 0:
                stats['date_range'] = {
                    'start': str(ts.min()), 'end': str(ts.max()),
                    'span_days': (ts.max() - ts.min()).total_seconds() / 86400
                }
        return stats

    def top_talkers(self, n=20):
        results = {}
        for role, field in [('caller', 'caller'), ('callee', 'callee')]:
            col = self.cols.get(field)
            if col and col in self.df:
                counts = self.df[col].dropna().value_counts().head(n)
                results[role] = pd.DataFrame({
                    'id': [str(x) for x in counts.index],
                    'count': counts.values,
                    'percentage': (counts.values / len(self.df) * 100).round(2)
                }).reset_index(drop=True)
        return results

    def hourly_activity(self):
        ts_col = self.cols.get('start_time')
        if not ts_col or ts_col not in self.df:
            return pd.DataFrame()
        ts = self.df[ts_col].dropna()
        if not pd.api.types.is_datetime64_any_dtype(ts):
            return pd.DataFrame()
        hourly = ts.dt.hour.value_counts().sort_index()
        return pd.DataFrame({'hour': hourly.index, 'count': hourly.values}).reset_index(drop=True)

    def daily_activity(self):
        ts_col = self.cols.get('start_time')
        if not ts_col or ts_col not in self.df:
            return pd.DataFrame()
        ts = self.df[ts_col].dropna()
        if not pd.api.types.is_datetime64_any_dtype(ts):
            return pd.DataFrame()
        daily = ts.dt.date.value_counts().sort_index()
        return pd.DataFrame({'date': [str(d) for d in daily.index], 'count': daily.values}).reset_index(drop=True)

    def weekday_activity(self):
        ts_col = self.cols.get('start_time')
        if not ts_col or ts_col not in self.df:
            return pd.DataFrame()
        ts = self.df[ts_col].dropna()
        if not pd.api.types.is_datetime64_any_dtype(ts):
            return pd.DataFrame()
        wd = ts.dt.dayofweek.value_counts().sort_index()
        days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        return pd.DataFrame({
            'weekday': [days[i] for i in wd.index],
            'code': wd.index, 'count': wd.values
        }).reset_index(drop=True)

    def most_frequent_contacts(self, number, n=20):
        caller_col = self.cols.get('caller')
        callee_col = self.cols.get('callee')
        if not caller_col or not callee_col:
            return pd.DataFrame()
        mask = self.df[caller_col].astype(str).str.contains(re.escape(str(number)), case=False, na=False)
        if mask.sum() == 0:
            return pd.DataFrame()
        contacts = self.df.loc[mask, callee_col].value_counts().head(n)
        return pd.DataFrame({'contact': [str(x) for x in contacts.index], 'count': contacts.values}).reset_index(drop=True)

    def calling_hours_pattern(self, number):
        caller_col = self.cols.get('caller')
        callee_col = self.cols.get('callee')
        ts_col = self.cols.get('start_time')
        if not ts_col or ts_col not in self.df:
            return pd.DataFrame()
        mask = pd.Series(False, index=self.df.index)
        if caller_col and caller_col in self.df:
            mask |= self.df[caller_col].astype(str).str.contains(re.escape(str(number)), case=False, na=False)
        if callee_col and callee_col in self.df:
            mask |= self.df[callee_col].astype(str).str.contains(re.escape(str(number)), case=False, na=False)
        if mask.sum() == 0:
            return pd.DataFrame()
        ts = self.df.loc[mask, ts_col].dropna()
        if not pd.api.types.is_datetime64_any_dtype(ts):
            return pd.DataFrame()
        hourly = ts.dt.hour.value_counts().sort_index()
        return pd.DataFrame({'hour': hourly.index, 'count': hourly.values}).reset_index(drop=True)

    def detect_anomalies(self, z_threshold=2.5):
        dur_col = self.cols.get('duration')
        if not dur_col or dur_col not in self.df:
            return pd.DataFrame()
        dur = self.df[dur_col].dropna()
        if len(dur) < 10:
            return pd.DataFrame()
        mean, std = dur.mean(), dur.std()
        if std == 0:
            return pd.DataFrame()
        z_scores = ((self.df[dur_col] - mean) / std).abs()
        anomalies = self.df[z_scores > z_threshold].copy()
        anomalies['z_score'] = z_scores[z_scores > z_threshold]

        def label(row):
            d = row.get(dur_col)
            if pd.isna(d):
                return 'missing_duration'
            if d > mean + z_threshold * std:
                return f'unusually_long (z={row["z_score"]:.1f})'
            elif d < mean - z_threshold * std:
                return f'unusually_short (z={row["z_score"]:.1f})'
            return 'other'

        anomalies['anomaly_reason'] = anomalies.apply(label, axis=1)
        return anomalies.sort_values('z_score', ascending=False)

    def detect_off_hours_activity(self, quiet_start=23, quiet_end=6):
        ts_col = self.cols.get('start_time')
        if not ts_col or ts_col not in self.df:
            return pd.DataFrame()
        ts = self.df[ts_col]
        if not pd.api.types.is_datetime64_any_dtype(ts):
            return pd.DataFrame()
        hour = ts.dt.hour
        off_hours = (hour >= quiet_start) | (hour < quiet_end) if quiet_end > quiet_start else (hour >= quiet_start) | (hour < quiet_end)
        return self.df[off_hours].copy()

    def detect_burst_activity(self, window_minutes=5, threshold_multiplier=3.0):
        ts_col = self.cols.get('start_time')
        if not ts_col or ts_col not in self.df:
            return pd.DataFrame()
        ts = self.df[ts_col].dropna()
        if len(ts) < 50 or not pd.api.types.is_datetime64_any_dtype(ts):
            return pd.DataFrame()
        counts = ts.dt.floor(f'{window_minutes}min').value_counts().sort_index()
        mean_c, std_c = counts.mean(), counts.std()
        if std_c == 0:
            return pd.DataFrame()
        bursts = counts[counts > mean_c + threshold_multiplier * std_c]
        if len(bursts) == 0:
            return pd.DataFrame()
        return self.df[ts.dt.floor(f'{window_minutes}min').isin(set(bursts.index))].copy()

    def detect_imei_changes(self):
        imei_col, msisdn_col, ts_col = self.cols.get('imei'), self.cols.get('msisdn'), self.cols.get('start_time')
        if not all([imei_col, msisdn_col, ts_col]) or any(c not in self.df for c in [imei_col, msisdn_col, ts_col]):
            return pd.DataFrame()
        df = self.df[[msisdn_col, imei_col, ts_col]].dropna().copy()
        if len(df) < 2:
            return pd.DataFrame()
        df = df.sort_values(ts_col)
        changes = []
        for num, g in df.groupby(msisdn_col):
            imeis = g[imei_col].unique()
            if len(imeis) > 1:
                for i in range(len(imeis) - 1):
                    ct = g.loc[g[imei_col] == imeis[i+1], ts_col].min()
                    changes.append({'msisdn': str(num), 'old_imei': str(imeis[i]), 'new_imei': str(imeis[i+1]), 'change_time': str(ct)})
        return pd.DataFrame(changes).sort_values('change_time') if changes else pd.DataFrame()

    def detect_imsi_changes(self):
        imsi_col, msisdn_col, ts_col = self.cols.get('imsi'), self.cols.get('msisdn'), self.cols.get('start_time')
        if not all([imsi_col, msisdn_col, ts_col]) or any(c not in self.df for c in [imsi_col, msisdn_col, ts_col]):
            return pd.DataFrame()
        df = self.df[[msisdn_col, imsi_col, ts_col]].dropna().copy()
        if len(df) < 2:
            return pd.DataFrame()
        df = df.sort_values(ts_col)
        changes = []
        for num, g in df.groupby(msisdn_col):
            imsis = g[imsi_col].unique()
            if len(imsis) > 1:
                for i in range(len(imsis) - 1):
                    ct = g.loc[g[imsi_col] == imsis[i+1], ts_col].min()
                    changes.append({'msisdn': str(num), 'old_imsi': str(imsis[i]), 'new_imsi': str(imsis[i+1]), 'change_time': str(ct)})
        return pd.DataFrame(changes).sort_values('change_time') if changes else pd.DataFrame()

    def tower_analysis(self):
        cell_col = self.cols.get('cell_id')
        if not cell_col or cell_col not in self.df:
            return pd.DataFrame()
        towers = self.df[cell_col].value_counts()
        return pd.DataFrame({
            'cell_id': [str(x) for x in towers.index],
            'call_count': towers.values,
            'percentage': (towers.values / len(self.df) * 100).round(2)
        }).reset_index(drop=True)

    def location_history(self, number):
        cell_col, ts_col = self.cols.get('cell_id'), self.cols.get('start_time')
        caller_col, callee_col = self.cols.get('caller'), self.cols.get('callee')
        if not all([cell_col, ts_col]) or any(c not in self.df for c in [cell_col, ts_col]):
            return pd.DataFrame()
        mask = pd.Series(False, index=self.df.index)
        if caller_col and caller_col in self.df:
            mask |= self.df[caller_col].astype(str).str.contains(re.escape(str(number)), case=False, na=False)
        if callee_col and callee_col in self.df:
            mask |= self.df[callee_col].astype(str).str.contains(re.escape(str(number)), case=False, na=False)
        if mask.sum() == 0:
            return pd.DataFrame()
        df = self.df.loc[mask, [ts_col, cell_col]].dropna().sort_values(ts_col)
        df['changed'] = df[cell_col] != df[cell_col].shift(1)
        return df[df['changed']][[ts_col, cell_col]].reset_index(drop=True)

    def build_connection_graph(self, min_calls=1):
        caller_col, callee_col = self.cols.get('caller'), self.cols.get('callee')
        if not caller_col or not callee_col:
            return {'nodes': [], 'edges': []}
        pairs = self.df.groupby([caller_col, callee_col]).size().reset_index(name='weight')
        pairs = pairs[pairs['weight'] >= min_calls]
        nodes = set()
        nodes.update(pairs[caller_col].unique())
        nodes.update(pairs[callee_col].unique())
        return {
            'nodes': [{'id': str(n), 'label': str(n)} for n in nodes],
            'edges': [{'source': str(r[caller_col]), 'target': str(r[callee_col]), 'weight': int(r['weight'])} for _, r in pairs.iterrows()]
        }

    def get_record_by_number(self, number):
        caller_col, callee_col = self.cols.get('caller'), self.cols.get('callee')
        mask = pd.Series(False, index=self.df.index)
        if caller_col and caller_col in self.df:
            mask |= self.df[caller_col].astype(str).str.contains(re.escape(str(number)), case=False, na=False)
        if callee_col and callee_col in self.df:
            mask |= self.df[callee_col].astype(str).str.contains(re.escape(str(number)), case=False, na=False)
        return self.df[mask].copy()


class IPDRAnalyzer(CDRAnalyzer):
    """Analysis engine for IPDR (network session) records."""

    def __init__(self, df):
        self.df = normalize_numeric(normalize_timestamps(df.copy()))
        self.record_type = 'ipdr'
        self.cols = self._map_columns_ipdr()
        log.info(f"IPDR Analyzer: {len(df):,} records, {len(self.cols)} fields mapped")

    def _map_columns_ipdr(self):
        cols_lower = {c.lower().replace(' ', '_').replace('-', '_'): c for c in self.df.columns}
        mapping = {}
        for canonical, aliases in IPDR_FIELD_SIGNATURES.items():
            for alias in aliases:
                if alias in cols_lower:
                    mapping[canonical] = cols_lower[alias]
                    break
        return mapping

    def protocol_distribution(self):
        col = self.cols.get('protocol')
        if col and col in self.df:
            return {str(k): int(v) for k, v in self.df[col].value_counts().head(20).items()}
        return {}

    def top_destinations(self, n=20):
        dst_col = self.cols.get('dst_ip')
        if not dst_col or dst_col not in self.df:
            return pd.DataFrame()
        counts = self.df[dst_col].value_counts().head(n)
        result = pd.DataFrame({
            'destination_ip': [str(x) for x in counts.index],
            'connection_count': counts.values,
            'percentage': (counts.values / len(self.df) * 100).round(2)
        }).reset_index(drop=True)
        bytes_col = self.cols.get('total_bytes') or self.cols.get('bytes_sent')
        if bytes_col and bytes_col in self.df:
            bpd = self.df.groupby(dst_col)[bytes_col].sum()
            result['total_bytes'] = result['destination_ip'].map(lambda ip: int(bpd.get(ip, 0)))
        return result

    def port_analysis(self):
        dst_col = self.cols.get('dst_port')
        ports = []
        if dst_col and dst_col in self.df:
            for p, c in self.df[dst_col].dropna().value_counts().head(30).items():
                port_num = int(p)
                ports.append({'port': port_num, 'role': 'destination', 'count': int(c), 'service': PORT_SERVICES.get(port_num, 'Unknown')})
        return {'top_ports': ports}

    def bandwidth_analysis(self):
        bytes_col = self.cols.get('total_bytes') or self.cols.get('bytes_sent') or self.cols.get('bytes_recv')
        dur_col = self.cols.get('duration')
        if not bytes_col or bytes_col not in self.df:
            return {}
        total_bytes = int(self.df[bytes_col].sum())
        result = {'total_bytes': total_bytes, 'record_count': len(self.df)}
        if dur_col and dur_col in self.df:
            td = self.df[dur_col].sum()
            if td > 0:
                result['avg_bandwidth_bps'] = total_bytes / td
        src_col = self.cols.get('src_ip') or self.cols.get('subscriber_id')
        if src_col and src_col in self.df:
            top = self.df.groupby(src_col)[bytes_col].sum().sort_values(ascending=False).head(20)
            result['top_consumers'] = [{'subscriber': str(k), 'bytes': int(v)} for k, v in top.items()]
        return result

    def ip_pair_analysis(self, n=20):
        src_col, dst_col = self.cols.get('src_ip'), self.cols.get('dst_ip')
        if not src_col or not dst_col:
            return pd.DataFrame()
        pairs = self.df.groupby([src_col, dst_col]).size().reset_index(name='count')
        return pairs.sort_values('count', ascending=False).head(n).reset_index(drop=True)

    def get_record_by_ip(self, ip_address):
        src_col, dst_col = self.cols.get('src_ip'), self.cols.get('dst_ip')
        mask = pd.Series(False, index=self.df.index)
        if src_col and src_col in self.df:
            mask |= self.df[src_col].astype(str).str.contains(re.escape(str(ip_address)), case=False, na=False)
        if dst_col and dst_col in self.df:
            mask |= self.df[dst_col].astype(str).str.contains(re.escape(str(ip_address)), case=False, na=False)
        return self.df[mask].copy()


def _human_bytes(b):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f"{b:.2f} {unit}"
        b /= 1024
    return f"{b:.2f} PB"
