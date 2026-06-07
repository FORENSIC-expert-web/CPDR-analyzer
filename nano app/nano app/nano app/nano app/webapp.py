#!/usr/bin/env python3
"""
Flask web dashboard for CDR/IPDR Analyzer.
Provides interactive UI for data analysis, search, and visualization.
"""

import os
import json
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template_string, request, jsonify, send_file, session
import pandas as pd

from app.analyzer import load_data, detect_record_type, CDRAnalyzer, IPDRAnalyzer, _human_bytes
from app.visualizer import Visualizer
from app.reporter import ReportGenerator


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CDR/IPDR Analysis Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
        body { background: #f0f2f5; font-family: 'Segoe UI', sans-serif; }
        .sidebar { background: linear-gradient(180deg, #1a237e, #283593);
            min-height: 100vh; color: white; padding: 20px; position: fixed; width: 220px; }
        .sidebar a { color: rgba(255,255,255,0.8); text-decoration: none; padding: 10px 15px;
            display: block; border-radius: 8px; margin: 4px 0; transition: all 0.2s; cursor: pointer; }
        .sidebar a:hover, .sidebar a.active { background: rgba(255,255,255,0.15); color: white; }
        .sidebar .logo { font-size: 1.4rem; font-weight: bold; padding: 15px;
            border-bottom: 1px solid rgba(255,255,255,0.1); margin-bottom: 20px; }
        .main-content { margin-left: 220px; padding: 20px; }
        .stat-card { background: white; border-radius: 12px; padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08); transition: transform 0.2s; }
        .stat-card:hover { transform: translateY(-3px); }
        .stat-card .number { font-size: 2rem; font-weight: bold; color: #1a237e; }
        .stat-card .label { color: #666; font-size: 0.9rem; }
        .search-box, .result-table { background: white; border-radius: 12px; padding: 20px;
            margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        .btn-upload { background: white; color: #1a237e; border: 2px dashed #1a237e;
            padding: 40px; border-radius: 12px; cursor: pointer; transition: all 0.3s; }
        .btn-upload:hover { background: #e8eaf6; }
        .loading { display: none; }
        .img-preview { max-width: 100%; border-radius: 8px; border: 1px solid #ddd; }
    </style>
</head>
<body>
<div class="sidebar">
    <div class="logo"><i class="bi bi-graph-up"></i> CDR/IPDR</div>
    <a class="active" onclick="showTab('overview')"><i class="bi bi-house"></i> Overview</a>
    <a onclick="showTab('upload')"><i class="bi bi-upload"></i> Upload Data</a>
    <a onclick="showTab('search')"><i class="bi bi-search"></i> Search</a>
    <a onclick="showTab('anomalies')"><i class="bi bi-exclamation-triangle"></i> Anomalies</a>
    <a onclick="showTab('patterns')"><i class="bi bi-bar-chart"></i> Patterns</a>
    <a onclick="showTab('network')"><i class="bi bi-diagram-3"></i> Network</a>
    <a onclick="showTab('visuals')"><i class="bi bi-image"></i> Charts</a>
    <a onclick="showTab('report')"><i class="bi bi-download"></i> Report</a>
    <hr style="border-color: rgba(255,255,255,0.1)">
    <div class="small text-muted mt-2">
        <div id="sidebar-type">{{ record_type }}</div>
        <div id="sidebar-count">{{ total_records }}</div>
    </div>
</div>

<div class="main-content">
    <div class="loading text-center py-5" id="loading">
        <div class="spinner-border text-primary" role="status"></div>
        <p class="mt-2">Processing...</p>
    </div>

    <!-- Upload Tab -->
    <div id="tab-upload">
        <h2><i class="bi bi-upload"></i> Upload Data File</h2>
        <div class="row mt-4">
            <div class="col-md-8 offset-md-2">
                <form action="/upload" method="post" enctype="multipart/form-data">
                    <div class="btn-upload text-center d-block w-100" onclick="document.getElementById('file-input').click()">
                        <i class="bi bi-cloud-upload display-1"></i>
                        <h4 class="mt-3">Click to Upload or Drag & Drop</h4>
                        <p class="text-muted">CSV, JSON, TSV, XLSX, Parquet files supported</p>
                        <input type="file" id="file-input" name="file" accept=".csv,.json,.tsv,.txt,.xlsx,.xls,.parquet" style="display:none" onchange="this.form.submit()">
                    </div>
                </form>
                <div class="mt-4 text-center">
                    <p class="text-muted">Or use sample data:</p>
                    <a href="/load-sample/cdr" class="btn btn-outline-primary me-2">Load Sample CDR</a>
                    <a href="/load-sample/ipdr" class="btn btn-outline-danger">Load Sample IPDR</a>
                </div>
            </div>
        </div>
    </div>

    <!-- Overview Tab -->
    <div id="tab-overview">
        <h2><i class="bi bi-house"></i> Overview</h2>
        <div class="row mt-4">
            {{ overview_cards }}
        </div>
        <div class="row mt-3">
            <div class="col-md-6">
                <div class="stat-card"><h5>Top Callers / Sources</h5>
                <div style="max-height:400px; overflow-y:auto;">{{ top_callers_table }}</div></div>
            </div>
            <div class="col-md-6">
                <div class="stat-card"><h5>Top Destinations</h5>
                <div style="max-height:400px; overflow-y:auto;">{{ top_callees_table }}</div></div>
            </div>
        </div>
    </div>

    <!-- Search Tab -->
    <div id="tab-search" style="display:none;">
        <h2><i class="bi bi-search"></i> Search Records</h2>
        <div class="search-box">
            <div class="row">
                <div class="col-md-9">
                    <input type="text" id="search-input" class="form-control form-control-lg"
                           placeholder="Enter phone number or IP address...">
                </div>
                <div class="col-md-3">
                    <button class="btn btn-primary btn-lg w-100" onclick="searchRecords()">
                        <i class="bi bi-search"></i> Search
                    </button>
                </div>
            </div>
        </div>
        <div id="search-results" class="result-table">
            <p class="text-muted text-center my-5">Enter a phone number or IP address above to search.</p>
        </div>
    </div>

    <!-- Anomalies Tab -->
    <div id="tab-anomalies" style="display:none;">
        <h2><i class="bi bi-exclamation-triangle"></i> Anomaly Detection</h2>
        <div class="row mt-3">
            {{ anomaly_cards }}
        </div>
        <div id="anomaly-results" class="result-table mt-3"></div>
    </div>

    <!-- Patterns Tab -->
    <div id="tab-patterns" style="display:none;">
        <h2><i class="bi bi-bar-chart"></i> Pattern Analysis</h2>
        <div class="search-box">
            <div class="row">
                <div class="col-md-9">
                    <input type="text" id="pattern-input" class="form-control form-control-lg"
                           placeholder="Enter phone number or IP for pattern analysis...">
                </div>
                <div class="col-md-3">
                    <button class="btn btn-success btn-lg w-100" onclick="analyzePattern()">
                        <i class="bi bi-graph-up"></i> Analyze
                    </button>
                </div>
            </div>
        </div>
        <div id="pattern-results" class="result-table"></div>
    </div>

    <!-- Network Tab -->
    <div id="tab-network" style="display:none;">
        <h2><i class="bi bi-diagram-3"></i> Connection Network Graph</h2>
        <div class="text-center mt-3">
            <img src="/static/network_graph.png" class="img-fluid img-preview"
                 onerror="this.style.display='none'" style="max-width:100%">
            <p class="text-muted mt-2">Caller ↔ Callee connection graph (generated from data)</p>
        </div>
    </div>

    <!-- Visuals Tab -->
    <div id="tab-visuals" style="display:none;">
        <h2><i class="bi bi-image"></i> Charts & Visualizations</h2>
        <div class="row mt-3">
            <div class="col-md-6 mb-3 text-center">
                <h6>Hourly Activity</h6>
                <img src="/static/hourly_activity.png" class="img-fluid img-preview"
                     onerror="this.style.display='none'">
            </div>
            <div class="col-md-6 mb-3 text-center">
                <h6>Weekday Activity</h6>
                <img src="/static/weekday_activity.png" class="img-fluid img-preview"
                     onerror="this.style.display='none'">
            </div>
            <div class="col-md-6 mb-3 text-center">
                <h6>Duration Distribution</h6>
                <img src="/static/duration_distribution.png" class="img-fluid img-preview"
                     onerror="this.style.display='none'">
            </div>
            <div class="col-md-6 mb-3 text-center">
                <h6>Activity Timeline</h6>
                <img src="/static/activity_timeline.png" class="img-fluid img-preview"
                     onerror="this.style.display='none'">
            </div>
            <div class="col-md-6 mb-3 text-center">
                <h6>Protocol Distribution</h6>
                <img src="/static/protocol_distribution.png" class="img-fluid img-preview"
                     onerror="this.style.display='none'">
            </div>
            <div class="col-md-6 mb-3 text-center">
                <h6>Top Callers</h6>
                <img src="/static/top_callers.png" class="img-fluid img-preview"
                     onerror="this.style.display='none'">
            </div>
        </div>
    </div>

    <!-- Report Tab -->
    <div id="tab-report" style="display:none;">
        <h2><i class="bi bi-download"></i> Export & Report</h2>
        <div class="row mt-4">
            <div class="col-md-4 mb-3">
                <div class="stat-card text-center p-4">
                    <i class="bi bi-filetype-html display-3 text-primary"></i>
                    <h4 class="mt-2">HTML Report</h4>
                    <p>Complete analysis with tables and charts</p>
                    <a href="/report" class="btn btn-primary" target="_blank">
                        <i class="bi bi-download"></i> Download
                    </a>
                </div>
            </div>
            <div class="col-md-4 mb-
