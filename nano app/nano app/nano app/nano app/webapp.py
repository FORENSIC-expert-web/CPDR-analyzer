#!/usr/bin/env python3
"""
Flask web dashboard for CDR/IPDR Analyzer.
"""

import os
import json
from datetime import datetime
from pathlib import Path
import secrets

from flask import Flask, render_template_string, request, jsonify, send_file, session
import pandas as pd

from app.analyzer import load_data, detect_record_type, CDRAnalyzer, IPDRAnalyzer, _human_bytes
from app.visualizer import Visualizer
from app.reporter import ReportGenerator

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('./output/static', exist_ok=True)
os.makedirs('./sample_data', exist_ok=True)

# Global analyzer reference
analyzer = None

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
            padding: 40px; border-radius: 12px; cursor: pointer; transition: all 0.3s; display: block; text-align: center; }
        .btn-upload:hover { background: #e8eaf6; }
        .img-preview { max-width: 100%; border-radius: 8px; border: 1px solid #ddd; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
</head>
<body>
<div class="sidebar">
    <div class="logo"><i class="bi bi-graph-up"></i> CDR/IPDR</div>
    <a class="active" onclick="showTab('overview')"><i class="bi bi-house"></i> Overview</a>
    <a onclick="showTab('upload')"><i class="bi bi-upload"></i> Upload</a>
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
    <div id="loading" class="text-center py-5" style="display:none;">
        <div class="spinner-border text-primary" role="status"></div>
        <p class="mt-2">Processing...</p>
    </div>

    <!-- Upload Tab -->
    <div id="tab-upload" class="tab-content">
        <h2><i class="bi bi-upload"></i> Upload Data File</h2>
        <div class="row mt-4">
            <div class="col-md-8 offset-md-2">
                <form action="/upload" method="post" enctype="multipart/form-data">
                    <div class="btn-upload" onclick="document.getElementById('file-input').click()">
                        <i class="bi bi-cloud-upload display-1"></i>
                        <h4 class="mt-3">Click to Upload</h4>
                        <p class="text-muted">CSV, JSON, TSV, XLSX, Parquet</p>
                        <input type="file" id="file-input" name="file"
                               accept=".csv,.json,.tsv,.txt,.xlsx,.xls,.parquet"
                               style="display:none" onchange="this.form.submit()">
                    </div>
                </form>
                <div class="mt-4 text-center">
                    <p class="text-muted">Or load sample data:</p>
                    <a href="/load-sample/cdr" class="btn btn-outline-primary me-2">Sample CDR</a>
                    <a href="/load-sample/ipdr" class="btn btn-outline-danger">Sample IPDR</a>
                </div>
            </div>
        </div>
    </div>

    <!-- Overview Tab -->
    <div id="tab-overview" class="tab-content active">
        <h2><i class="bi bi-house"></i> Overview</h2>
        <div class="row mt-4">{{ overview_cards }}</div>
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
    <div id="tab-search" class="tab-content">
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
            <p class="text-muted text-center my-5">Enter a query above to search.</p>
        </div>
    </div>

    <!-- Anomalies Tab -->
    <div id="tab-anomalies" class="tab-content">
        <h2><i class="bi bi-exclamation-triangle"></i> Anomaly Detection</h2>
        <div class="row mt-3">{{ anomaly_cards }}</div>
        <div id="anomaly-results" class="result-table mt-3"></div>
    </div>

    <!-- Patterns Tab -->
    <div id="tab-patterns" class="tab-content">
        <h2><i class="bi bi-bar-chart"></i> Pattern Analysis</h2>
        <div class="search-box">
            <div class="row">
                <div class="col-md-9">
                    <input type="text" id="pattern-input" class="form-control form-control-lg"
                           placeholder="Enter phone number or IP...">
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
    <div id="tab-network" class="tab-content">
        <h2><i class="bi bi-diagram-3"></i> Connection Network Graph</h2>
        <div class="text-center mt-3">
            <img src="/static/network_graph.png" class="img-fluid img-preview"
                 onerror="this.parentElement.innerHTML='<p class=text-muted>No network graph available.</p>'"
                 style="max-width:100%">
        </div>
    </div>

    <!-- Visuals Tab -->
    <div id="tab-visuals" class="tab-content">
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
    <div id="tab-report" class="tab-content">
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
            <div class="col-md-4 mb-3">
                <div class="stat-card text-center p-4">
                    <i class="bi bi-filetype-csv display-3 text-success"></i>
                    <h4 class="mt-2">CSV Export</h4>
                    <p>Raw data with all analyzed records</p>
                    <a href="/export" class="btn btn-success" target="_blank">
                        <i class="bi bi-download"></i> Download
                    </a>
                </div>
            </div>
            <div class="col-md-4 mb-3">
                <div class="stat-card text-center p-4">
                    <i class="bi bi-map display-3 text-danger"></i>
                    <h4 class="mt-2">Interactive Map</h4>
                    <p>Geo-located tower/session map</p>
                    <a href="/static/activity_map.html" class="btn btn-danger" target="_blank">
                        <i class="bi bi-eye"></i> View Map
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
function showTab(name) {
    document.querySelectorAll('.sidebar a').forEach(a => a.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    document.querySelector(`.sidebar a[onclick*="'${name}'"]`).classList.add('active');
}

function searchRecords() {
    const q = document.getElementById('search-input').value.trim();
    if (!q) return;
    document.getElementById('loading').style.display = 'block';
    fetch('/api/search?q=' + encodeURIComponent(q))
        .then(r => r.json())
        .then(data => {
            document.getElementById('loading').style.display = 'none';
            const div = document.getElementById('search-results');
            if (data.error) { div.innerHTML = '<div class="alert alert-danger">' + data.error + '</div>'; return; }
            if (data.records.length === 0) { div.innerHTML = '<div class="alert alert-info">No records found.</div>'; return; }
            let html = '<h5>Found ' + data.total + ' records</h5><div style="max-height:500px; overflow-y:auto;"><table class="table table-sm table-striped"><thead><tr>';
            data.columns.forEach(c => html += '<th>' + c + '</th>');
            html += '</tr></thead><tbody>';
            data.records.forEach(r => {
                html += '<tr>';
                data.columns.forEach(c => html += '<td>' + (r[c] || '') + '</td>');
                html += '</tr>';
            });
            html += '</tbody></table></div>';
            div.innerHTML = html;
        }).catch(e => { document.getElementById('loading').style.display = 'none';
            document.getElementById('search-results').innerHTML = '<div class="alert alert-danger">Error: ' + e + '</div>'; });
}

function analyzePattern() {
    const q = document.getElementById('pattern-input').value.trim();
    if (!q) return;
    document.getElementById('loading').style.display = 'block';
    fetch('/api/pattern?q=' + encodeURIComponent(q))
        .then(r => r.json())
        .then(data => {
            document.getElementById('loading').style.display = 'none';
            const div = document.getElementById('pattern-results');
            let html = '';
            if (data.hourly && data.hourly.length > 0) {
                html += '<h5>Hourly Pattern</h5><table class="table table-sm"><tr><th>Hour</th><th>Count</th></tr>';
                data.hourly.forEach(h => html += '<tr><td>' + h.hour + ':00</td><td>' + h.count + '</td></tr>');
                html += '</table>';
            }
            if (data.contacts && data.contacts.length > 0) {
                html += '<h5>Frequent Contacts</h5><table class="table table-sm"><tr><th>Contact</th><th>Count</th></tr>';
                data.contacts.forEach(c => html += '<tr><td>' + c.contact + '</td><td>' + c.count + '</td></tr>');
                html += '</table>';
            }
            div.innerHTML = html || '<div class="alert alert-warning">No pattern data found for this entity.</div>';
        });
}

// Load anomalies on tab click
document.querySelector('.sidebar a:nth-child(4)').addEventListener('click', function() {
    fetch('/api/anomalies')
        .then(r => r.json())
        .then(data => {
            const div = document.getElementById('anomaly-results');
            if (data.error) { div.innerHTML = '<div class="alert alert-info">' + data.error + '</div>'; return; }
            if (data.anomalies && data.anomalies.length > 0) {
                let html = '<h5>Duration Anomalies (' + data.count + ' found)</h5><div style="max-height:500px; overflow-y:auto;"><table class="table table-sm table-striped"><thead><tr>';
                data.columns.forEach(c => html += '<th>' + c + '</th>');
                html += '</tr></thead><tbody>';
                data.anomalies.forEach(r => {
                    html += '<tr>';
                    data.columns.forEach(c => html += '<td>' + (r[c] || '') + '</td>');
                    html += '</tr>';
                });
                html += '</tbody></table></div>';
                div.innerHTML = html;
            } else {
                div.innerHTML = '<div class="alert alert-success">No significant anomalies detected.</div>';
            }
        });
});
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""


def render_dashboard():
    """Render the dashboard with current analyzer data."""
    global analyzer
    if analyzer is None:
        return DASHBOARD_HTML.replace('{{ record_type }}', 'No data loaded')
    
    stats = analyzer.summary()
    top = analyzer.top_talkers(10)
    anomalies = analyzer.detect_anomalies()
    off_hours = analyzer.detect_off_hours_activity()
    bursts = analyzer.detect_burst_activity()

    def table_from_df(df, cols):
        if df.empty:
            return '<p class="text-muted">No data</p>'
        h = ''.join(f'<th>{c}</th>' for c in cols)
        r = ''.join('<tr>' + ''.join(f'<td>{str(row.get(c, ""))[:30]}</td>' for c in cols) + '</tr>' for _, row in df.iterrows())
        return f'<table class="table table-sm table-striped"><thead><tr>{h}</tr></thead><tbody>{r}</tbody></table>'

    dr = stats.get('date_range', {})
    dur = stats.get('duration', {})

    overview_cards = f'''
    <div class="col-md-3 mb-3"><div class="stat-card text-center">
        <div class="number">{stats["total_records"]:,}</div>
        <div class="label">Total Records</div></div></div>
    <div class="col-md-3 mb-3"><div class="stat-card text-center">
        <div class="number">{f"{dur.get('mean', 0):.1f}" if dur else 'N/A'}</div>
        <div class="label">Avg Duration (s)</div></div></div>
    <div class="col-md-3 mb-3"><div class="stat-card text-center">
        <div class="number">{f"{dr.get('span_days', 0):.1f}" if dr else 'N/A'}</div>
        <div class="label">Days Span</div></div></div>
    <div class="col-md-3 mb-3"><div class="stat-card text-center">
        <div class="number">{f"{dur.get('total', 0)/3600:.1f}" if dur else 'N/A'}</div>
        <div class="label">Total Hours</div></div></div>
    '''

    anomaly_cards = f'''
    <div class="col-md-4 mb-3"><div class="stat-card text-center">
        <div class="number text-danger">{len(anomalies)}</div>
        <div class="label">Duration Anomalies</div></div></div>
    <div class="col-md-4 mb-3"><div class="stat-card text-center">
        <div class="number text-warning">{len(off_hours)}</div>
        <div class="label">Off-Hours Records</div></div></div>
    <div class="col-md-4 mb-3"><div class="stat-card text-center">
        <div class="number text-info">{len(bursts)}</div>
        <div class="label">Burst Records</div></div></div>
    '''

    return DASHBOARD_HTML \
        .replace('{{ record_type }}', f'{stats["record_type"]} · {stats["total_records"]:,} records') \
        .replace('{{ total_records }}', f'{stats["total_records"]:,} records loaded') \
        .replace('{{ overview_cards }}', overview_cards) \
        .replace('{{ top_callers_table }}', table_from_df(top.get('caller', pd.DataFrame()), ['id', 'count', 'percentage'])) \
        .replace('{{ top_callees_table }}', table_from_df(top.get('callee', pd.DataFrame()), ['id', 'count', 'percentage'])) \
        .replace('{{ anomaly_cards }}', anomaly_cards)


@app.route('/')
def index():
    global analyzer
    if analyzer is None:
        return render_dashboard()
    # Regenerate visualizations
    viz = Visualizer(analyzer, output_dir='./output/static')
    viz.generate_all()
    return render_dashboard()


@app.route('/upload', methods=['POST'])
def upload():
    global analyzer
    if 'file' not in request.files:
        return 'No file uploaded', 400
    file = request.files['file']
    if file.filename == '':
        return 'No file selected', 400
    path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(path)
    try:
        df = load_data(path)
        rtype = detect_record_type(df)
        analyzer = IPDRAnalyzer(df) if rtype == 'ipdr' else CDRAnalyzer(df)
        return index()
    except Exception as e:
        return f'Error loading file: {str(e)}', 500


@app.route('/load-sample/<rtype>')
def load_sample(rtype):
    global analyzer
    if rtype == 'cdr':
        path = './sample_data/sample_cdr.csv'
        df = load_data(path)
        analyzer = CDRAnalyzer(df)
    else:
        path = './sample_data/sample_ipdr.csv'
        df = load_data(path)
        analyzer = IPDRAnalyzer(df)
    return index()


@app.route('/api/search')
def api_search():
    q = request.args.get('q', '')
    if not q or analyzer is None:
        return jsonify({'error': 'No query or no data loaded'}), 400
    results = analyzer.get_record_by_ip(q) if isinstance(analyzer, IPDRAnalyzer) else analyzer.get_record_by_number(q)
    if results.empty:
        return jsonify({'records': [], 'total': 0, 'columns': []})
    records = results.head(100).fillna('').astype(str).to_dict('records')
    return jsonify({'records': records, 'total': len(results), 'columns': list(results.columns[:15])})


@app.route('/api/pattern')
def api_pattern():
    q = request.args.get('q', '')
    if not q or analyzer is None:
        return jsonify({'error': 'No query'}), 400
    result = {}
    hourly = analyzer.calling_hours_pattern(q)
    if not hourly.empty:
        result['hourly'] = hourly.to_dict('records')
    contacts = analyzer.most_frequent_contacts(q, 20)
    if not contacts.empty:
        result['contacts'] = contacts.to_dict('records')
    return jsonify(result)


@app.route('/api/anomalies')
def api_anomalies():
    if analyzer is None:
        return jsonify({'error': 'No data loaded'})
    anomalies = analyzer.detect_anomalies()
    if anomalies.empty:
        return jsonify({'anomalies': [], 'count': 0})
    cols = [c for c in anomalies.columns[:10] if c not in ('z_score',)]
    return jsonify({
        'anomalies': anomalies.head(100).fillna('').astype(str).to_dict('records'),
        'count': len(anomalies),
        'columns': cols
    })


@app.route('/report')
def download_report():
    if analyzer is None:
        return 'No data loaded', 400
    rg = ReportGenerator(analyzer, output_dir='./output')
    viz = Visualizer(analyzer, output_dir='./output/static')
    viz_files = viz.generate_all()
    report_path = rg.generate_html_report(viz_files)
    return send_file(report_path, as_attachment=True, download_name='analysis_report.html')


@app.route('/export')
def download_export():
    if analyzer is None:
        return 'No data loaded', 400
    path = './output/analysis_data.csv'
    analyzer.df.to_csv(path, index=False)
    return send_file(path, as_attachment=True, download_name='analysis_data.csv')


@app.route('/static/<path:filename>')
def static_files(filename):
    return send_file(f'./output/static/{filename}')
