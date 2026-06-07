#!/usr/bin/env python3
"""
Visualization engine for CDR/IPDR Analyzer.
Generates charts, maps, and network graphs.
"""

import os
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

import networkx as nx
import folium
from folium.plugins import HeatMap, MarkerCluster

import pandas as pd


class Visualizer:
    """Generate visualizations from analysis results."""

    def __init__(self, analyzer, output_dir='./output/static'):
        self.analyzer = analyzer
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []

    def plot_hourly_activity(self):
        hourly = self.analyzer.hourly_activity()
        if hourly.empty:
            return None
        plt.figure(figsize=(12, 5))
        bars = plt.bar(hourly['hour'], hourly['count'], color='#2196F3', edgecolor='white', alpha=0.85)
        bars[hourly['count'].idxmax()].set_color('#F44336')
        plt.xlabel('Hour of Day', fontsize=12)
        plt.ylabel('Number of Records', fontsize=12)
        plt.title('Activity by Hour of Day (24h)', fontsize=14, fontweight='bold')
        plt.xticks(range(0, 24))
        plt.grid(axis='y', alpha=0.3)
        plt.tight_layout()
        path = self.output_dir / 'hourly_activity.png'
        plt.savefig(path, dpi=150)
        plt.close()
        self.generated_files.append(str(path))
        return str(path)

    def plot_weekday_activity(self):
        weekday = self.analyzer.weekday_activity()
        if weekday.empty:
            return None
        plt.figure(figsize=(10, 5))
        colors = ['#4CAF50' if i < 5 else '#FF9800' for i in weekday['code']]
        plt.bar(weekday['weekday'], weekday['count'], color=colors, edgecolor='white', alpha=0.85)
        plt.xlabel('Day of Week', fontsize=12)
        plt.ylabel('Number of Records', fontsize=12)
        plt.title('Activity by Day of Week', fontsize=14, fontweight='bold')
        plt.grid(axis='y', alpha=0.3)
        plt.tight_layout()
        path = self.output_dir / 'weekday_activity.png'
        plt.savefig(path, dpi=150)
        plt.close()
        self.generated_files.append(str(path))
        return str(path)

    def plot_top_talkers(self, role='caller', n=15):
        top = self.analyzer.top_talkers(n)
        if not top or role not in top or top[role].empty:
            return None
        df = top[role]
        plt.figure(figsize=(10, max(5, n * 0.35)))
        labels = [str(x)[-25:] for x in df['id'].head(n)]
        values = df['count'].head(n)
        plt.barh(range(len(labels)), values[::-1], color='#2196F3', edgecolor='white', alpha=0.85)
        plt.yticks(range(len(labels)), labels[::-1], fontsize=9)
        plt.xlabel('Record Count', fontsize=12)
        plt.title(f'Top {n} {"Callers" if role == "caller" else "Destinations"}', fontsize=14, fontweight='bold')
        plt.grid(axis='x', alpha=0.3)
        plt.tight_layout()
        path = self.output_dir / f'top_{role}s.png'
        plt.savefig(path, dpi=150, bbox_inches='tight')
        plt.close()
        self.generated_files.append(str(path))
        return str(path)

    def plot_duration_distribution(self):
        dur_col = self.analyzer.cols.get('duration')
        if not dur_col or dur_col not in self.analyzer.df:
            return None
        dur = self.analyzer.df[dur_col].dropna()
        if len(dur) == 0:
            return None
        clipped = dur.clip(upper=dur.quantile(0.98))
        plt.figure(figsize=(10, 5))
        plt.hist(clipped, bins=50, color='#2196F3', alpha=0.7, edgecolor='white')
        plt.axvline(dur.median(), color='#F44336', linestyle='--', linewidth=2, label=f'Median: {dur.median():.1f}')
        plt.axvline(dur.mean(), color='#FF9800', linestyle='--', linewidth=2, label=f'Mean: {dur.mean():.1f}')
        plt.xlabel('Duration (seconds)', fontsize=12)
        plt.ylabel('Frequency', fontsize=12)
        plt.title('Duration Distribution', fontsize=14, fontweight='bold')
        plt.legend(fontsize=10)
        plt.grid(axis='y', alpha=0.3)
        plt.tight_layout()
        path = self.output_dir / 'duration_distribution.png'
        plt.savefig(path, dpi=150)
        plt.close()
        self.generated_files.append(str(path))
        return str(path)

    def plot_protocol_distribution(self):
        from app.analyzer import IPDRAnalyzer
        if not isinstance(self.analyzer, IPDRAnalyzer):
            return None
        proto = self.analyzer.protocol_distribution()
        if not proto:
            return None
        labels, values = list(proto.keys()), list(proto.values())
        total = sum(values)
        threshold = total * 0.03
        main_labels, main_values, other = [], [], 0
        for l, v in zip(labels, values):
            if v >= threshold:
                main_labels.append(l); main_values.append(v)
            else:
                other += v
        if other > 0:
            main_labels.append('Other'); main_values.append(other)
        plt.figure(figsize=(8, 8))
        plt.pie(main_values, labels=main_labels, autopct='%1.1f%%', colors=plt.cm.Set3(range(len(main_labels))), startangle=90)
        plt.title('Protocol Distribution', fontsize=14, fontweight='bold')
        plt.tight_layout()
        path = self.output_dir / 'protocol_distribution.png'
        plt.savefig(path, dpi=150)
        plt.close()
        self.generated_files.append(str(path))
        return str(path)

    def plot_timeline(self):
        daily = self.analyzer.daily_activity()
        if daily.empty:
            return None
        dates = pd.to_datetime(daily['date'])
        counts = daily['count']
        plt.figure(figsize=(14, 5))
        plt.plot(dates, counts, color='#2196F3', linewidth=1.5, marker='o', markersize=3)
        plt.fill_between(dates, counts, alpha=0.1, color='#2196F3')
        plt.xlabel('Date', fontsize=12)
        plt.ylabel('Record Count', fontsize=12)
        plt.title('Activity Timeline', fontsize=14, fontweight='bold')
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
        plt.gcf().autofmt_xdate()
        plt.grid(alpha=0.3)
        plt.tight_layout()
        path = self.output_dir / 'activity_timeline.png'
        plt.savefig(path, dpi=150)
        plt.close()
        self.generated_files.append(str(path))
        return str(path)

    def generate_map(self, tower_data=None):
        m = folium.Map(location=[20, 0], zoom_start=2, tiles='OpenStreetMap')
        cell_col = self.analyzer.cols.get('cell_id')
        if tower_data is not None and not tower_data.empty:
            mc = MarkerCluster().add_to(m)
            for _, row in tower_data.iterrows():
                lat, lon = row.get('lat'), row.get('lon')
                if pd.notna(lat) and pd.notna(lon):
                    folium.Marker([lat, lon],
                        popup=f"Cell: {row.get(cell_col, 'N/A')}<br>Records: {row.get('call_count', row.get('count', 'N/A'))}",
                        icon=folium.Icon(color='blue', icon='signal', prefix='fa')).add_to(mc)
        path = self.output_dir / 'activity_map.html'
        m.save(str(path))
        self.generated_files.append(str(path))
        return str(path)

    def generate_network_graph(self, graph_data):
        if not graph_data.get('nodes'):
            return None
        G = nx.Graph()
        for node in graph_data['nodes']:
            G.add_node(node['id'], label=node['label'])
        for edge in graph_data['edges']:
            G.add_edge(edge['source'], edge['target'], weight=edge.get('weight', 1))
        plt.figure(figsize=(14, 10))
        pos = nx.spring_layout(G, k=0.3, iterations=50, seed=42)
        degrees = dict(G.degree())
        node_sizes = [200 + degrees[n] * 20 for n in G.nodes()]
        node_colors = ['#2196F3' if degrees[n] > 1 else '#B0BEC5' for n in G.nodes()]
        nx.draw_networkx_nodes(G, pos, node_size=node_sizes, node_color=node_colors, alpha=0.8)
        nx.draw_networkx_edges(G, pos, alpha=0.2, width=[G[u][v].get('weight', 1) * 0.5 for u, v in G.edges()])
        nx.draw_networkx_labels(G, pos, font_size=7, alpha=0.9)
        plt.title('Connection Network Graph', fontsize=14, fontweight='bold')
        plt.axis('off')
        plt.tight_layout()
        path = self.output_dir / 'network_graph.png'
        plt.savefig(path, dpi=150, bbox_inches='tight')
        plt.close()
        self.generated_files.append(str(path))
        return str(path)

    def generate_all(self):
        """Generate all standard visualizations."""
        self.plot_hourly_activity()
        self.plot_weekday_activity()
        self.plot_duration_distribution()
        self.plot_timeline()
        self.plot_top_talkers('caller')
        self.plot_top_talkers('callee')
        self.plot_protocol_distribution()
        graph = self.analyzer.build_connection_graph()
        self.generate_network_graph(graph)
        towers = self.analyzer.tower_analysis()
        if not towers.empty:
            self.generate_map(towers)
        return self.generated_files
