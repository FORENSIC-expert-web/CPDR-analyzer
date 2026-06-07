#!/usr/bin/env python3
"""
CDR/IPDR Analysis Tool - Entry Point
Start with: python run.py
"""

import os
import sys
import argparse

# Ensure the project root is in the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.webapp import app


def main():
    parser = argparse.ArgumentParser(description='CDR/IPDR Analysis Tool')
    parser.add_argument('--port', '-p', type=int, default=5000, help='Port (default: 5000)')
    parser.add_argument('--host', default='0.0.0.0', help='Host (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true', help='Debug mode')
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║      CDR / IPDR Examination & Analysis Tool v1.0            ║
║      ──────────────────────────────────────────             ║
║      Dashboard: http://{args.host}:{args.port}                    ║
║      Press Ctrl+C to stop                                   ║
╚══════════════════════════════════════════════════════════════╝
    """)
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
