#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import logging
import os
import json

from receipt import Receipt
"""
User Access Review Tool

This script provides functionality to parse a CSV file containing user access data and process it.

Usage:
    python main.py <csv_file>

License:
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

from data_source import DataSource
from static_analysis import StaticAnalysis
from dynamic_analysis import DynamicAnalysis
from report import Report
from config import Config

def parse_arguments():
    parser = argparse.ArgumentParser(description='User Access Review Tool')
    parser.add_argument('config', type=str, help='YAML describing source of truth and compare data')
    return parser.parse_args()

def process_source(source: DataSource, analyzer: StaticAnalysis, output_prefix: str = None):
    analyzer.validate(source)

def process_comparison(source: DataSource, compare: DataSource, analyzer: StaticAnalysis, rules_file: str = None):
    analyzer.validate(compare)
    dynamic = DynamicAnalysis(rules_file)
    dynamic.validate(compare)
    dynamic.compare(source, compare)

if __name__ == "__main__":
    args = parse_arguments()
    analyzer = StaticAnalysis()
    receipt = Receipt()

    # Load configuration from file
    config = Config.from_file(args.config)
    receipt.audit_file(args.config, "Configuration file")
    
    # Process source of truth
    source = DataSource()
    source.load(config.truth_source, config.truth_map)
    receipt.audit_file(config.truth_source, "Source of truth")
    receipt.audit_file(config.truth_map, "Source of truth field mapping")
    process_source(source, analyzer, config.output_prefix)
    source.save(f'{config.output_prefix}_baseline.csv')
    receipt.audit_file(f'{config.output_prefix}_baseline.csv', "Source of truth baseline")
    master_report = [source]

    # Process comparisons if any
    for comp in config.comparisons:
        compare = DataSource()
        compare.load(comp.source, comp.map_file)
        receipt.audit_file(comp.source, "Comparison source")
        receipt.audit_file(comp.map_file, "Comparison field mapping")
        rules = comp.rules or config.rules
        process_comparison(source, compare, analyzer, rules)
        compare.save(f'{config.output_prefix}_{comp.safe_name}_baseline.csv')

        master_report.append(compare)

    # Save the master report (includes all sources)
    report = Report()
    report.generate(master_report)
    report.save(f'{config.output_prefix}_findings.csv')
    receipt.audit_file(f'{config.output_prefix}_findings.csv', "Findings report")

    # Save the receipt
    receipt_filename = f'{config.output_prefix}_receipt.txt'
    try:
        receipt_hash = receipt.save(receipt_filename)
        print(f'Receipt saved to {receipt_filename}')
        print(f'Receipt SHA256: {receipt_hash}')
    except Exception as e:
        logging.error(f'Error saving receipt: {e}')
        raise