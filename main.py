#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import os
import json
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
from findings import Severity

def parse_arguments():
    parser = argparse.ArgumentParser(description='User Access Review Tool')
    parser.add_argument('--truth', type=str, help='Source of truth for all user access data (like Google Workspace, Okta, etc)')
    parser.add_argument('--truth_map', type=str, help='YAML file describing how we map the source of truth to our internal user data')
    parser.add_argument('--compare', type=str, help='What to compare the source of truth to')
    parser.add_argument('--compare_map', type=str, help='YAML file describing how we map the compare data to our internal user data')
    parser.add_argument('--output', type=str, help='filename to write output to (default is csv)')
    parser.add_argument('--config', type=str, help='YAML describing source of truth and compare data')
    return parser.parse_args()

def process_source(source: DataSource, analyzer: StaticAnalysis, output_prefix: str = None):
    if analyzer.validate(source):
        print('The source of truth is clean.')
    else:
        print('The source of truth has the following issues:')
        # Print all findings by severity
        for severity in [Severity.ERROR, Severity.WARNING, Severity.NOTICE]:
            findings = source.get_findings_by_severity(severity)
            if findings:
                print(f'  {severity.value.title()}s:')
                for user_id, user_findings in findings.items():
                    for finding in user_findings:
                        print(f'    {user_id}: {finding.message}')

    if output_prefix:
        # Save the source of truth to a CSV file
        source.save(f'{output_prefix}_source.csv')

        # Also generate a report which can be used to update the source of truth
        report = Report()
        report.generate(source)
        report.save(f'{output_prefix}_report.csv')

def process_comparison(source: DataSource, compare: DataSource, analyzer: StaticAnalysis, rules_file: str = None):
    if analyzer.validate(compare):
        print('The compare data is clean.')
    else:
        print('The compare data has the following issues:')

    print('=' * 80)

    dynamic = DynamicAnalysis(rules_file)
    dynamic.compare(source, compare)

    # Print all findings by severity
    for severity in [Severity.ERROR, Severity.WARNING, Severity.NOTICE]:
        findings = compare.get_findings_by_severity(severity)
        if findings:
            print(f'  {severity.value.title()}s:')
            for user_id, user_findings in findings.items():
                for finding in user_findings:
                    print(f'    {user_id}: {finding.message}')
    return dynamic

if __name__ == "__main__":
    args = parse_arguments()
    analyzer = StaticAnalysis()

    if args.config:
        # Load configuration from file
        config = Config.from_file(args.config)
        
        # Process source of truth
        source = DataSource()
        source.load(config.truth_source, config.truth_map)
        process_source(source, analyzer, config.output_prefix)

        master_report = []

        # Process comparisons if any
        for comp in config.comparisons:
            compare = DataSource()
            compare.load(comp.source, comp.map_file)
            rules = comp.rules or config.rules
            process_comparison(source, compare, analyzer, rules)
            report = Report()
            report.generate(compare)
            report.save(f'{config.output_prefix}_{comp.safe_name}.csv')
            master_report.append(compare)

        # Save the master report (includes all sources)
        report = Report()
        report.generate(master_report)
        report.save(f'{config.output_prefix}_master.csv')
    else:
        # Process using command line arguments
        source = DataSource()
        source.load(args.truth, args.truth_map)
        process_source(source, analyzer, args.output)

        if args.compare:
            compare = DataSource()
            compare.load(args.compare, args.compare_map)
            process_comparison(source, compare, analyzer)
        else:
            print('No comparison data provided.')