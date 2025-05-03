#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import os

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

def parse_arguments():
    parser = argparse.ArgumentParser(description='User Access Review Tool')
    parser.add_argument('truth', type=str, help='Source of truth for all user access data (like Google Workspace, Okta, etc)')
    parser.add_argument('truth_map', type=str, help='YAML file describing how we map the source of truth to our internal user data')
    parser.add_argument('--compare', type=str, help='What to compare the source of truth to')
    parser.add_argument('--compare_map', type=str, help='YAML file describing how we map the compare data to our internal user data')
    parser.add_argument('--output', type=str, help='filename to write output to (default is csv)')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()

    analyzer = StaticAnalysis()

    source = DataSource()
    source.load(args.truth, args.truth_map)

    if analyzer.validate(source):
        print('The source of truth is clean.')
    else:
        print('The source of truth has the following issues:')
        # Print all known errors, warnings and notices
        for user_id in source.users.keys():
            if user_id in source.errors:
                for message in source.errors[user_id]:
                    print(f'  Error: {user_id}: {message}')
            if user_id in source.warnings:
                for message in source.warnings[user_id]:
                    print(f'  Warning: {user_id}: {message}')
            if user_id in source.notice:
                for message in source.notice[user_id]:
                    print(f'  Notice: {user_id}: {message}')

    if args.compare:
        compare = DataSource()
        compare.load(args.compare, args.compare_map)

        if analyzer.validate(compare):
            print('The compare data is clean.')
        else:
            print('The compare data has the following issues:')

        print('=' * 80)

        dynamic = DynamicAnalysis('rules.yaml')
        dynamic.compare(source, compare)

        # Print all known errors, warnings and notices
        for user_id, messages in dynamic.errors.items():
            for message in messages:
                print(f'  Error: {user_id}: {message}')
        for user_id, messages in dynamic.warnings.items():
            for message in messages:
                print(f'  Warning: {user_id}: {message}')
        for user_id, messages in dynamic.notice.items():
            for message in messages:
                print(f'  Notice: {user_id}: {message}')
    else:
        print('No comparison data provided.')
        # Save the source of truth to a CSV file
        source.save(args.output + '_source.csv')

        # Also generate a report which can be used to update the source of truth
        report = Report()
        report.generate(source)
        report.save(args.output + '_report.csv')