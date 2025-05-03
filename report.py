#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import csv
from datetime import datetime

class Report:
    def __init__(self):
        self.rows = []

    def generate(self, source):
        """
        Generate a report from the source data and its findings.
        Each finding (error, warning, notice) will be a separate row with minimal user data.
        """
        # Define the minimal report fields
        report_fields = [
            'user_id', 'email', 'first_name', 'last_name', 'status',
            'finding_type', 'finding_message'
        ]

        # Process each user
        for user_id, user_data in source.users.items():
            # Add a row for each error
            if user_id in source.errors:
                for message in source.errors[user_id]:
                    row = {
                        'user_id': user_data['user_id'],
                        'email': user_data['email'],
                        'first_name': user_data['first_name'],
                        'last_name': user_data['last_name'],
                        'status': user_data['status'],
                        'finding_type': 'ERROR',
                        'finding_message': message
                    }
                    self.rows.append(row)

            # Add a row for each warning
            if user_id in source.warnings:
                for message in source.warnings[user_id]:
                    row = {
                        'user_id': user_data['user_id'],
                        'email': user_data['email'],
                        'first_name': user_data['first_name'],
                        'last_name': user_data['last_name'],
                        'status': user_data['status'],
                        'finding_type': 'WARNING',
                        'finding_message': message
                    }
                    self.rows.append(row)

            # Add a row for each notice
            if user_id in source.notice:
                for message in source.notice[user_id]:
                    row = {
                        'user_id': user_data['user_id'],
                        'email': user_data['email'],
                        'first_name': user_data['first_name'],
                        'last_name': user_data['last_name'],
                        'status': user_data['status'],
                        'finding_type': 'NOTICE',
                        'finding_message': message
                    }
                    self.rows.append(row)

            # If no findings, add a row indicating everything is clean
            if (user_id not in source.errors and 
                user_id not in source.warnings and 
                user_id not in source.notice):
                row = {
                    'user_id': user_data['user_id'],
                    'email': user_data['email'],
                    'first_name': user_data['first_name'],
                    'last_name': user_data['last_name'],
                    'status': user_data['status'],
                    'finding_type': 'CLEAN',
                    'finding_message': 'No issues found'
                }
                self.rows.append(row)

    def save(self, output_path):
        """
        Save the report to a CSV file.
        If no output path is provided, generate a timestamped filename.
        """
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f'user_access_findings_{timestamp}.csv'

        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = [
                'user_id', 'email', 'first_name', 'last_name', 'status',
                'finding_type', 'finding_message'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.rows) 