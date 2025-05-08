#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import csv
from models.findings import Severity

class Report:
    def __init__(self, include=[]):
        self.rows = []
        self.include = include
    
    def generate(self, source):
        """Generate a report from the source data
        
        Args:
            source: The data source to generate the report from
        """
        if not isinstance(source, list):
            source = [source]

        # Add a row for each finding
        for s in source:
            for user_id, findings in s.findings.items():
                for finding in findings:
                    row = {
                        'source': s.name,
                        'user_id': user_id,
                        'severity': str(finding.severity).upper(),
                        'finding': finding.key,
                        'message': finding.message
                    }
                    # Add any additional included fields from the user data
                    for field in self.include:
                        if field in s.users[user_id]:
                            row[field] = s.users[user_id][field]
                    self.rows.append(row)
            
            for user_id, user in s.users.items():
                if user_id not in s.findings:
                    row = {
                        'source': s.name,
                        'user_id': user_id,
                        'severity': 'INFO',
                        'finding': 'CLEAN',
                        'message': 'No issues found'
                    }
                    # Add any additional included fields from the user data
                    for field in self.include:
                        if field in user:
                            row[field] = user[field]
                    self.rows.append(row)

    def save(self, filename):
        """Save the report to a CSV file
        
        Args:
            filename: The name of the file to save to
        """
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['source', 'user_id'] + self.include + ['severity', 'finding', 'message'])
            writer.writeheader()
            writer.writerows(self.rows)