#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import csv
from models.findings import Severity

class Report:
    def __init__(self):
        self.rows = []
    
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
                    self.rows.append({
                        'source': s.name,
                        'user_id': user_id,
                        'severity': str(finding.severity).upper(),
                        'finding': finding.key,
                        'message': finding.message
                    })
            for user_id, user in s.users.items():
                if user_id not in s.findings:
                    self.rows.append({
                        'source': s.name,
                        'user_id': user_id,
                        'severity': 'INFO',
                        'finding': 'CLEAN',
                        'message': 'No issues found'
                    })

    def save(self, filename):
        """Save the report to a CSV file
        
        Args:
            filename: The name of the file to save to
        """
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['source', 'user_id', 'severity', 'finding', 'message'])
            writer.writeheader()
            writer.writerows(self.rows)