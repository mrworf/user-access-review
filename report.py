#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import csv
from findings import Severity

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
                if not isinstance(findings, list):
                    self.rows.append({
                        'source': s.name,
                        'user_id': user_id,
                        'finding_type': 'CLEAN',
                        'message': 'No issues found'
                    })
                else:
                    for finding in findings:
                        self.rows.append({
                            'source': s.name,
                            'user_id': user_id,
                            'finding_type': str(finding.severity).upper(),
                            'message': finding.message
                        })
        
    
    def save(self, filename):
        """Save the report to a CSV file
        
        Args:
            filename: The name of the file to save to
        """
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['source', 'user_id', 'finding_type', 'message'])
            writer.writeheader()
            writer.writerows(self.rows)