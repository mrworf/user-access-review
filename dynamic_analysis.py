#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import yaml
import re
from findings import FindingType, Severity

class DynamicAnalysis:
    def __init__(self, rules_file = None):
        self.rules = self.load_yaml(rules_file) if rules_file else {}  
        self.findings = {}

    def add_finding(self, user_id, finding: FindingType, **kwargs):
        """Add a finding for a user
        
        Args:
            user_id: The user ID
            finding: The Finding object
            **kwargs: Parameters to format into the finding description
        """
        if user_id not in self.findings:
            self.findings[user_id] = []
        self.findings[user_id].append(finding(**kwargs))

    def load_yaml(self, file_path):
        # Load YAML data without converting 'yes' and 'no' to booleans
        def no_bool_constructor(loader, node):
            return loader.construct_scalar(node)
        yaml.SafeLoader.add_constructor('tag:yaml.org,2002:bool', no_bool_constructor)

        if not file_path or not os.path.exists(file_path):
            raise ValueError(f'File "{file_path}" does not exist')
        with open(file_path, 'r') as file:
            data = yaml.safe_load(file)
        return data

    def compare(self, source, compare):
        # Get the rules for comparing the source and compare data
        comp_rules = self.rules.get('comparison', {}).get('rules', [])
        comp_exceptions = self.rules.get('comparison', {}).get('exceptions', [])

        # First, find all users in the compare that are not in the source
        for user_id in compare.users.keys():
            if user_id not in source.users:
                # Okay, we found one, is there an exception for particular user and source?
                for exception in comp_exceptions:
                    # Check if this applies to the datasource
                    if 'only' in exception and compare.name not in exception.get('only', []):
                        continue
                    if 'skip' in exception and compare.name in exception.get('skip', []):
                        continue
                    field = exception.get('field')
                    pattern = re.compile(exception.get('pattern'))
                    # Fetch the value of the field from the compare user
                    value = compare.users[user_id].get(field)
                    reason = exception.get('reason')
                    if pattern.match(value):
                        # We found a match, so we can skip this user, but document it
                        compare.add_finding(user_id, FindingType.DOCUMENTED_EXCEPTION, reason=reason)
                        break
                else:
                    compare.add_finding(user_id, FindingType.NOT_IN_SOURCE)