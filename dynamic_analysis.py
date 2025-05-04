#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
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

    def field_supported(self, source, compare, field):
        return field in source.mapping and field in compare.mapping

    def fields_differ(self, source, compare, user_id, field):
        if not self.field_supported(source, compare, field):
            # Field is not mapped, so we can't compare it
            logging.debug(f'Field "{field}" is not mapped, so we can\'t compare it')
            return False
        return source.users[user_id].get(field) != compare.users[user_id].get(field)

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
            else: # User exists in source
                # Check if the user status has discrepancies
                if self.fields_differ(source, compare, user_id, 'status'):
                    # Discrepancy, document it
                    if source.users[user_id].get('status') == 'active':
                        compare.add_finding(user_id, FindingType.NOT_ACTIVE_COMPARE, status=compare.users[user_id].get('status'), source_status=source.users[user_id].get('status'))
                    elif compare.users[user_id].get('status') == 'active':
                        compare.add_finding(user_id, FindingType.NOT_ACTIVE_SOURCE, status=source.users[user_id].get('status'), compare_status=compare.users[user_id].get('status'))
                if self.fields_differ(source, compare, user_id, 'first_name'):
                    compare.add_finding(user_id, FindingType.NAME_MISMATCH, source_name=source.users[user_id].get('first_name'), compare_name=compare.users[user_id].get('first_name'))
                if self.fields_differ(source, compare, user_id, 'last_name'):
                    compare.add_finding(user_id, FindingType.NAME_MISMATCH, source_name=source.users[user_id].get('last_name'), compare_name=compare.users[user_id].get('last_name'))
                if self.fields_differ(source, compare, user_id, 'email'):
                    compare.add_finding(user_id, FindingType.EMAIL_MISMATCH, source_email=source.users[user_id].get('email'), compare_email=compare.users[user_id].get('email'))
                if self.field_supported(source, compare, 'email'):
                    # Compare the email domain
                    source_domain = source.users[user_id].get('email').split('@')[1]
                    compare_domain = compare.users[user_id].get('email').split('@')[1]
                    if source_domain != compare_domain:
                        compare.add_finding(user_id, FindingType.DOMAIN_MISMATCH, source_domain=source_domain, compare_domain=compare_domain)
        # Next
