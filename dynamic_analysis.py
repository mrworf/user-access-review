#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from datetime import datetime
import logging
import os
import yaml
import re
from validation_helper import ValidationHelper
from findings import FindingType, Finding

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
        return source.has_field(field) and compare.has_field(field)

    def field_only_in_compare(self, source, compare, field):
        return not source.has_field(field) and compare.has_field(field)

    def field_only_in_source(self, source, compare, field):
        return source.has_field(field) and not compare.has_field(field)

    def fields_differ(self, source, compare, user_id, field):
        if not self.field_supported(source, compare, field):
            # Field is not mapped, so we can't compare it
            logging.debug(f'Field "{field}" is not mapped, so we can\'t compare it')
            return False
        return source.users[user_id].get(field) != compare.users[user_id].get(field)

    def compare(self, source, compare):
        # Get the rules for comparing the source and compare data
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
                    # This means we won't check anything else. That could be a problem.
                    if compare.users[user_id].get('status') == 'active':
                        compare.add_finding(user_id, FindingType.SOURCE_MISSING_ACTIVE)
                    elif compare.users[user_id].get('status') == 'inactive':
                        compare.add_finding(user_id, FindingType.SOURCE_MISSING_INACTIVE)
                    elif compare.users[user_id].get('status') == 'suspended':
                        compare.add_finding(user_id, FindingType.SOURCE_MISSING_SUSPENDED)
                    elif compare.users[user_id].get('status') == 'deleted':
                        compare.add_finding(user_id, FindingType.SOURCE_MISSING_DELETED)
                    elif compare.users[user_id].get('status') == 'unknown':
                        compare.add_finding(user_id, FindingType.SOURCE_MISSING_UNKNOWN)
                    else:
                        compare.add_finding(user_id, FindingType.SOURCE_MISSING)
            else: # User exists in source
                # Check if the user status has discrepancies
                if self.fields_differ(source, compare, user_id, 'status'):
                    # Discrepancy, document it
                    compare.add_finding(user_id, FindingType.STATUS_MISMATCH, source_status=source.users[user_id].get('status'), compare_status=compare.users[user_id].get('status'))
                if self.fields_differ(source, compare, user_id, 'first_name'):
                    compare.add_finding(user_id, FindingType.FIRST_NAME_MISMATCH, source_name=source.users[user_id].get('first_name'), compare_name=compare.users[user_id].get('first_name'))
                elif self.field_only_in_compare(source, compare, 'first_name'):
                    if compare.users[user_id].get('first_name') == '':
                        compare.add_finding(user_id, FindingType.FIRST_NAME_MISSING)
                    elif not ValidationHelper.is_valid_name(compare.users[user_id].get('first_name')):
                        compare.add_finding(user_id, FindingType.FIRST_NAME_INVALID, name=compare.users[user_id].get('first_name'))
                if self.fields_differ(source, compare, user_id, 'last_name'):
                    compare.add_finding(user_id, FindingType.LAST_NAME_MISMATCH, source_name=source.users[user_id].get('last_name'), compare_name=compare.users[user_id].get('last_name'))
                elif self.field_only_in_compare(source, compare, 'last_name'):
                    if compare.users[user_id].get('last_name') == '':
                        compare.add_finding(user_id, FindingType.LAST_NAME_MISSING)
                    elif not ValidationHelper.is_valid_name(compare.users[user_id].get('last_name')):
                        compare.add_finding(user_id, FindingType.LAST_NAME_INVALID, name=compare.users[user_id].get('last_name'))
                if self.fields_differ(source, compare, user_id, 'email'):
                    compare.add_finding(user_id, FindingType.EMAIL_MISMATCH, source_email=source.users[user_id].get('email'), compare_email=compare.users[user_id].get('email'))
                elif self.field_only_in_compare(source, compare, 'email'):
                    if compare.users[user_id].get('email') == '':
                        compare.add_finding(user_id, FindingType.EMAIL_MISSING)
                    elif not ValidationHelper.is_valid_email(compare.users[user_id].get('email')):
                        compare.add_finding(user_id, FindingType.EMAIL_INVALID, email=compare.users[user_id].get('email'))
                if self.field_supported(source, compare, 'email'):
                    # Compare the email domain
                    source_domain = source.users[user_id].get('email').split('@')[1]
                    compare_domain = compare.users[user_id].get('email').split('@')[1]
                    if source_domain != compare_domain:
                        compare.add_finding(user_id, FindingType.DOMAIN_MISMATCH, domain=source_domain, compare_domain=compare_domain)
                if self.fields_differ(source, compare, user_id, 'department'):
                    compare.add_finding(user_id, FindingType.DEPT_MISMATCH, source_dept=source.users[user_id].get('department'), compare_dept=compare.users[user_id].get('department'))
                if self.fields_differ(source, compare, user_id, 'location'):
                    compare.add_finding(user_id, FindingType.LOCATION_MISMATCH, source_location=source.users[user_id].get('location'), compare_location=compare.users[user_id].get('location'))
                if self.fields_differ(source, compare, user_id, 'title'):
                    compare.add_finding(user_id, FindingType.TITLE_MISMATCH, source_title=source.users[user_id].get('title'), compare_title=compare.users[user_id].get('title'))

    def validate(self, compare):
        # Get the rules for validating the compare data
        val_rules = self.rules.get('validation', {}).get('rules', [])
        for rule in val_rules:
            # Check if the field is supported
            if not compare.has_field(rule.get('field')):
                continue
            for user_id in compare.users.keys():
                triggered = False
                value = compare.users[user_id].get(rule.get('field'))
                # Skip if the value is empty
                if rule.get('skip-empty', False):
                    if isinstance(value, datetime) and not ValidationHelper.has_date_value(value):
                        continue
                    elif isinstance(value, str) and value.strip() == '':
                        continue
                    elif isinstance(value, int) and value == 0:
                        continue
                    elif isinstance(value, float) and value == 0.0:
                        continue
                    elif isinstance(value, bool) and value == False:
                        continue
                    elif isinstance(value, list) and len(value) == 0:
                        continue
                    elif isinstance(value, dict) and len(value) == 0:
                        continue
                    elif value is None:
                        continue

                # Perform desired operation if defined
                if rule.get('operation') == 'days_since':
                    # Calculate the number of days since the value
                    value = (datetime.now() - value).days
                # Perform the comparison
                if rule.get('trigger') == 'greater_than' and value > rule.get('value'):
                    triggered = True
                elif rule.get('trigger') == 'less_than' and value < rule.get('value'):
                    triggered = True
                elif rule.get('trigger') == 'equal_to' and value == rule.get('value'):
                    triggered = True
                elif rule.get('trigger') == 'not_equal_to' and value != rule.get('value'):
                    triggered = True
                elif rule.get('trigger') == 'equal_to_case' and str(value).casefold() == str(rule.get('value')).casefold():
                    triggered = True
                elif rule.get('trigger') == 'not_equal_to_case' and str(value).casefold() != str(rule.get('value')).casefold():
                    triggered = True
                elif rule.get('trigger') == 'contains' and str(rule.get('value')).casefold() in str(value).casefold():
                    triggered = True
                elif rule.get('trigger') == 'not_contains' and str(rule.get('value')).casefold() not in str(value).casefold():
                    triggered = True
                elif rule.get('trigger') == 'starts_with' and str(value).startswith(str(rule.get('value'))):
                    triggered = True
                elif rule.get('trigger') == 'ends_with' and str(value).endswith(str(rule.get('value'))):
                    triggered = True
                elif rule.get('trigger') == 'starts_with_case' and str(value).casefold().startswith(str(rule.get('value')).casefold()):
                    triggered = True
                elif rule.get('trigger') == 'ends_with_case' and str(value).casefold().endswith(str(rule.get('value')).casefold()):
                    triggered = True
                elif rule.get('trigger') == 'matches' and re.match(rule.get('regex'), str(value)):
                    triggered = True
                elif rule.get('trigger') == 'not_matches' and not re.match(rule.get('regex'), str(value)):
                    triggered = True
                elif rule.get('trigger') == 'in' and value in rule.get('values'):
                    triggered = True
                elif rule.get('trigger') == 'not_in' and value not in rule.get('values'):
                    triggered = True
                elif rule.get('trigger') == 'is_true' and value is True:
                    triggered = True
                elif rule.get('trigger') == 'is_false' and value is False:
                    triggered = True
                elif rule.get('trigger') == 'is_none' and value is None:
                    triggered = True
                elif rule.get('trigger') == 'is_not_none' and value is not None:
                    triggered = True
                    
                if triggered:
                    compare.add_finding(user_id, Finding(rule.get('name'), rule.get('reason'), rule.get('severity')), value=value)
