#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import yaml
import re

class DynamicAnalysis:
    def __init__(self, configuration):
        self.configuration = self.load_yaml(configuration)
        self.warnings = {}
        self.errors = {}
        self.notice = {}

    def add_error(self, user_id, message):
        if user_id not in self.errors:
            self.errors[user_id] = []
        self.errors[user_id].append(message)

    def add_warning(self, user_id, message):
        if user_id not in self.warnings:
            self.warnings[user_id] = []
        self.warnings[user_id].append(message)

    def add_notice(self, user_id, message):
        if user_id not in self.notice:
            self.notice[user_id] = []
        self.notice[user_id].append(message)

    def load_yaml(self, file_path):
        # Load YAML data without converting 'yes' and 'no' to booleans
        def no_bool_constructor(loader, node):
            return loader.construct_scalar(node)
        yaml.SafeLoader.add_constructor('tag:yaml.org,2002:bool', no_bool_constructor)

        if not file_path or not os.path.exists(file_path):
            return {}
        with open(file_path, 'r') as file:
            data = yaml.safe_load(file)
        return data

    def compare(self, source, compare):
        # Get the rules for comparing the source and compare data
        comp_rules = self.configuration.get('comparison', {}).get('rules', [])
        comp_exceptions = self.configuration.get('comparison', {}).get('exceptions', [])

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
                        self.add_notice(user_id, f'Doesn\'t exist in source but is a documented exception: {reason}')
                        break
                else:
                    self.add_warning(user_id, f'Not found in source data') 