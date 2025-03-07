#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import os
import dateutil.parser
import pytz

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
import csv
import yaml
import re

def parse_arguments():
    parser = argparse.ArgumentParser(description='User Access Review Tool')
    parser.add_argument('truth', type=str, help='Source of truth for all user access data (like Google Workspace, Okta, etc)')
    parser.add_argument('truth_map', type=str, help='YAML file describing how we map the source of truth to our internal user data')
    parser.add_argument('compare', type=str, help='What to compare the source of truth to')
    parser.add_argument('compare_map', type=str, help='YAML file describing how we map the compare data to our internal user data')
    return parser.parse_args()

'''
Our tool uses the following fields internally, so all data sources must
be mapped to these fields.

The tool will perform validation checks based on the values. The yaml file
allows each CSV file to be mapped properly to these fields, including remapping
the content of the field (specifically the status field).

TODO:
This should be loaded from a YAML file, not hardcoded here. Well, except for the user_id field.
However, this also means the rules must be flexible and loaded from the YAML file.

'''
common_fields = {
    'user_id':'str',
    'email':'email',
    'first_name':'name',
    'last_name':'name',
    'department':'str',
    'role':'str',
    'title':'str',
    'manager':'email',
    'location':'str',
    'last_login':'date',
    'created_date':'date',
    'end_date':'date',
    'status':['active', 'inactive', 'suspended', 'deleted', 'unknown'],
    'type':['employee', 'contractor', 'intern', 'vendor', 'unknown'],
    'two_factor':'bool',
}

'''
There's also warning, error and info fields where messages about an entry can be stored.
'''

class DataSource:
    __NEVER_LOGGED_IN = dateutil.parser.parse('1970-01-01T00:00:00Z') # Not the ideal way to handle this, but let's do this for now

    def __init__(self):
        self.name = None
        self.users = None
        self.mapping = None
        self.tz = {tz: pytz.timezone(tz) for tz in pytz.all_timezones}
        
        # Add some missing timezones
        self.tz['EDT'] = self.tz['EST']
        
        #print(f'TZ = {self.tz}')

    def load(self, csv_file, yaml_file):
        config = self.load_yaml(yaml_file)
        self.mapping = config.get('mapping', {})
        self.rewrite = config.get('rewrite', {})

        self.users = self.load_csv(csv_file)
        self.name = os.path.splitext(os.path.basename(csv_file))[0]

        self.managers = {}
        self.warnings = {}
        self.errors = {}
        self.notice = {}
        # Separate out the managers for easier processing
        for user in self.users.values():
            if user['manager'] != '' and user['manager'] not in self.managers:
                mgr = self.users.get(user['manager'])
                if mgr is not None:
                    self.managers[user['manager']] = mgr

    def conform(self, value, field):
        if field not in common_fields:
            raise ValueError(f'Field "{field}" not found in common fields for field "{field}"')
        if isinstance(common_fields[field], list):
            if value not in common_fields[field]:
                raise ValueError(f'Value "{value}" not in allowed values for field "{field}"')
        elif common_fields[field] == 'email':
            value = value.lower().strip()
            if not re.match(r'[^@]+@[^@]+\.[^@]+', value) and value != '':
                raise ValueError(f'Value "{value}" is not a valid email address for field "{field}"')
        elif common_fields[field] == 'name':
            if not re.match(r'[A-Za-z\- ]+', value):
                raise ValueError(f'Value "{value}" is not a valid name for field "{field}"')
        elif common_fields[field] == 'date':
            try:
                # Try to parse the date and time
                value = dateutil.parser.parse(value, tzinfos=self.tz)
                if value.tzinfo is None:
                    value = value.replace(tzinfo=pytz.UTC)
            except ValueError:
                raise ValueError(f'Value "{value}" is not a valid date for field "{field}"')
        elif common_fields[field] == 'str':
            if value is None:
                raise ValueError(f'Value "{value}" is not a valid string for field "{field}"')
        elif common_fields[field] == 'bool':
            if value.lower() in ['true', 'false']:
                value = value.lower() == 'true'
            elif value.lower() in ['yes', 'no']:
                value = value.lower() == 'yes'
            elif value.lower() in ['1', '0']:
                value = value.lower() == '1'
            else:
                raise ValueError(f'Value "{value}" is not a valid boolean for field "{field}"')
        return value

    def load_csv(self, file_path):
        with open(file_path, mode='r') as file:
            csv_reader = csv.DictReader(file)
            data = {}
            for row in csv_reader:
                line = {}
                # Grab only the mapped fields, ignore the rest
                for k, v in self.mapping.items():
                    line[k] = row.get(v)
                    if line[k] is None:
                        raise ValueError(f'Field "{v}" not found in CSV file')
                    # Rewrite the value if needed
                    if k in self.rewrite:
                        # Next, loop through possible combos
                        # Doing this in a loop allows for "else" conditions
                        # Also allow use of backreferences to change the value
                        for dst, src in self.rewrite[k].items():
                            #print(f'Checking "{src}" against "{line[k]}"')
                            #print(repr(src))
                            if src is None and line[k] == '':
                                #print('Blank')
                                line[k] = dst
                                break
                            elif src is None:
                                continue # We can't match a blank value
                            match = re.match(src, line[k])
                            if match:
                                line[k] = match.expand(dst)
                                break
                    # Conform the value to the expected type
                    line[k] = self.conform(line[k], k)
                if line['user_id'] in data:
                    raise ValueError(f'Duplicate user ID "{line["user_id"]}" found in CSV file')
                # Lastly, we need to add any missing fields
                for k, v in common_fields.items():
                    if k not in line:
                        line[k] = None
                data[line['user_id']] = line
                #print(f'Loaded user: {line}')
        return data

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

    def has_logged_in(self, user):
        #print(f'Checking user: "{user["last_login"]}" against "{self.__NEVER_LOGGED_IN}"')
        return user['last_login'] != self.__NEVER_LOGGED_IN

class StaticAnalysis:
    def __init__(self):
        pass

    def validate(self, source):
        # Check if everyone has an active manager
        for user in source.users.values():
            if user['status'] not in ['active', 'suspended']:
                # Ignore non-active users
                continue

            if user['manager'] is None:
                # This is fine, means this file isn't utilizing managers
                # Continue with other test below
                pass
            elif user['manager'] == '':
                source.add_error(user['user_id'], 'User has no manager')
            elif user['manager'] not in source.managers:
                source.add_error(user['user_id'], f'Manager "{user["manager"]}" not found in user list')
            elif source.managers[user['manager']]['status'] != 'active':
                #print(f'Manager "{source.managers[user["manager"]]}" is not active, but user is')
                source.add_error(user['user_id'], f'Manager "{user["manager"]}" is not active, but user is')

            if not source.has_logged_in(user):
                source.add_warning(user['user_id'], 'User has never logged in')

        # Signal success if there are no errors, warnings or notices
        return not (len(source.errors) > 0 or len(source.warnings) > 0 or len(source.notice) > 0)

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
