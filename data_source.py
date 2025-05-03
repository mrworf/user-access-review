#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import csv
import yaml
import re
import dateutil.parser
import pytz

from common_fields import common_fields

class DataSource:
    __NEVER_LOGGED_IN = dateutil.parser.parse('1970-01-01T00:00:00Z') # Not the ideal way to handle this, but let's do this for now

    def __init__(self):
        self.name = None
        self.users = None
        self.mapping = None
        self.tz = {tz: pytz.timezone(tz) for tz in pytz.all_timezones}
        
        # Add some missing timezones
        self.tz['EDT'] = self.tz['EST']

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
                            if src is None and line[k] == '':
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
        return user['last_login'] != self.__NEVER_LOGGED_IN 

    def save(self, file_path):
        with open(file_path, 'w') as file:
            writer = csv.DictWriter(file, fieldnames=common_fields.keys())
            writer.writeheader()
            writer.writerows(self.users.values())