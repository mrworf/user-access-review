#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from datetime import datetime
import os
import csv
import yaml
import regex
import dateutil.parser
import pytz

from config.common_fields import common_fields, default_values
from .findings import Finding, Severity
from analysis.validation_helper import ValidationHelper

class DataSource:
    def __init__(self, config):
        self.name = None
        self.users = {}
        self.mapping = None
        self.tz = {tz: pytz.timezone(tz) for tz in pytz.all_timezones}
        
        # Add some missing timezones
        self.tz['EDT'] = self.tz['EST']
        self.findings = {}  # Single array for all findings, keyed by user_id

        self.config = config

    def load(self, csv_file, yaml_file):
        config = self.load_yaml(yaml_file)
        self.mapping = config.get('mapping', {})
        self.rewrite = config.get('rewrite', {})
        self.options = config.get('options', {})
        self.name = os.path.splitext(os.path.basename(yaml_file))[0]

        if len(self.mapping) == 0:
            raise ValueError(f'No mapping found in {yaml_file}')

        self.users = self.load_csv(csv_file, skip_first_rows=self.options.get('skip_first_rows', 0), skip_last_rows=self.options.get('skip_last_rows', 0))

        self.managers = {}
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
        elif common_fields[field] == 'date':
            if value is None or value == '':
                value = ValidationHelper.NEVER_LOGGED_IN
            try:
                # Try to parse the date and time, preserving original timezone
                if isinstance(value, datetime):
                    value = value
                else:
                    value = dateutil.parser.parse(value, tzinfos=self.tz)
            except ValueError:
                raise ValueError(f'Value "{value}" is not a valid date for field "{field}"')
        elif common_fields[field] == 'name':
            if value is not None:
                value = value.casefold()
        elif common_fields[field] == 'bool':
            if value is None:
                value = ''
            if value.lower() in ['true', 'false']:
                value = value.lower() == 'true'
            elif value.lower() in ['yes', 'no']:
                value = value.lower() == 'yes'
            elif value.lower() in ['1', '0']:
                value = value.lower() == '1'
            else:
                raise ValueError(f'Value "{value}" is not a valid boolean for field "{field}"')
        else:
            if value is None:
                value = ''
        return value

    def load_csv(self, file_path, skip_first_rows=0, skip_last_rows=0):
        try:
            # First read all lines to handle skipping
            with open(file_path, mode='r') as file:
                lines = file.readlines()
                
            # Skip first and last rows if specified
            if skip_first_rows > 0:
                lines = lines[skip_first_rows:]
            if skip_last_rows > 0:
                lines = lines[:-skip_last_rows]
                
            # Create a CSV reader from the filtered lines
            csv_reader = csv.DictReader([line.encode('utf-8').decode('utf-8-sig') for line in lines])

            # Check if any fields are regex fields, if so, replace with the matching field.
            # Note tha this will use the first field that matches.
            for k, v in self.mapping.items():
                # Loop through all fields in the row
                for field in csv_reader.fieldnames:
                    if regex.match(v, field):
                        self.mapping[k] = field
                        break

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
                            match = regex.match(src, line[k])
                            if match:
                                line[k] = match.expand(dst)
                                break
                    # Conform the value to the expected type
                    line[k] = self.conform(line[k], k)
                if line['user_id'] in data:
                    raise ValueError(f'Duplicate user ID "{line["user_id"]}" found in CSV file')

                # Ensure default values are set for missing fields
                for k, v in default_values.items():
                    if k not in line:
                        line[k] = v

                # Lastly, we need to add any missing fields
                for k, v in common_fields.items():
                    if k not in line:
                        line[k] = None
                
                data[line['user_id']] = line
            return data
        except Exception as e:
            raise ValueError(f'Error loading CSV file "{file_path}": {e}')

    def load_yaml(self, file_path):
        # Load YAML data without converting 'yes' and 'no' to booleans
        def no_bool_constructor(loader, node):
            return loader.construct_scalar(node)
        yaml.SafeLoader.add_constructor('tag:yaml.org,2002:bool', no_bool_constructor)

        if not file_path or not os.path.exists(file_path):
            raise ValueError(f'File "{file_path}" does not exist')
        data = {}
        try:
            with open(file_path, 'r') as file:
                data = yaml.safe_load(file)
        except Exception as e:
            raise ValueError(f'Error loading YAML file "{file_path}": {e}')
        
        # Check if this depends on another mapping file
        if 'inherit' in data:
            base = self.load_yaml(os.path.join(os.path.dirname(file_path), data['inherit']))
            # Remove inherit key before merging
            del data['inherit']
            # Deep merge base and data
            data = self._deep_merge(base, data)
        return data

    def _deep_merge(self, base, override):
        """Deep merge two dictionaries, with override taking precedence
        
        Args:
            base: Base dictionary
            override: Dictionary with overrides
            
        Returns:
            Merged dictionary
        """
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
    
    def add_finding(self, user_id: str, finding: Finding, **kwargs):
        """Add a finding (error, warning, or notice) for a user
        
        Args:
            user_id: The user ID
            finding: The Finding object
            **kwargs: Parameters to format into the finding description
        """
        if finding.key in self.config.disable:
            return
        
        if user_id not in self.findings:
            self.findings[user_id] = []
        self.findings[user_id].append(finding(**kwargs))
    
    def get_findings_by_severity(self, severity: Severity):
        """Get all findings of a specific severity
        
        Args:
            severity: The severity level to filter by
            
        Returns:
            Dictionary of user_id to list of findings with the specified severity
        """
        result = {}
        for user_id, findings in self.findings.items():
            user_findings = [f for f in findings if f.severity == severity]
            if user_findings:
                result[user_id] = user_findings
        return result
    
    def has_findings(self):
        """Check if there are any findings
        
        Returns:
            True if there are any findings, False otherwise
        """
        return len(self.findings) > 0
    
    def has_errors(self):
        """Check if there are any error-level findings
        
        Returns:
            True if there are any errors, False otherwise
        """
        return len(self.get_findings_by_severity(Severity.ERROR)) > 0
    
    def has_warnings(self):
        """Check if there are any warning-level findings
        
        Returns:
            True if there are any warnings, False otherwise
        """
        return len(self.get_findings_by_severity(Severity.WARNING)) > 0
    
    def has_notices(self):
        """Check if there are any notice-level findings
        
        Returns:
            True if there are any notices, False otherwise
        """
        return len(self.get_findings_by_severity(Severity.NOTICE)) > 0

    def has_logged_in(self, user):
        if not self.has_field('last_login'):
            return True # No last login field, so we can't check
        if not ValidationHelper.has_date_value(user['last_login']):
            return False
        return True

    def has_field(self, field):
        return field in self.mapping

    def save(self, file_path, append=False):
        with open(file_path, 'a' if append else 'w') as file:
            writer = csv.DictWriter(file, fieldnames=['source'] + list(common_fields.keys()))
            if not append:
                writer.writeheader()
            for user in self.users.values():
                row = {'source': self.name}
                row.update(user)
                writer.writerow(row)