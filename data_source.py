#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import csv
import yaml
import regex
import dateutil.parser
import pytz

from common_fields import common_fields
from findings import Finding, Severity

class DataSource:
    __NEVER_LOGGED_IN = dateutil.parser.parse('1970-01-01T00:00:00Z') # Not the ideal way to handle this, but let's do this for now

    def __init__(self):
        self.name = None
        self.users = {}
        self.mapping = None
        self.tz = {tz: pytz.timezone(tz) for tz in pytz.all_timezones}
        
        # Add some missing timezones
        self.tz['EDT'] = self.tz['EST']
        self.findings = {}  # Single array for all findings, keyed by user_id

    def load(self, csv_file, yaml_file):
        config = self.load_yaml(yaml_file)
        self.mapping = config.get('mapping', {})
        self.rewrite = config.get('rewrite', {})

        self.users = self.load_csv(csv_file)
        self.name = os.path.splitext(os.path.basename(csv_file))[0]

        self.managers = {}
        # Separate out the managers for easier processing
        for user in self.users.values():
            if user['manager'] != '' and user['manager'] not in self.managers:
                mgr = self.users.get(user['manager'])
                if mgr is not None:
                    self.managers[user['manager']] = mgr

    # TODO: Move this to static analysis
    def conform(self, value, field):
        if field not in common_fields:
            raise ValueError(f'Field "{field}" not found in common fields for field "{field}"')
        if isinstance(common_fields[field], list):
            if value not in common_fields[field]:
                raise ValueError(f'Value "{value}" not in allowed values for field "{field}"')

        if common_fields[field] == 'date':
            if value is None:
                value = ''
            try:
                # Try to parse the date and time
                value = dateutil.parser.parse(value, tzinfos=self.tz)
                if value.tzinfo is None:
                    value = value.replace(tzinfo=pytz.UTC)
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

    def load_csv(self, file_path):
        try:
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
                                match = regex.match(src, line[k])
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
        except Exception as e:
            raise ValueError(f'Error loading CSV file "{file_path}": {e}')

    def load_yaml(self, file_path):
        # Load YAML data without converting 'yes' and 'no' to booleans
        def no_bool_constructor(loader, node):
            return loader.construct_scalar(node)
        yaml.SafeLoader.add_constructor('tag:yaml.org,2002:bool', no_bool_constructor)

        if not file_path or not os.path.exists(file_path):
            raise ValueError(f'File "{file_path}" does not exist')
        try:
            with open(file_path, 'r') as file:
                data = yaml.safe_load(file)
            return data
        except Exception as e:
            raise ValueError(f'Error loading YAML file "{file_path}": {e}')
    
    def add_finding(self, user_id: str, finding: Finding, **kwargs):
        """Add a finding (error, warning, or notice) for a user
        
        Args:
            user_id: The user ID
            finding: The Finding object
            **kwargs: Parameters to format into the finding description
        """
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
        return user['last_login'] != self.__NEVER_LOGGED_IN 

    def has_field(self, field):
        return field in self.mapping

    def save(self, file_path):
        with open(file_path, 'w') as file:
            writer = csv.DictWriter(file, fieldnames=common_fields.keys())
            writer.writeheader()
            writer.writerows(self.users.values())