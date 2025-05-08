#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from datetime import datetime, timezone

import regex
from models.findings import FindingType

class StaticAnalysis:
    def __init__(self, config):
        self.config = config

    def validate(self, source):
        """Validate the source data
        
        Args:
            source: The data source to validate
            
        Returns:
            True if the data is valid, False otherwise
        """
        # Check each user
        for user in source.users.values():
            # Check email format
            if source.has_field('email'):
                if user['email'] == None or user['email'] == '':
                    source.add_finding(user['user_id'], FindingType.EMAIL_MISSING)
                elif not regex.match(r'[^@]+@[^@]+\.[^@]+', user['email']):
                    source.add_finding(user['user_id'], FindingType.EMAIL_INVALID, email=user['email'])
                domain = user['email'].split('@')[1]
                if domain not in self.config.domains:
                    source.add_finding(user['user_id'], FindingType.DOMAIN_INVALID, domain=domain)

            # Check name
            if source.has_field('first_name'):
                if user['first_name'] == None or user['first_name'] == '':
                    source.add_finding(user['user_id'], FindingType.FIRST_NAME_MISSING)
                elif not regex.match(r'^\p{L}[\p{L}\s\-\.\,\'\(\)0-9]*$', user['first_name']):
                    source.add_finding(user['user_id'], FindingType.FIRST_NAME_INVALID, name=user['first_name'])
            if source.has_field('last_name'):
                if user['last_name'] == None or user['last_name'] == '':
                    source.add_finding(user['user_id'], FindingType.LAST_NAME_MISSING)
                elif not regex.match(r'^\p{L}[\p{L}\s\-\.\,\'\(\)0-9]*$', user['last_name']):
                    source.add_finding(user['user_id'], FindingType.LAST_NAME_INVALID, name=user['last_name'])

            # Check manager
            if source.has_field('manager'):
                if user['manager'] == '':
                    source.add_finding(user['user_id'], FindingType.MANAGER_MISSING)
                elif user['manager'] not in source.users:
                    source.add_finding(user['user_id'], FindingType.MANAGER_INVALID, manager=user['manager'])
                elif not source.has_logged_in(source.users[user['manager']]) and source.has_logged_in(user):
                    source.add_finding(user['user_id'], FindingType.MANAGER_INACTIVE, manager=user['manager'])
            
            # Check last login
            if not source.has_logged_in(user):
                if source.has_field('created_date'):
                    # Use the same timezone as created_date
                    now = datetime.now(user['created_date'].tzinfo)
                    age = (now - user['created_date']).days
                    source.add_finding(user['user_id'], FindingType.LOGIN_NEVER_AGED, age=age)
                else:
                    source.add_finding(user['user_id'], FindingType.LOGIN_NEVER)

            # Check privileged
            if source.has_field('privileged'):
                if user['privileged']:
                    source.add_finding(user['user_id'], FindingType.ACCESS_PRIVILEGED)

        # Signal success if there are no findings
        return not source.has_findings()