#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from datetime import datetime

import regex
from findings import FindingType

class StaticAnalysis:
    def __init__(self):
        pass

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
                    source.add_finding(user['user_id'], FindingType.MISSING_EMAIL)
                elif not regex.match(r'[^@]+@[^@]+\.[^@]+', user['email']):
                    source.add_finding(user['user_id'], FindingType.INVALID_EMAIL, email=user['email'])

            # Check name
            if source.has_field('first_name'):
                if user['first_name'] == None or user['first_name'] == '':
                    source.add_finding(user['user_id'], FindingType.MISSING_FIRST_NAME)
                elif not regex.match(r'^\p{L}[\p{L}\s\-\.\,\'\(\)0-9]*$', user['first_name']):
                    source.add_finding(user['user_id'], FindingType.INVALID_FIRST_NAME, name=user['first_name'])
            if source.has_field('last_name'):
                if user['last_name'] == None or user['last_name'] == '':
                    source.add_finding(user['user_id'], FindingType.MISSING_LAST_NAME)
                elif not regex.match(r'^\p{L}[\p{L}\s\-\.\,\'\(\)0-9]*$', user['last_name']):
                    source.add_finding(user['user_id'], FindingType.INVALID_LAST_NAME, name=user['last_name'])

            # Check manager
            if source.has_field('manager'):
                if user['manager'] == '':
                    source.add_finding(user['user_id'], FindingType.MISSING_MANAGER)
                elif user['manager'] not in source.users:
                    source.add_finding(user['user_id'], FindingType.INVALID_MANAGER, manager=user['manager'])
                elif not source.has_logged_in(source.users[user['manager']]) and source.has_logged_in(user):
                    source.add_finding(user['user_id'], FindingType.INACTIVE_MANAGER, manager=user['manager'])
            
            # Check last login
            if not source.has_logged_in(user):
                if source.has_field('created_date'):
                    age = (datetime.now() - user['created_date']).days
                    source.add_finding(user['user_id'], FindingType.NEVER_LOGGED_IN_AGED, age=age)
                else:
                    source.add_finding(user['user_id'], FindingType.NEVER_LOGGED_IN)

            # Check privileged
            if source.has_field('privileged'):
                if user['privileged']:
                    source.add_finding(user['user_id'], FindingType.IS_PRIVILEGED)

        # Signal success if there are no findings
        return not source.has_findings()