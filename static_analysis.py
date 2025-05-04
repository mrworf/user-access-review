#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
            # Check manager
            if user['manager'] != None: # Manager is supported by the source
                if user['manager'] == '':
                    source.add_finding(user['user_id'], FindingType.MISSING_MANAGER)
                elif user['manager'] not in source.users:
                    source.add_finding(user['user_id'], FindingType.INVALID_MANAGER, manager=user['manager'])
                elif not source.has_logged_in(source.users[user['manager']]) and source.has_logged_in(user):
                    source.add_finding(user['user_id'], FindingType.INACTIVE_MANAGER, manager=user['manager'])
            
            # Check last login
            if not source.has_logged_in(user):
                source.add_finding(user['user_id'], FindingType.NEVER_LOGGED_IN)

        # Signal success if there are no findings
        return not source.has_findings()