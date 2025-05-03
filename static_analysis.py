#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
                source.add_error(user['user_id'], f'Manager "{user["manager"]}" is not active, but user is')

            if not source.has_logged_in(user):
                source.add_warning(user['user_id'], 'User has never logged in')

        # Signal success if there are no errors, warnings or notices
        return not (len(source.errors) > 0 or len(source.warnings) > 0 or len(source.notice) > 0) 