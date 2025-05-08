#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Common fields used across the user access review tool.
These fields define the internal data structure that all data sources
must be mapped to.
"""

common_fields = {
    'user_id': 'str',
    'email': 'email',
    'first_name': 'name',
    'last_name': 'name',
    'department': 'str',
    'role': 'str',
    'title': 'str',
    'manager': 'email',
    'location': 'str',
    'last_login': 'date',
    'created_date': 'date',
    'end_date': 'date',
    'status': ['active', 'inactive', 'suspended', 'deactivated','deleted', 'unknown'],
    'type': ['employee', 'contractor', 'intern', 'vendor', 'unknown'],
    'two_factor': 'bool',
    'user_type': ['fte', 'part-time', 'contractor', 'vendor', 'intern', 'service', 'unknown'],
    'privileged': 'bool',
    'sso': 'bool'
} 