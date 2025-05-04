#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from enum import Enum
import logging

class Severity(Enum):
    """Severity levels for findings"""
    COMPLIANCE = "compliance"
    ERROR = "error"
    WARNING = "warning"
    NOTICE = "notice"
    
    def __str__(self):
        return self.value

class Finding:
    """Represents a single finding type with key, description, and severity"""
    def __init__(self, key: str, description: str, severity: Severity):
        self.key = key
        self._description = description
        self.severity = severity
        self._formatted_message = None
    
    def __call__(self, **kwargs):
        """Create a new Finding instance with the formatted message
        
        Args:
            **kwargs: Parameters to format into the finding description
            
        Returns:
            A new Finding instance with the formatted message
        """
        new_finding = Finding(self.key, self._description, self.severity)
        try:
            new_finding._formatted_message = self._description.format(**kwargs)
        except KeyError as e:
            # Replace missing parameters with '##N/A##'
            logging.exception(f'Missing parameter "{e}" in finding "{self.key}"')
            param_name = str(e).strip("'")
            new_finding._formatted_message = self._description.format(**{**kwargs, param_name: '##N/A##'})
        return new_finding

    @property
    def message(self) -> str:
        """Get the formatted message
        
        Returns:
            The formatted message, or the original description if not formatted
        """
        return self._formatted_message if self._formatted_message else self._description
    
    @property
    def severity_str(self) -> str:
        """Get the severity as a string
        
        Returns:
            The severity as a string
        """
        return str(self.severity)
    
    def description(self, **kwargs):
        """Format the description with the given keyword arguments.
        If a required parameter is missing, it will be replaced with '##N/A##'."""
        try:
            return self.message.format(**kwargs)
        except KeyError as e:
            # Replace missing parameters with '##N/A##'
            param_name = str(e).strip("'")
            return self.message.format(**{**kwargs, param_name: '##N/A##'})

class FindingType:
    """Finding types and their descriptions for user access review"""
    
    # Manager related findings
    MISSING_MANAGER = Finding("MISSING_MANAGER", "User has no manager", Severity.WARNING)
    INVALID_MANAGER = Finding("INVALID_MANAGER", 'Manager "{manager}" not found in user list', Severity.ERROR)
    INACTIVE_MANAGER = Finding("INACTIVE_MANAGER", 'Manager "{manager}" is not active, but user is', Severity.ERROR)
    
    # Source of truth related findings
    NOT_IN_SOURCE = Finding("NOT_IN_SOURCE", "User not found in source of truth", Severity.ERROR)
    NOT_ACTIVE_SOURCE = Finding("NOT_ACTIVE_SOURCE", 'User is "{status}" in source of truth while comparison is "{compare_status}"', Severity.WARNING)
    NEVER_LOGGED_IN = Finding("NEVER_LOGGED_IN", "User has never logged in", Severity.WARNING)
    NEVER_LOGGED_IN_AGED = Finding("NEVER_LOGGED_IN_AGED", "User has never logged in and is {age} days old", Severity.WARNING)
    
    # Comparison related findings
    NOT_IN_COMPARE = Finding("NOT_IN_COMPARE", "User does not exist in the comparison data", Severity.ERROR)
    NOT_ACTIVE_COMPARE = Finding("NOT_ACTIVE_COMPARE", 'User is "{status}" in the comparison data while source is "{source_status}"', Severity.WARNING)
    
    # Identity related findings
    NAME_MISMATCH = Finding("NAME_MISMATCH", 'Name does not match between sources (source: "{source_name}", compare: "{compare_name}")', Severity.WARNING)
    EMAIL_MISMATCH = Finding("EMAIL_MISMATCH", 'Email does not match between sources (source: "{source_email}", compare: "{compare_email}")', Severity.ERROR)
    DOMAIN_MISMATCH = Finding("DOMAIN_MISMATCH", 'Email domain does not match (source "{domain}", compare: "{compare_domain"})', Severity.ERROR)
    MISSING_EMAIL = Finding("MISSING_EMAIL", "No email address", Severity.ERROR)
    INVALID_EMAIL = Finding("INVALID_EMAIL", "Invalid email address: {email}", Severity.ERROR)
    MISSING_FIRST_NAME = Finding("MISSING_FIRST_NAME", "No first name found", Severity.ERROR)
    INVALID_FIRST_NAME = Finding("INVALID_FIRST_NAME", 'Invalid first name: "{name}"', Severity.ERROR)
    MISSING_LAST_NAME = Finding("MISSING_LAST_NAME", "No last name found", Severity.ERROR)
    INVALID_LAST_NAME = Finding("INVALID_LAST_NAME", 'Invalid last name: "{name}"', Severity.ERROR)
    
    # Access related findings
    EXTRA_ACCESS = Finding("EXTRA_ACCESS", "User has access in comparison that is not in source of truth ({access})", Severity.WARNING)
    MISSING_ACCESS = Finding("MISSING_ACCESS", "User has no access", Severity.ERROR)
    INVALID_ACCESS = Finding("INVALID_ACCESS", "User has invalid access: {access}", Severity.ERROR)
    
    # Role related findings
    ROLE_MISMATCH = Finding("ROLE_MISMATCH", "User's role does not match between sources (source: {source_role}, compare: {compare_role})", Severity.WARNING)
    INVALID_ROLE = Finding("INVALID_ROLE", "User has an invalid role: {role}", Severity.ERROR)
    MISSING_ROLE = Finding("MISSING_ROLE", "User has no role", Severity.ERROR)
    
    # Department related findings
    DEPT_MISMATCH = Finding("DEPT_MISMATCH", "User's department does not match between sources (source: {source_dept}, compare: {compare_dept})", Severity.WARNING)
    INVALID_DEPT = Finding("INVALID_DEPT", "User has an invalid or unexpected department ({department})", Severity.ERROR)
    MISSING_DEPARTMENT = Finding("MISSING_DEPARTMENT", "User has no department", Severity.ERROR)
    
    # Exception related findings
    DOCUMENTED_EXCEPTION = Finding("DOCUMENTED_EXCEPTION", "User matches a documented exception rule: {reason}", Severity.NOTICE)
    
    @classmethod
    def get_all_codes(cls) -> list:
        """Get all finding codes
        
        Returns:
            List of all finding codes
        """
        codes = []
        for attr_name in dir(cls):
            if not attr_name.startswith('_'):
                value = getattr(cls, attr_name)
                if isinstance(value, Finding):
                    codes.append(value.key)
        return codes
    
    @classmethod
    def get_all_descriptions(cls) -> dict:
        """Get all finding codes and their descriptions
        
        Returns:
            Dictionary mapping finding codes to descriptions
        """
        descriptions = {}
        for attr_name in dir(cls):
            if not attr_name.startswith('_'):
                value = getattr(cls, attr_name)
                if isinstance(value, Finding):
                    descriptions[value.key] = value.message
        return descriptions 