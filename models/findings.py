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
    
    # Access related findings
    ACCESS_EXTRA = Finding("ACCESS_EXTRA", "Has access in comparison that is not in source of truth ({access})", Severity.WARNING)
    ACCESS_INVALID = Finding("ACCESS_INVALID", 'Invalid access: "{access}"', Severity.ERROR)
    ACCESS_MISSING = Finding("ACCESS_MISSING", "No access", Severity.ERROR)
    ACCESS_PRIVILEGED = Finding("ACCESS_PRIVILEGED", "Privileged access", Severity.COMPLIANCE)

    # Department related findings
    DEPT_INVALID = Finding("DEPT_INVALID", 'Invalid or unexpected department: "{department}"', Severity.ERROR)
    DEPT_MISMATCH = Finding('DEPT_MISMATCH', 'Department does not match between sources (source: "{source_dept}", compare: "{compare_dept}")', Severity.WARNING)
    DEPT_MISSING = Finding("DEPT_MISSING", "Missing department", Severity.ERROR)

    # Email related findings
    DOMAIN_INVALID = Finding("DOMAIN_INVALID", 'Email domain is not approved (domain: "{domain}")', Severity.ERROR)
    DOMAIN_MISMATCH = Finding("DOMAIN_MISMATCH", 'Email domain does not match (source "{domain}", compare: "{compare_domain}")', Severity.ERROR)
    EMAIL_INVALID = Finding("EMAIL_INVALID", "Invalid email address: {email}", Severity.ERROR)
    EMAIL_MISMATCH = Finding("EMAIL_MISMATCH", 'Email does not match between sources (source: "{source_email}", compare: "{compare_email}")', Severity.ERROR)
    EMAIL_MISSING = Finding("EMAIL_MISSING", "No email address", Severity.ERROR)

    # Exception related findings
    DOCUMENTED_EXCEPTION = Finding("DOCUMENTED_EXCEPTION", "{reason}", Severity.NOTICE)

    # Login related findings
    LOGIN_NEVER = Finding("LOGIN_NEVER", "Never logged in", Severity.WARNING)
    LOGIN_NEVER_AGED = Finding("LOGIN_NEVER_AGED", "User has never logged in and is {age} days old", Severity.WARNING)

    LOCATION_INVALID = Finding("LOCATION_INVALID", 'Invalid location: "{location}"', Severity.ERROR)
    LOCATION_MISMATCH = Finding("LOCATION_MISMATCH", 'Location does not match between sources (source: "{source_location}", compare: "{compare_location}")', Severity.WARNING)
    LOCATION_MISSING = Finding("LOCATION_MISSING", "No location", Severity.ERROR)

    # Manager related findings
    MANAGER_INACTIVE = Finding("MANAGER_INACTIVE", 'Manager "{manager}" is not active, but user is', Severity.ERROR)
    MANAGER_INVALID = Finding("MANAGER_INVALID", 'Manager "{manager}" not found in user list', Severity.ERROR)
    MANAGER_MISSING = Finding("MANAGER_MISSING", "No manager", Severity.WARNING)

    # Name related findings
    FIRST_NAME_INVALID = Finding("FIRST_NAME_INVALID", 'Invalid first name: "{name}"', Severity.ERROR)
    FIRST_NAME_MISMATCH = Finding("FIRST_NAME_MISMATCH", 'First name does not match between sources (source: "{source_name}", compare: "{compare_name}")', Severity.WARNING)
    FIRST_NAME_MISSING = Finding("FIRST_NAME_MISSING", "No first name found", Severity.ERROR)
    LAST_NAME_INVALID = Finding("LAST_NAME_INVALID", 'Invalid last name: "{name}"', Severity.ERROR)
    LAST_NAME_MISMATCH = Finding("LAST_NAME_MISMATCH", 'Last name does not match between sources (source: "{source_name}", compare: "{compare_name}")', Severity.WARNING)
    LAST_NAME_MISSING = Finding("LAST_NAME_MISSING", "No last name found", Severity.ERROR)

    # Source of truth related findings
    COMPARE_MISSING = Finding("COMPARE_MISSING", "Does not exist in the comparison data", Severity.ERROR)
    SOURCE_MISSING = Finding("SOURCE_MISSING", "Not found in source of truth", Severity.ERROR)
    SOURCE_MISSING_ACTIVE = Finding("SOURCE_MISSING_ACTIVE", "Not found in source of truth and is active", Severity.ERROR)
    SOURCE_MISSING_DELETED = Finding("SOURCE_MISSING_DELETED", "Not found in source of truth and is deleted", Severity.ERROR)
    SOURCE_MISSING_INACTIVE = Finding("SOURCE_MISSING_INACTIVE", "Not found in source of truth and is inactive", Severity.ERROR)
    SOURCE_MISSING_SUSPENDED = Finding("SOURCE_MISSING_SUSPENDED", "Not found in source of truth and is suspended", Severity.ERROR)
    SOURCE_MISSING_DEACTIVATED = Finding("SOURCE_MISSING_DEACTIVATED", "Not found in source of truth and is deactivated", Severity.ERROR) 
    SOURCE_MISSING_UNKNOWN = Finding("SOURCE_MISSING_UNKNOWN", "Not found in source of truth and status is unknown", Severity.ERROR)
    COMPARE_ACTIVE_SOURCE_DEACTIVATED = Finding("COMPARE_ACTIVE_SOURCE_DEACTIVATED", "Source is deactivated but compare is active", Severity.ERROR)
    COMPARE_ACTIVE_SOURCE_INACTIVE = Finding("COMPARE_ACTIVE_SOURCE_INACTIVE", "Source is inactive but compare is active", Severity.ERROR)
    COMPARE_ACTIVE_SOURCE_SUSPENDED = Finding("COMPARE_ACTIVE_SOURCE_SUSPENDED", "Source is suspended but compare is active", Severity.ERROR)
    COMPARE_ACTIVE_SOURCE_DELETED = Finding("COMPARE_ACTIVE_SOURCE_DELETED", "Source is deleted but compare is active", Severity.ERROR)
    COMPARE_ACTIVE_SOURCE_UNKNOWN = Finding("COMPARE_ACTIVE_SOURCE_UNKNOWN", "Source is unknown but compare is active", Severity.ERROR)
    STATUS_MISMATCH = Finding("STATUS_MISMATCH", 'Status does not match between sources (source: "{source_status}", compare: "{compare_status}")', Severity.ERROR)
    STATUS_MATCH = Finding("STATUS_MATCH", 'Status matches between sources (source: "{source_status}", compare: "{compare_status}")', Severity.COMPLIANCE)

    # Title related findings
    TITLE_INVALID = Finding("TITLE_INVALID", "Invalid title: {title}", Severity.WARNING)
    TITLE_MISMATCH = Finding("TITLE_MISMATCH", 'Title does not match between sources (source: "{source_title}", compare: "{compare_title}")', Severity.WARNING)
    TITLE_MISSING = Finding("TITLE_MISSING", "No title", Severity.WARNING)

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