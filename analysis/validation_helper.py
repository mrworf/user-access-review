#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from datetime import datetime
import dateutil.parser
import regex

class ValidationHelper:
    """Helper class for data validation functions"""
    
    NEVER_LOGGED_IN = dateutil.parser.parse('1970-01-01T00:00:00Z')

    @staticmethod
    def is_valid_name(value):
        """Check if a value is a valid name
        
        Args:
            value: The value to check
            
        Returns:
            True if the value is a valid name, False otherwise
        """
        if not value:
            return False
        
        # Check if the first character is a letter
        if not value[0].isalpha():
            return False
            
        # Check if all characters are valid
        for char in value:
            if not (char.isalpha() or char.isspace() or char in '-.,\'()0123456789'):
                return False
                
        return True

    @staticmethod
    def has_date_value(value):
        """Check if a datetime value is valid (not NEVER_LOGGED_IN)
        
        Args:
            value: The datetime value to check
            
        Returns:
            True if the value is a valid datetime, False otherwise
        """
        if not isinstance(value, datetime):
            return False
        if value.tzinfo is not None:
            # If value has timezone, copy it to NEVER_LOGGED_IN
            never_logged_in = ValidationHelper.NEVER_LOGGED_IN.replace(tzinfo=value.tzinfo)
        else:
            # If value is naive, use naive NEVER_LOGGED_IN
            never_logged_in = ValidationHelper.NEVER_LOGGED_IN.replace(tzinfo=None)
        return value != never_logged_in

    @staticmethod
    def is_valid_email(value):
        """Check if a value is a valid email address
        
        Args:
            value: The value to check
        """ 
        if not value:
            return False
        return regex.match(r'[^@]+@[^@]+\.[^@]+', value) is not None 