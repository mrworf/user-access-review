# User Access Review Tool

A tool for analyzing and comparing user access data across different sources. It helps identify discrepancies, validate user information, and generate comprehensive reports.

This is a very common requirement for PCI-DSS and SOC2 audits, but it's also a good security practice since SAML and SCIM aren't always implemented, available or fully functional.

Relying on manual review is also a risk factor, since it's slow and prone to errors.

This tool aims to solve this a generic fashion. While there are many commercial offerings out there, all of them focus on UI/UX and deep integration with various vendors. Which will never be enough since there's too many vendors. The approach taken by this tool is instead to allow you to use CSV files and then map them so you can do an apples to apples comparison.

It uses configuration files to minimize overhead, meaning that once a source has been configured, you often only need to grab new CSV files. And an enterprising admin could easily script that part to further automate their process.

**Note, some of the capabilities are under active development and may not yet be working**

## Configuration Files

### Main Configuration (`config.yml`)

The main configuration file defines the source of truth, comparison files, and output settings.

```yaml
# Source of truth configuration
truth:
  name: "HR System"                    # Optional: Human-readable name for the source
  source: "data/hr_system.csv"         # CSV file containing the source of truth
  map: "mappings/hr_system.yml"        # Mapping file for source CSV
  rules: "rules/hr_system.yml"         # Optional: specific rules for source

# Comparison configurations
comparisons:
  - name: "Google Workspace"           # Optional: Human-readable name for the comparison
    source: "data/google.csv"          # CSV file to compare against source
    map: "mappings/google.yml"         # Mapping file for comparison CSV
    rules: "rules/google.yml"          # Optional: specific rules for this comparison
  - name: "Okta"
    source: "data/okta.csv"
    map: "mappings/okta.yml"

# List approved email domains
# If a user's email domain is not in this list, they will be
# flagged as an invalid email address
domains:
  - example.com
  - example.org

# Output file prefix
output: "access_review"

# Global rules file
rules: "rules/global.yml"

# Global options
# List findings here to disable them on a global level
# You can also put this on a per-comparison basis
disable:
  - MANAGER_MISSING
  - TITLE_MISMATCH
```

The configuration file supports the following sections:

1. **Truth Source** (Required)
   - `name`: Optional human-readable name (defaults to source filename)
   - `source`: Path to the source of truth CSV file
   - `map`: Path to the mapping configuration file
   - `rules`: Optional path to specific rules for the source _(not yet implemented)_

2. **Comparisons** (Optional)
   - List of comparison sources to validate against the source of truth
   - Each comparison requires:
     - `source`: Path to the comparison CSV file
     - `map`: Path to the mapping configuration file
   - Optional fields:
     - `name`: Human-readable name (defaults to source filename)
     - `rules`: Path to specific rules for this comparison _(not yet implemented)_

3. **Domains** (Optional)
   - List of approved email domains
   - Users with email addresses from unapproved domains will be flagged

4. **Output** (Optional)
   - `prefix`: Prefix for all output files (defaults to "output")

5. **Rules** (Optional)
   - Path to the global rules file

6. **Disable** (Optional)
   - List of finding codes to disable globally
   - Can be used to suppress specific types of findings

### Mapping Configuration (`*.yml`)

Mapping files define how CSV fields map to standardized field names. They support both direct field mapping and advanced features like regex patterns and inheritance.

```yaml
# Optional: Inherit mappings from another file
inherit: "base_mapping.yml"

mapping:
  # Direct field mapping
  user_id: "email"              # Maps CSV column "email" to "user_id"
  email: "email"                # Maps CSV column "email" to "email"
  first_name: "User name"       # Maps CSV column "User name" to "first_name"
  last_name: "User name"        # Maps CSV column "User name" to "last_name"
  status: "User status"         # Maps CSV column "User status" to "status"
  created_date: "Added to org"  # Maps CSV column "Added to org" to "created_date"
  privileged: "Group membership" # Maps CSV column "Group membership" to "privileged"

# Optional field value rewrites
rewrite:
  first_name:
    "\1": "(^[^ ]+)"           # Extracts first word as first name
  last_name:
    "\2": "(^[^ ]+) +(.*)"     # Extracts everything after first word as last name
  status:
    "active": "Active"         # Exact match rewrite
    "inactive": "Deactivated"
    "suspended": "Suspended"
  last_login:
    "1/1/1970": "Never accessed"  # Special case handling
  privileged:
    "true": ".*admin.*"        # Regex match for admin groups
    "false": "^(?!.*admin).*$" # Regex match for non-admin groups
```

The mapping configuration supports several features:

1. **File Inheritance**
   - Use `inherit` to include mappings from another YAML file
   - Child mappings override inherited mappings
   - Useful for sharing common mappings across multiple systems

2. **Direct Field Mapping**
   - Maps CSV column names directly to standardized field names
   - Example: `user_id: "email"`

3. **Field Value Rewrites**
   - Transforms field values after mapping
   - Supports several types of rewrites:
     - **Regex Capture Groups**: Use `\1`, `\2`, etc. to reference captured groups
       ```yaml
       first_name:
         "\1": "(^[^ ]+)"  # Captures first word
       last_name:
         "\2": "(^[^ ]+) +(.*)"  # Captures everything after first word
       ```
     - **Exact Matches**: Simple string replacement
       ```yaml
       status:
         "active": "Active"
       ```
     - **Regex Patterns**: Use regex to match and transform values
       ```yaml
       privileged:
         "true": ".*admin.*"  # Any group containing "admin"
       ```
     - **Special Cases**: Handle specific values
       ```yaml
       last_login:
         "1/1/1970": "Never accessed"
       ```
   - Rewrites are evaluated in order, first match wins
   - Empty values can be handled with `"": "default_value"`
   - Dates are special, if you need to indicate that no date is available, replace it with `1/1/1970` which will be interpreted as never.

4. **Value Conformance**
   - Values are automatically conformed to the expected type:
     - Dates are parsed and normalized
     - Names are case-folded
     - Booleans are normalized to true/false
     - Empty values are handled appropriately
   - Invalid values will raise an error

The mapping system is designed to handle the common case where different systems use different field names and value formats. The inheritance feature allows you to create base mappings that can be reused across multiple systems, while the rewrite system helps standardize values across different formats.

### Supported Fields

The tool expects the following standardized fields in your CSV files. Use the mapping configuration to map your CSV columns to these fields:

| Field Name | Type | Description | Validation Rules |
|------------|------|-------------|------------------|
| `user_id` | String | Unique identifier for the user | Required, must be unique |
| `email` | Email | User's email address | Optional, must be valid email format |
| `first_name` | Name | User's first name | Optional, must match pattern `[A-Za-z\- ]+` |
| `last_name` | Name | User's last name | Optional, must match pattern `[A-Za-z\- ]+` |
| `department` | String | User's department | Optional |
| `role` | String | User's role | Optional |
| `title` | String | User's job title | Optional |
| `manager` | Email | Manager's email address | Optional, must be valid email format |
| `location` | String | User's physical location | Optional |
| `last_login` | Date | User's last login timestamp | Optional, must be valid ISO 8601 date |
| `created_date` | Date | User's account creation date | Optional, must be valid ISO 8601 date |
| `end_date` | Date | User's termination/end date | Optional, must be valid ISO 8601 date |
| `status` | Enum | User's account status | Optional, Must be one of: active, inactive, suspended, deleted, unknown |
| `type` | Enum | User's employment type | Optional, Must be one of: employee, contractor, intern, vendor, unknown |
| `two_factor` | Boolean | Whether 2FA is enabled | Optional, Must be true/false, yes/no, or 1/0 |
| `user_type` | Enum | Detailed user type | Optional, Must be one of: fte, part-time, contractor, vendor, intern, service, unknown |
| `privileged` | Boolean | Whether user has privileged access | Optional, Must be true/false, yes/no, or 1/0 |

#### Field Types

1. **String** (`str`)
   - Alphanumeric text
   - No specific format restrictions
   - Case-sensitive

2. **Email** (`email`)
   - Must be valid email format
   - Case-insensitive
   - Examples:
     - `user@example.com`
     - `first.last@company.org`

3. **Name** (`name`)
   - Must contain only letters, spaces, and hyphens
   - Case-sensitive
   - Examples:
     - `John`
     - `Smith`
     - `O'Brien`

4. **Date** (`date`)
   - ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)
   - Supports timezone information
   - Examples:
     - `2024-01-01T00:00:00Z`
     - `2024-01-01T00:00:00-05:00`
   - Special value `1/1/1970` indicates "never" (e.g., never logged in)

5. **Boolean** (`bool`)
   - Accepts multiple formats:
     - `true`/`false`
     - `yes`/`no`
     - `1`/`0`
   - Case-insensitive
   - Automatically normalized to `true`/`false`

6. **Enum**
   - Must match one of the predefined values exactly
   - Case-sensitive
   - No partial matches allowed
   - Supported enums:
     - `status`: active, inactive, suspended, deleted, unknown
     - `type`: employee, contractor, intern, vendor, unknown
     - `user_type`: fte, part-time, contractor, vendor, intern, service, unknown

#### Field Validation

The tool performs the following validations:

1. **Required Fields**
   - `user_id` must be present

2. **Format Validation**
   - Email addresses must match standard email format
   - Names must contain only letters, spaces, and hyphens
   - Dates should be valid ISO 8601 format, but will make valiant attempt to parse most types, with or without timezones
   - Boolean values must be in supported formats
   - Enum values must match predefined options exactly

3. **Relationship Validation**
   - Manager emails must be valid email addresses

### Rules Configuration (`rules.yml`)

Rules files define validation rules and exceptions for comparisons. The rules file has two main sections: `comparison` for exceptions and `validation` for validation rules.

```yaml
comparison:
  exceptions:
    - field: user_id                    # Field to check for exception
      pattern: ^admin[^@]+@[^.]+\.com$  # Regex pattern for exception
      reason: Admin accounts are typically google groups, not individual users  # Reason for exception
      only:                             # Optional: only apply to specific systems
        - hubspot
      skip:                             # Optional: skip specific systems
        - something

validation:
  rules:
    - name: NO_LOGIN_IN_90_DAYS         # Unique name for the rule
      reason: Has not logged in for 90 days ({value} days ago)  # Description of the rule
      severity: COMPLIANCE              # Severity level (COMPLIANCE, ERROR, WARNING, NOTICE)
      field: last_login                 # Field to validate
      operation: days_since             # Operation to perform
      trigger: greater_than             # Condition to trigger the rule
      value: 90                         # Value to compare against
      skip-empty: true                  # Optional: skip validation if field is empty
```

The rules file supports two types of configurations:

1. **Comparison Exceptions**
   - Define exceptions for specific fields in comparison data
   - Can be scoped to specific systems using `only` and `skip`
   - Uses regex patterns to match field values
   - Requires a reason for documentation

2. **Validation Rules**
   - Define custom validation rules for fields
   - Can specify severity level
   - Support various operations and triggers
   - Can be configured to skip empty values
   - Use template variables in reason messages

You can define these rules at two levels:
- Global (using the top-level `rules` keyword in the config)
- Per comparison source (not yet implemented)

A comparison rule will always be evaluated FIRST before the global rule is evaluated.

### Custom validation

Custom validation rules allow you to define specific checks for your data. These rules can be used to enforce business requirements, compliance needs, or security policies.

Example:
```yaml
validation:
  rules:
    - name: NO_LOGIN_IN_90_DAYS
      reason: Has not logged in for 90 days ({value} days ago)
      severity: COMPLIANCE
      field: last_login
      operation: days_since
      trigger: greater_than
      value: 90
      skip-empty: true  # Skip validation if last_login is empty
```

Each validation rule consists of the following components:

1. **Basic Information**
   - `name`: Unique identifier for the rule (required)
   - `reason`: Description of the rule, can include template variables like `{value}` (required)
   - `severity`: Level of the finding (required)
     - `COMPLIANCE`: Critical compliance issues
     - `ERROR`: Critical issues requiring immediate attention
     - `WARNING`: Issues that should be reviewed
     - `NOTICE`: Informational findings

2. **Field Configuration**
   - `field`: The field to validate (required)
   - `skip-empty`: Whether to skip validation if the field is empty (optional, default: false)
     - Handles empty strings, zero values, false booleans, empty lists/dicts, None values
     - Useful for optional fields where empty values are acceptable

3. **Validation Logic**
   - `operation`: The operation to perform on the field value (required)
   - `trigger`: The condition that triggers the rule (required)
   - `value`: The value to compare against (required for most triggers)

You can define these rules at two levels:
- Global (using the top-level `rules` keyword in the config)
- Per comparison source (not yet implemented)

A comparison rule will always be evaluated FIRST before the global rule is evaluated.

#### Operations

The validation rules support various operations and triggers for comparing values. Here are all supported operations:

#### Value Operations
- `days_since`: Calculates the number of days between the current date and the field value (for date fields)

#### Comparison Triggers
1. **Numeric Comparisons**
   - `greater_than`: Value is greater than the specified value
   - `less_than`: Value is less than the specified value
   - `equal_to`: Value equals the specified value
   - `not_equal_to`: Value does not equal the specified value

2. **String Comparisons**
   - `equal_to_case`: String equals the specified value (case-insensitive)
   - `not_equal_to_case`: String does not equal the specified value (case-insensitive)
   - `contains`: String contains the specified value (case-insensitive)
   - `not_contains`: String does not contain the specified value (case-insensitive)
   - `starts_with`: String starts with the specified value
   - `ends_with`: String ends with the specified value
   - `starts_with_case`: String starts with the specified value (case-insensitive)
   - `ends_with_case`: String ends with the specified value (case-insensitive)

3. **Pattern Matching**
   - `matches`: Value matches the specified regex pattern
   - `not_matches`: Value does not match the specified regex pattern

4. **List Operations**
   - `in`: Value is in the specified list of values
   - `not_in`: Value is not in the specified list of values

5. **Boolean Operations**
   - `is_true`: Value is True
   - `is_false`: Value is False
   - `is_none`: Value is None
   - `is_not_none`: Value is not None

## Output Files

The tool generates several output files:

1. `{prefix}_baseline.csv`
   - Contains the source of truth data with standardized field names
   - Used as a reference for all comparisons

2. `{prefix}_{system_name}_baseline.csv`
   - Contains the comparison data with standardized field names
   - One file per comparison system

3. `{prefix}_findings.csv`
   - Comprehensive report of all findings
   - Includes findings from both static and dynamic analysis
   - Organized by user and severity level
   - Grouped by the source

4. `{prefix}_receipt.txt`
   - Audit trail of the tool's execution
   - Contains:
     - Timestamp and timezone of execution
     - User who ran the tool
     - System information (hostname, IP address)
     - Git information (if in a git repository)
     - List of processed files with:
       - File path
       - Description
       - File size
       - Last modified timestamp
       - SHA256 hash
   - Used for compliance and audit purposes
   - Helps track which files were used in the analysis

# Current capabilities

- Detects users not in source of truth
- Detects managers who are not in the source of truth
- Detects disabled managers with employees
- Can make exceptions based on global rules

All other capabilities listed below are not yet implemented.

# Findings Categories

Findings are categorized by severity:

1. **Compliance** (Critical compliance issues)
   - Access Issues
     - `ACCESS_PRIVILEGED`: User has privileged access

2. **Errors** (Critical issues requiring immediate attention)
   - Access Issues
     - `ACCESS_INVALID`: Invalid access
     - `ACCESS_MISSING`: No access
   - Department Issues
     - `DEPT_INVALID`: Invalid or unexpected department
     - `DEPT_MISSING`: Missing department
   - Email Issues
     - `EMAIL_MISSING`: Email address is missing
     - `EMAIL_INVALID`: Email address is invalid
     - `DOMAIN_INVALID`: Email domain is not in allowed list
     - `DOMAIN_MISMATCH`: Email domain does not match between sources
     - `EMAIL_MISMATCH`: Email does not match between sources
   - Name Issues
     - `FIRST_NAME_MISSING`: First name is missing
     - `FIRST_NAME_INVALID`: First name is invalid
     - `LAST_NAME_MISSING`: Last name is missing
     - `LAST_NAME_INVALID`: Last name is invalid
   - Manager Issues
     - `MANAGER_INVALID`: Manager does not exist
     - `MANAGER_INACTIVE`: Manager is not active, but user is
   - Source of Truth Issues
     - `SOURCE_MISSING`: User not found in source of truth
     - `SOURCE_MISSING_ACTIVE`: Active user not found in source of truth
     - `SOURCE_MISSING_INACTIVE`: Inactive user not found in source of truth
     - `SOURCE_MISSING_SUSPENDED`: Suspended user not found in source of truth
     - `SOURCE_MISSING_DELETED`: Deleted user not found in source of truth
     - `SOURCE_MISSING_UNKNOWN`: User with unknown status not found in source of truth
     - `STATUS_MISMATCH`: User status differs between source and comparison
     - `COMPARE_MISSING`: User does not exist in the comparison data

3. **Warnings** (Issues that should be reviewed)
   - Access Issues
     - `ACCESS_EXTRA`: Has access in comparison that is not in source of truth
   - Department Issues
     - `DEPT_MISMATCH`: Department differs between source and comparison
   - Login Issues
     - `LOGIN_NEVER`: User has never logged in
     - `LOGIN_NEVER_AGED`: User has never logged in and account is aged
   - Manager Issues
     - `MANAGER_MISSING`: Manager is missing
   - Name Mismatches
     - `FIRST_NAME_MISMATCH`: First name differs between source and comparison
     - `LAST_NAME_MISMATCH`: Last name differs between source and comparison
   - Title Issues
     - `TITLE_MISMATCH`: Title differs between source and comparison
     - `TITLE_INVALID`: Invalid title
     - `TITLE_MISSING`: No title

4. **Notices** (Informational findings)
   - `DOCUMENTED_EXCEPTION`: A documented exception exists for this finding

## Usage

1. Create configuration files:
   - Main configuration (`config.yml`)
   - Mapping files for each data source
   - Rules files (optional)

2. Run the tool:
   ```bash
   python main.py config.yml
   ```

3. Review the generated reports:
   - Check `{prefix}_findings.csv` for all identified issues
   - Review baseline files to verify data standardization
   - Address findings based on severity

## Requirements

- Python 3.6+
- python-dateutil
- PyYAML
- regex
- gitpython

## License

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version. 