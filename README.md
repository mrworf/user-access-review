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
  source: "path/to/source.csv"  # CSV file containing the source of truth
  map: "path/to/source_map.yml" # Mapping file for source CSV

# Comparison configurations
comparisons:
  - name: "system1"             # Human-readable name for the comparison
    source: "path/to/compare1.csv"
    map: "path/to/compare1_map.yml"
    rules: "path/to/rules1.yml" # Optional: specific rules for this comparison
  - name: "system2"
    source: "path/to/compare2.csv"
    map: "path/to/compare2_map.yml"

# Output configuration
output:
  prefix: "user_access_review"  # Prefix for all output files

# Global rules (optional)
rules: "path/to/global_rules.yml"
```

### Mapping Configuration (`*_map.yml`)

Mapping files define how CSV fields map to standardized field names.

```yaml
mapping:
  user_id: "employee_id"        # Maps CSV column "employee_id" to "user_id"
  name: "full_name"
  email: "email_address"
  manager: "supervisor_id"
  department: "org_unit"
  role: "job_title"
  last_login: "last_active"

# Optional field value rewrites
rewrite:
  role:
    "Software Engineer": "SE"   # Rewrites "Software Engineer" to "SE"
    "Product Manager": "PM"
```

Rewrite allows you to conform to the requirements of the supported fields, since it's quite common for various systems to differ quite a bit in how they handle data.

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

#### Field Types

1. **String**
   - Alphanumeric text
   - No specific format restrictions
   - Case-sensitive

2. **Email**
   - Must be valid email format
   - Case-insensitive
   - Examples:
     - `user@example.com`
     - `first.last@company.org`

3. **Name**
   - Must contain only letters, spaces, and hyphens
   - Case-sensitive
   - Examples:
     - `John`
     - `Smith`
     - `O'Brien`

4. **Date**
   - ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)
   - Supports timezone information
   - Examples:
     - `2024-01-01T00:00:00Z`
     - `2024-01-01T00:00:00-05:00`

5. **Boolean**
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

#### Field Validation

The tool performs the following validations:

1. **Required Fields**
   - `user_id` must be present

2. **Format Validation**
   - Email addresses must match standard email format
   - Names must contain only letters, spaces, and hyphens
   - Dates must be valid ISO 8601 format
   - Boolean values must be in supported formats
   - Enum values must match predefined options exactly

3. **Relationship Validation**
   - Manager emails must be valid email addresses


### Rules Configuration (`rules.yml`)

Rules files define validation rules and exceptions for comparisons.

You can define two levels of rules, global (using the top-level `rules` keyword in the config) and per comparison source. A comparison rule will always be evaluated FIRST before the global rule is evaluated.

```yaml
comparison:
  rules:
    - field: "role"             # Field to validate
      pattern: "^[A-Z]{2}$"     # Regex pattern for validation
    - field: "department"
      pattern: "^[A-Z]+$"

  exceptions:
    - field: "user_id"          # Field to check for exception
      pattern: "^admin.*"       # Regex pattern for exception
      reason: "Administrative account"  # Reason for exception
      only: ["system1"]         # Optional: only apply to specific systems
      skip: ["system2"]         # Optional: skip specific systems
```

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

# Current capabilities

- Detects users not in source of truth
- Detects managers who are not in the source of truth
- Detects disabled managers with employees
- Can make exceptions based on global rules

All other capabilities listed below are not yet implemented.

# Findings Categories

Findings are categorized by severity:

1. **Errors** (Critical issues requiring immediate attention)
   - Missing manager
   - Invalid manager
   - Inactive manager
   - Missing email
   - Invalid email
   - Missing name
   - Invalid name
   - Missing role
   - Invalid role
   - Missing department
   - Invalid department
   - Missing access
   - Invalid access

2. **Warnings** (Issues that should be reviewed)
   - Name mismatch
   - Role mismatch
   - Department mismatch
   - Extra access
   - Possible domain mismatch
   - Not active in source
   - Not active in comparison

3. **Notices** (Informational findings)
   - Documented exceptions

## Usage

1. Create configuration files:
   - Main configuration (`config.yml`)
   - Mapping files for each data source
   - Rules files (optional)

2. Run the tool:
   ```bash
   python main.py --config config.yml
   ```

3. Review the generated reports:
   - Check `{prefix}_findings.csv` for all identified issues
   - Review baseline files to verify data standardization
   - Address findings based on severity

## Requirements

- Python 3.6+
- PyYAML
- dateutil
- pytz

## License

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version. 