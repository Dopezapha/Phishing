# Anti-Phishing Smart Contract

## About
The Enhanced Anti-Phishing Smart Contract is a decentralized security system built on the Stacks blockchain that helps protect web users from phishing attacks. It implements a collaborative threat detection and validation mechanism where trusted sentinels can report and validate potentially malicious websites.

## Key Features
- Website registration with security endorsements
- Decentralized threat reporting system
- Sentinel-based validation mechanism
- Risk scoring and threat metrics
- Collateral-backed reporting to prevent abuse
- System-wide protection intensity controls

## Core Components

### 1. Site Registration
Legitimate websites can be registered in the system with security endorsements. Registration requires:
- A unique web identifier
- Security endorsement documentation
- Collateral deposit based on current protection intensity

### 2. Sentinel System
Trusted validators (sentinels) who monitor and validate threat reports:
- Must stake collateral to participate
- Earn credibility based on accurate validations
- Subject to time restrictions between actions
- Performance tracked through precision metrics

### 3. Threat Reporting
Comprehensive threat detection system featuring:
- Detailed threat documentation
- Severity classification
- Multiple confirmation requirements
- Victim impact tracking

## Data Structures

### Primary Maps
1. `registered_sites`: Stores legitimate website information
2. `malicious_site_registry`: Records reported malicious sites
3. `sentinel_performance_log`: Tracks sentinel activity and performance
4. `site_inspection_records`: Maintains site inspection history
5. `sentinel_registry`: Contains sentinel registration and status

## System Constants

```
INACTIVITY_WINDOW: 86400 seconds (24 hours)
BASE_COLLATERAL_REQUIREMENT: 1,000,000 microSTX
TRUSTWORTHINESS_BASELINE: 50
EVIDENCE_STRING_LIMIT: 500 characters
```

## Key Functions

### Administrative Functions
- `initialize_system`: Set up initial system parameters
- `modify_protection_level`: Adjust system-wide security intensity
- `toggle_system_state`: Emergency pause/resume functionality
- `reassign_system_control`: Transfer system control

### Core Operations
1. `register_secure_site`
   - Register legitimate websites
   - Requires collateral deposit
   - Assigns initial security metrics

2. `submit_threat_alert`
   - Report suspicious websites
   - Requires proof documentation
   - Updates sentinel metrics

3. `validate_threat_report`
   - Confirm or reject threat reports
   - Affects site risk scores
   - Updates sentinel credibility

4. `enlist_sentinel`
   - Register as a system validator
   - Requires minimum collateral
   - Initializes performance tracking

### Query Functions
- `fetch_site_status`: Get registered site information
- `check_threat_status`: Verify if a site is marked as malicious
- `fetch_sentinel_rating`: Retrieve sentinel credibility score

## Error Codes
- `ACCESS_FORBIDDEN (u100)`: Unauthorized access attempt
- `DUPLICATE_ENTRY_ERROR (u101)`: Site already registered
- `ENTRY_MISSING_ERROR (u102)`: Referenced entry not found
- `OPERATION_BLOCKED_ERROR (u103)`: System paused or operation restricted
- `COLLATERAL_MISSING_ERROR (u104)`: Insufficient funds for operation
- `TIME_RESTRICTION_ERROR (u105)`: Action attempted too soon
- `LIMIT_BREACH_ERROR (u106)`: Exceeded system limits
- `TEMPORAL_ERROR (u107)`: Time-related operation failure

## Security Mechanisms

### Collateral Requirements
- Base requirement: 1,000,000 microSTX
- Adjustable based on protection intensity
- Required for both site registration and sentinel enrollment

### Time Restrictions
- 24-hour cool-down period between actions
- Prevents rapid-fire false reports
- Enables proper validation periods

### Credibility System
- Baseline trustworthiness threshold: 50
- Incremental scoring based on validated reports
- Performance tracking for accountability

## Best Practices

### For Website Owners
1. Maintain sufficient collateral for registration
2. Provide comprehensive security endorsements
3. Monitor site threat metrics regularly

### For Sentinels
1. Maintain minimum required stake
2. Validate reports thoroughly
3. Respect cool-down periods
4. Document evidence comprehensively

## System Administration
The contract includes emergency controls:
- System pause functionality
- Adjustable protection levels
- Transferable system control
- Configurable validation requirements

## Integration Guidelines
To integrate with the system:
1. Initialize contract interaction
2. Maintain required collateral balances
3. Implement proper error handling
4. Monitor system state changes
5. Follow time restriction guidelines

## Author
Chukwudi Daniel Nwaneri