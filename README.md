# Decision Layer - Endpoint Protection Prioritization System

A Python program that analyzes endpoint security data from multiple CSV sources and prioritizes endpoints for protection based on risk assessment.

## Overview

This decision layer system takes 4 CSV input files containing:
- Endpoint metadata and risk scores
- Vulnerability information
- Access frequency logs
- Data sensitivity classifications

It then produces a prioritized list of endpoints requiring protection, ranked by calculated risk scores.

## Features

- **Multi-source analysis**: Combines data from 4 CSV files
- **Weighted scoring**: Balanced algorithm accounting for risk, vulnerabilities, access frequency, and data sensitivity
- **Multiple output formats**: JSON, CSV, and console output
- **Error handling**: Robust exception handling and validation
- **Logging**: Detailed execution logs
- **Unit tested**: Comprehensive test coverage

## Installation

```bash
# No external dependencies required - uses only Python stdlib
python --version  # Python 3.8+
```

## Usage

### Basic Usage

```python
from decision_layer import main

csv_files = {
    'endpoints': 'data/endpoints.csv',
    'vulnerabilities': 'data/vulnerabilities.csv',
    'access_logs': 'data/access_logs.csv',
    'data_sensitivity': 'data/data_sensitivity.csv'
}

# Run analysis and output all formats
protected_endpoints = main(csv_files, output_format='all')
```

### Advanced Usage

```python
from decision_layer import DecisionLayer

# Initialize the decision layer
dl = DecisionLayer()

# Load data
dl.load_endpoints('data/endpoints.csv')
dl.load_vulnerabilities('data/vulnerabilities.csv')
dl.load_access_logs('data/access_logs.csv')
dl.load_data_sensitivity('data/data_sensitivity.csv')

# Analyze and get results
results = dl.analyze()

# Export results
dl.export_json('protected_endpoints.json')
dl.export_csv('protected_endpoints.csv')
```

## CSV File Formats

### endpoints.csv
```
endpoint_id,endpoint_name,risk_score
1,/api/users,6.5
2,/api/admin,8.2
3,/api/data,7.1
```

### vulnerabilities.csv
```
endpoint_id,vulnerability_count
1,2
2,5
3,1
```

### access_logs.csv
```
endpoint_id,access_frequency
1,1250
2,450
3,3200
```

### data_sensitivity.csv
```
endpoint_id,handles_sensitive_data
1,0
2,1
3,1
```

## Priority Algorithm

Priority Score Calculation:

```
Priority = (Risk Score × 0.4) + (Vulnerability Count × 10 × 0.3) + 
           (Access Frequency Normalized × 0.2) + (Sensitive Data × 100 × 0.1)
```

**Weights:**
- Risk Score: 40%
- Vulnerabilities: 30%
- Access Frequency: 20%
- Sensitive Data Handling: 10%

## Output Format

### JSON Output (protected_endpoints.json)
```json
{
  "analysis_date": "2026-05-04",
  "total_endpoints": 10,
  "protected_endpoints": [
    {
      "rank": 1,
      "endpoint_id": 2,
      "endpoint_name": "/api/admin",
      "priority_score": 89.5,
      "risk_score": 8.2,
      "vulnerability_count": 5,
      "access_frequency": 450,
      "handles_sensitive_data": true
    }
  ]
}
```

### CSV Output (protected_endpoints.csv)
```
rank,endpoint_id,endpoint_name,priority_score,risk_score,vulnerability_count,access_frequency,handles_sensitive_data
1,2,/api/admin,89.5,8.2,5,450,true
```

## Testing

```bash
# Run all tests
python -m pytest test_decision_layer.py -v

# Run with coverage
python -m pytest test_decision_layer.py --cov=decision_layer
```

## Example Workflow

1. Prepare 4 CSV files with endpoint data
2. Run: `python decision_layer.py`
3. Review output in `protected_endpoints.json` and `protected_endpoints.csv`
4. Prioritize protection efforts based on the ranked list

## License

MIT
