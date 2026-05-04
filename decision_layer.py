#!/usr/bin/env python3
"""
Decision Layer - Endpoint Protection Prioritization System

This module analyzes endpoint security data from multiple CSV sources and
prioritizes endpoints for protection based on a weighted risk assessment algorithm.

Input: 4 CSV files containing endpoint data, vulnerabilities, access logs, and data sensitivity
Output: Prioritized list of endpoints requiring protection (JSON, CSV, console)
"""

import csv
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class Endpoint:
    """Represents an endpoint with all its security metrics"""
    endpoint_id: int
    endpoint_name: str
    risk_score: float
    vulnerability_count: int = 0
    access_frequency: int = 0
    handles_sensitive_data: bool = False
    priority_score: float = 0.0

    def calculate_priority(self) -> float:
        """
        Calculate priority score using weighted algorithm.

        Priority = (Risk Score × 0.4) + (Vulnerability Count × 10 × 0.3) +
                   (Access Frequency Normalized × 0.2) +
                   (Sensitive Data × 100 × 0.1)

        Returns:
            float: Calculated priority score
        """
        # Normalize access frequency (0-1 scale)
        # Assuming max typical access frequency is 5000
        normalized_access = min(self.access_frequency / 5000, 1.0)

        # Calculate weighted score
        score = (
            (self.risk_score * 0.4) +
            (self.vulnerability_count * 10 * 0.3) +
            (normalized_access * 0.2) +
            (int(self.handles_sensitive_data) * 100 * 0.1)
        )

        self.priority_score = round(score, 2)
        return self.priority_score


class DecisionLayer:
    """Decision layer for analyzing and prioritizing endpoints for protection"""

    def __init__(self):
        """Initialize the decision layer"""
        self.endpoints: Dict[int, Endpoint] = {}
        self.vulnerabilities: Dict[int, int] = {}
        self.access_logs: Dict[int, int] = {}
        self.data_sensitivity: Dict[int, bool] = {}
        logger.info("Decision Layer initialized")

    def load_endpoints(self, filepath: str) -> None:
        """
        Load endpoints data from CSV file.

        Expected columns: endpoint_id, endpoint_name, risk_score

        Args:
            filepath: Path to endpoints CSV file

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If CSV format is invalid
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    endpoint_id = int(row['endpoint_id'])
                    self.endpoints[endpoint_id] = Endpoint(
                        endpoint_id=endpoint_id,
                        endpoint_name=row['endpoint_name'],
                        risk_score=float(row['risk_score'])
                    )
            logger.info(f"Loaded {len(self.endpoints)} endpoints from {filepath}")
        except FileNotFoundError:
            logger.error(f"File not found: {filepath}")
            raise
        except KeyError as e:
            logger.error(f"Invalid CSV format in {filepath}: missing column {e}")
            raise ValueError(f"Missing required column: {e}")

    def load_vulnerabilities(self, filepath: str) -> None:
        """
        Load vulnerability counts from CSV file.

        Expected columns: endpoint_id, vulnerability_count

        Args:
            filepath: Path to vulnerabilities CSV file

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If CSV format is invalid
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    endpoint_id = int(row['endpoint_id'])
                    self.vulnerabilities[endpoint_id] = int(row['vulnerability_count'])
            logger.info(f"Loaded vulnerabilities from {filepath}")
        except FileNotFoundError:
            logger.error(f"File not found: {filepath}")
            raise
        except KeyError as e:
            logger.error(f"Invalid CSV format in {filepath}: missing column {e}")
            raise ValueError(f"Missing required column: {e}")

    def load_access_logs(self, filepath: str) -> None:
        """
        Load access frequency data from CSV file.

        Expected columns: endpoint_id, access_frequency

        Args:
            filepath: Path to access logs CSV file

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If CSV format is invalid
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    endpoint_id = int(row['endpoint_id'])
                    self.access_logs[endpoint_id] = int(row['access_frequency'])
            logger.info(f"Loaded access logs from {filepath}")
        except FileNotFoundError:
            logger.error(f"File not found: {filepath}")
            raise
        except KeyError as e:
            logger.error(f"Invalid CSV format in {filepath}: missing column {e}")
            raise ValueError(f"Missing required column: {e}")

    def load_data_sensitivity(self, filepath: str) -> None:
        """
        Load data sensitivity information from CSV file.

        Expected columns: endpoint_id, handles_sensitive_data

        Args:
            filepath: Path to data sensitivity CSV file

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If CSV format is invalid
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    endpoint_id = int(row['endpoint_id'])
                    # Convert string to boolean
                    sensitive = row['handles_sensitive_data'].lower() in ('1', 'true', 'yes')
                    self.data_sensitivity[endpoint_id] = sensitive
            logger.info(f"Loaded data sensitivity from {filepath}")
        except FileNotFoundError:
            logger.error(f"File not found: {filepath}")
            raise
        except KeyError as e:
            logger.error(f"Invalid CSV format in {filepath}: missing column {e}")
            raise ValueError(f"Missing required column: {e}")

    def analyze(self) -> List[Endpoint]:
        """
        Analyze all endpoints and calculate priority scores.

        Returns:
            List[Endpoint]: List of endpoints sorted by priority score (descending)
        """
        logger.info("Starting analysis of endpoints")

        # Merge data from all sources
        for endpoint_id, endpoint in self.endpoints.items():
            # Get vulnerability count if available, default to 0
            endpoint.vulnerability_count = self.vulnerabilities.get(endpoint_id, 0)

            # Get access frequency if available, default to 0
            endpoint.access_frequency = self.access_logs.get(endpoint_id, 0)

            # Get sensitivity status if available, default to False
            endpoint.handles_sensitive_data = self.data_sensitivity.get(endpoint_id, False)

            # Calculate priority score
            endpoint.calculate_priority()

        # Sort by priority score (descending)
        sorted_endpoints = sorted(
            self.endpoints.values(),
            key=lambda e: e.priority_score,
            reverse=True
        )

        logger.info(f"Analysis complete. Ranked {len(sorted_endpoints)} endpoints")
        return sorted_endpoints

    def export_json(self, filepath: str, endpoints: List[Endpoint]) -> None:
        """
        Export analysis results to JSON file.

        Args:
            filepath: Output JSON file path
            endpoints: List of sorted endpoints
        """
        try:
            output = {
                "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_endpoints": len(endpoints),
                "protected_endpoints": [
                    {
                        "rank": idx + 1,
                        **asdict(endpoint)
                    }
                    for idx, endpoint in enumerate(endpoints)
                ]
            }

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2)

            logger.info(f"Exported results to JSON: {filepath}")
        except IOError as e:
            logger.error(f"Failed to write JSON file: {e}")
            raise

    def export_csv(self, filepath: str, endpoints: List[Endpoint]) -> None:
        """
        Export analysis results to CSV file.

        Args:
            filepath: Output CSV file path
            endpoints: List of sorted endpoints
        """
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                fieldnames = [
                    'rank', 'endpoint_id', 'endpoint_name', 'priority_score',
                    'risk_score', 'vulnerability_count', 'access_frequency',
                    'handles_sensitive_data'
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()

                for idx, endpoint in enumerate(endpoints):
                    row = asdict(endpoint)
                    row['rank'] = idx + 1
                    writer.writerow(row)

            logger.info(f"Exported results to CSV: {filepath}")
        except IOError as e:
            logger.error(f"Failed to write CSV file: {e}")
            raise

    def print_results(self, endpoints: List[Endpoint]) -> None:
        """
        Print analysis results in tabular format.

        Args:
            endpoints: List of sorted endpoints
        """
        print("\n" + "=" * 120)
        print("ENDPOINT PROTECTION PRIORITY ANALYSIS".center(120))
        print("=" * 120)
        print(f"\n{'Rank':<6} {'Endpoint ID':<12} {'Endpoint Name':<25} {'Priority':<10} "
              f"{'Risk':<6} {'Vuln':<5} {'Access':<8} {'Sensitive':<10}")
        print("-" * 120)

        for idx, endpoint in enumerate(endpoints, 1):
            sensitive = "Yes" if endpoint.handles_sensitive_data else "No"
            print(f"{idx:<6} {endpoint.endpoint_id:<12} {endpoint.endpoint_name:<25} "
                  f"{endpoint.priority_score:<10.2f} {endpoint.risk_score:<6.2f} "
                  f"{endpoint.vulnerability_count:<5} {endpoint.access_frequency:<8} "
                  f"{sensitive:<10}")

        print("\n" + "=" * 120)
        print(f"Total Endpoints Analyzed: {len(endpoints)}")
        print("=" * 120 + "\n")


def main(csv_files: Dict[str, str], output_format: str = 'all') -> List[Endpoint]:
    """
    Main entry point for the decision layer analysis.

    Args:
        csv_files: Dictionary with keys: 'endpoints', 'vulnerabilities', 'access_logs', 'data_sensitivity'
        output_format: Output format - 'json', 'csv', 'console', or 'all'

    Returns:
        List[Endpoint]: Sorted list of endpoints by priority

    Example:
        csv_files = {
            'endpoints': 'data/endpoints.csv',
            'vulnerabilities': 'data/vulnerabilities.csv',
            'access_logs': 'data/access_logs.csv',
            'data_sensitivity': 'data/data_sensitivity.csv'
        }
        results = main(csv_files, output_format='all')
    """
    try:
        # Initialize decision layer
        dl = DecisionLayer()

        # Load data from all sources
        dl.load_endpoints(csv_files['endpoints'])
        dl.load_vulnerabilities(csv_files['vulnerabilities'])
        dl.load_access_logs(csv_files['access_logs'])
        dl.load_data_sensitivity(csv_files['data_sensitivity'])

        # Analyze endpoints
        results = dl.analyze()

        # Export results
        if output_format in ('json', 'all'):
            dl.export_json('protected_endpoints.json', results)

        if output_format in ('csv', 'all'):
            dl.export_csv('protected_endpoints.csv', results)

        if output_format in ('console', 'all'):
            dl.print_results(results)

        logger.info("Analysis completed successfully")
        return results

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise


if __name__ == '__main__':
    # Default file paths
    csv_files = {
        'endpoints': 'data/endpoints.csv',
        'vulnerabilities': 'data/vulnerabilities.csv',
        'access_logs': 'data/access_logs.csv',
        'data_sensitivity': 'data/data_sensitivity.csv'
    }

    # Run analysis with all output formats
    main(csv_files, output_format='all')
