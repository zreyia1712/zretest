#!/usr/bin/env python3
"""
Unit tests for the Decision Layer module.

Tests cover:
- Endpoint dataclass and priority calculation
- CSV loading from all 4 data sources
- Data merging and analysis
- Priority ranking algorithm
- Export functionality (JSON and CSV)
- Error handling
"""

import unittest
import csv
import json
import tempfile
import os
from pathlib import Path
from decision_layer import Endpoint, DecisionLayer, main


class TestEndpoint(unittest.TestCase):
    """Test cases for the Endpoint dataclass"""

    def test_endpoint_creation(self):
        """Test basic endpoint creation"""
        ep = Endpoint(
            endpoint_id=1,
            endpoint_name="/api/users",
            risk_score=6.5
        )
        self.assertEqual(ep.endpoint_id, 1)
        self.assertEqual(ep.endpoint_name, "/api/users")
        self.assertEqual(ep.risk_score, 6.5)

    def test_endpoint_priority_calculation_basic(self):
        """Test priority calculation with basic inputs"""
        ep = Endpoint(
            endpoint_id=1,
            endpoint_name="/api/users",
            risk_score=5.0,
            vulnerability_count=0,
            access_frequency=0,
            handles_sensitive_data=False
        )
        priority = ep.calculate_priority()
        expected = 5.0 * 0.4  # Only risk score contributes
        self.assertEqual(priority, round(expected, 2))

    def test_endpoint_priority_with_all_factors(self):
        """Test priority calculation with all factors"""
        ep = Endpoint(
            endpoint_id=1,
            endpoint_name="/api/admin",
            risk_score=8.0,
            vulnerability_count=5,
            access_frequency=1000,
            handles_sensitive_data=True
        )
        priority = ep.calculate_priority()
        # Risk: 8.0 * 0.4 = 3.2
        # Vuln: 5 * 10 * 0.3 = 15
        # Access: (1000/5000) * 0.2 = 0.04
        # Sensitive: 1 * 100 * 0.1 = 10
        # Total: 28.24
        expected = 28.24
        self.assertEqual(priority, round(expected, 2))

    def test_endpoint_priority_capped_access_frequency(self):
        """Test that access frequency normalization is capped at 1.0"""
        ep = Endpoint(
            endpoint_id=1,
            endpoint_name="/api/test",
            risk_score=5.0,
            vulnerability_count=0,
            access_frequency=10000,  # Way above 5000 cap
            handles_sensitive_data=False
        )
        priority = ep.calculate_priority()
        # Access should be capped at 1.0
        # Risk: 5.0 * 0.4 = 2.0
        # Access: 1.0 * 0.2 = 0.2
        # Total: 2.2
        expected = 2.2
        self.assertEqual(priority, round(expected, 2))

    def test_endpoint_sensitive_data_flag(self):
        """Test sensitive data flag influence on priority"""
        ep1 = Endpoint(
            endpoint_id=1,
            endpoint_name="/api/data",
            risk_score=5.0,
            vulnerability_count=0,
            access_frequency=0,
            handles_sensitive_data=False
        )
        ep2 = Endpoint(
            endpoint_id=2,
            endpoint_name="/api/data2",
            risk_score=5.0,
            vulnerability_count=0,
            access_frequency=0,
            handles_sensitive_data=True
        )
        p1 = ep1.calculate_priority()
        p2 = ep2.calculate_priority()
        # ep2 should have 10 points higher (100 * 0.1)
        self.assertEqual(p2 - p1, 10.0)


class TestDecisionLayerCSVLoading(unittest.TestCase):
    """Test cases for CSV loading functionality"""

    def setUp(self):
        """Create temporary directory and test CSV files"""
        self.temp_dir = tempfile.mkdtemp()

        # Create test endpoints CSV
        self.endpoints_file = os.path.join(self.temp_dir, 'endpoints.csv')
        with open(self.endpoints_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['endpoint_id', 'endpoint_name', 'risk_score'])
            writer.writeheader()
            writer.writerows([
                {'endpoint_id': '1', 'endpoint_name': '/api/users', 'risk_score': '6.5'},
                {'endpoint_id': '2', 'endpoint_name': '/api/admin', 'risk_score': '8.2'},
            ])

        # Create test vulnerabilities CSV
        self.vulnerabilities_file = os.path.join(self.temp_dir, 'vulnerabilities.csv')
        with open(self.vulnerabilities_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['endpoint_id', 'vulnerability_count'])
            writer.writeheader()
            writer.writerows([
                {'endpoint_id': '1', 'vulnerability_count': '2'},
                {'endpoint_id': '2', 'vulnerability_count': '5'},
            ])

        # Create test access logs CSV
        self.access_logs_file = os.path.join(self.temp_dir, 'access_logs.csv')
        with open(self.access_logs_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['endpoint_id', 'access_frequency'])
            writer.writeheader()
            writer.writerows([
                {'endpoint_id': '1', 'access_frequency': '1250'},
                {'endpoint_id': '2', 'access_frequency': '450'},
            ])

        # Create test data sensitivity CSV
        self.sensitivity_file = os.path.join(self.temp_dir, 'data_sensitivity.csv')
        with open(self.sensitivity_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['endpoint_id', 'handles_sensitive_data'])
            writer.writeheader()
            writer.writerows([
                {'endpoint_id': '1', 'handles_sensitive_data': '0'},
                {'endpoint_id': '2', 'handles_sensitive_data': '1'},
            ])

    def tearDown(self):
        """Clean up temporary files"""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_load_endpoints(self):
        """Test loading endpoints from CSV"""
        dl = DecisionLayer()
        dl.load_endpoints(self.endpoints_file)
        self.assertEqual(len(dl.endpoints), 2)
        self.assertIn(1, dl.endpoints)
        self.assertEqual(dl.endpoints[1].endpoint_name, '/api/users')
        self.assertEqual(dl.endpoints[2].risk_score, 8.2)

    def test_load_vulnerabilities(self):
        """Test loading vulnerabilities from CSV"""
        dl = DecisionLayer()
        dl.load_vulnerabilities(self.vulnerabilities_file)
        self.assertEqual(len(dl.vulnerabilities), 2)
        self.assertEqual(dl.vulnerabilities[1], 2)
        self.assertEqual(dl.vulnerabilities[2], 5)

    def test_load_access_logs(self):
        """Test loading access logs from CSV"""
        dl = DecisionLayer()
        dl.load_access_logs(self.access_logs_file)
        self.assertEqual(len(dl.access_logs), 2)
        self.assertEqual(dl.access_logs[1], 1250)
        self.assertEqual(dl.access_logs[2], 450)

    def test_load_data_sensitivity(self):
        """Test loading data sensitivity from CSV"""
        dl = DecisionLayer()
        dl.load_data_sensitivity(self.sensitivity_file)
        self.assertEqual(len(dl.data_sensitivity), 2)
        self.assertFalse(dl.data_sensitivity[1])
        self.assertTrue(dl.data_sensitivity[2])

    def test_load_missing_file(self):
        """Test error handling for missing files"""
        dl = DecisionLayer()
        with self.assertRaises(FileNotFoundError):
            dl.load_endpoints('/nonexistent/file.csv')

    def test_load_invalid_format(self):
        """Test error handling for invalid CSV format"""
        bad_file = os.path.join(self.temp_dir, 'bad.csv')
        with open(bad_file, 'w') as f:
            f.write('invalid,format\n1,2\n')

        dl = DecisionLayer()
        with self.assertRaises(ValueError):
            dl.load_endpoints(bad_file)


class TestDecisionLayerAnalysis(unittest.TestCase):
    """Test cases for the analysis functionality"""

    def setUp(self):
        """Set up test data"""
        self.temp_dir = tempfile.mkdtemp()

        # Create comprehensive test data
        self.endpoints_file = os.path.join(self.temp_dir, 'endpoints.csv')
        with open(self.endpoints_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['endpoint_id', 'endpoint_name', 'risk_score'])
            writer.writeheader()
            for i in range(1, 6):
                writer.writerow({
                    'endpoint_id': str(i),
                    'endpoint_name': f'/api/endpoint{i}',
                    'risk_score': str(5.0 + i)
                })

        self.vulnerabilities_file = os.path.join(self.temp_dir, 'vulnerabilities.csv')
        with open(self.vulnerabilities_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['endpoint_id', 'vulnerability_count'])
            writer.writeheader()
            for i in range(1, 6):
                writer.writerow({'endpoint_id': str(i), 'vulnerability_count': str(i)})

        self.access_logs_file = os.path.join(self.temp_dir, 'access_logs.csv')
        with open(self.access_logs_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['endpoint_id', 'access_frequency'])
            writer.writeheader()
            for i in range(1, 6):
                writer.writerow({'endpoint_id': str(i), 'access_frequency': str(i * 500)})

        self.sensitivity_file = os.path.join(self.temp_dir, 'data_sensitivity.csv')
        with open(self.sensitivity_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['endpoint_id', 'handles_sensitive_data'])
            writer.writeheader()
            for i in range(1, 6):
                writer.writerow({
                    'endpoint_id': str(i),
                    'handles_sensitive_data': '1' if i % 2 == 0 else '0'
                })

    def tearDown(self):
        """Clean up temporary files"""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_analyze_returns_sorted_list(self):
        """Test that analysis returns endpoints sorted by priority"""
        dl = DecisionLayer()
        dl.load_endpoints(self.endpoints_file)
        dl.load_vulnerabilities(self.vulnerabilities_file)
        dl.load_access_logs(self.access_logs_file)
        dl.load_data_sensitivity(self.sensitivity_file)

        results = dl.analyze()

        # Check that results are sorted in descending order
        self.assertEqual(len(results), 5)
        for i in range(len(results) - 1):
            self.assertGreaterEqual(results[i].priority_score, results[i + 1].priority_score)

    def test_analyze_calculates_all_priorities(self):
        """Test that analysis calculates priority for all endpoints"""
        dl = DecisionLayer()
        dl.load_endpoints(self.endpoints_file)
        dl.load_vulnerabilities(self.vulnerabilities_file)
        dl.load_access_logs(self.access_logs_file)
        dl.load_data_sensitivity(self.sensitivity_file)

        results = dl.analyze()

        for endpoint in results:
            self.assertGreater(endpoint.priority_score, 0)

    def test_analyze_merges_all_data(self):
        """Test that analysis merges data from all sources correctly"""
        dl = DecisionLayer()
        dl.load_endpoints(self.endpoints_file)
        dl.load_vulnerabilities(self.vulnerabilities_file)
        dl.load_access_logs(self.access_logs_file)
        dl.load_data_sensitivity(self.sensitivity_file)

        results = dl.analyze()

        # Check that all data is properly merged
        for endpoint in results:
            self.assertEqual(endpoint.vulnerability_count, endpoint.endpoint_id)
            self.assertEqual(endpoint.access_frequency, endpoint.endpoint_id * 500)
            expected_sensitive = endpoint.endpoint_id % 2 == 0
            self.assertEqual(endpoint.handles_sensitive_data, expected_sensitive)


class TestDecisionLayerExport(unittest.TestCase):
    """Test cases for export functionality"""

    def setUp(self):
        """Set up test data"""
        self.temp_dir = tempfile.mkdtemp()
        self.endpoints = [
            Endpoint(1, "/api/users", 6.5, 2, 1250, False, 8.1),
            Endpoint(2, "/api/admin", 8.2, 5, 450, True, 12.5),
        ]

    def tearDown(self):
        """Clean up temporary files"""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_export_json(self):
        """Test JSON export functionality"""
        dl = DecisionLayer()
        output_file = os.path.join(self.temp_dir, 'output.json')

        dl.export_json(output_file, self.endpoints)

        # Verify file was created and contains valid JSON
        self.assertTrue(os.path.exists(output_file))
        with open(output_file, 'r') as f:
            data = json.load(f)

        self.assertIn('analysis_date', data)
        self.assertIn('total_endpoints', data)
        self.assertIn('protected_endpoints', data)
        self.assertEqual(len(data['protected_endpoints']), 2)
        self.assertEqual(data['protected_endpoints'][0]['rank'], 1)

    def test_export_csv(self):
        """Test CSV export functionality"""
        dl = DecisionLayer()
        output_file = os.path.join(self.temp_dir, 'output.csv')

        dl.export_csv(output_file, self.endpoints)

        # Verify file was created
        self.assertTrue(os.path.exists(output_file))

        # Verify CSV content
        with open(output_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['rank'], '1')
        self.assertEqual(rows[0]['endpoint_name'], '/api/users')


class TestDecisionLayerMain(unittest.TestCase):
    """Test cases for the main function"""

    def setUp(self):
        """Create comprehensive test data"""
        self.temp_dir = tempfile.mkdtemp()

        # Create all 4 test CSV files
        self.endpoints_file = os.path.join(self.temp_dir, 'endpoints.csv')
        with open(self.endpoints_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['endpoint_id', 'endpoint_name', 'risk_score'])
            writer.writeheader()
            writer.writerows([
                {'endpoint_id': '1', 'endpoint_name': '/api/auth', 'risk_score': '9.0'},
                {'endpoint_id': '2', 'endpoint_name': '/api/payments', 'risk_score': '8.5'},
            ])

        self.vulnerabilities_file = os.path.join(self.temp_dir, 'vulnerabilities.csv')
        with open(self.vulnerabilities_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['endpoint_id', 'vulnerability_count'])
            writer.writeheader()
            writer.writerows([
                {'endpoint_id': '1', 'vulnerability_count': '7'},
                {'endpoint_id': '2', 'vulnerability_count': '6'},
            ])

        self.access_logs_file = os.path.join(self.temp_dir, 'access_logs.csv')
        with open(self.access_logs_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['endpoint_id', 'access_frequency'])
            writer.writeheader()
            writer.writerows([
                {'endpoint_id': '1', 'access_frequency': '980'},
                {'endpoint_id': '2', 'access_frequency': '2100'},
            ])

        self.sensitivity_file = os.path.join(self.temp_dir, 'data_sensitivity.csv')
        with open(self.sensitivity_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['endpoint_id', 'handles_sensitive_data'])
            writer.writeheader()
            writer.writerows([
                {'endpoint_id': '1', 'handles_sensitive_data': 'true'},
                {'endpoint_id': '2', 'handles_sensitive_data': 'yes'},
            ])

        # Save current directory
        self.original_dir = os.getcwd()
        os.chdir(self.temp_dir)

    def tearDown(self):
        """Clean up"""
        os.chdir(self.original_dir)
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_main_function_execution(self):
        """Test main function executes successfully"""
        csv_files = {
            'endpoints': self.endpoints_file,
            'vulnerabilities': self.vulnerabilities_file,
            'access_logs': self.access_logs_file,
            'data_sensitivity': self.sensitivity_file
        }

        results = main(csv_files, output_format='console')

        self.assertEqual(len(results), 2)
        self.assertIsInstance(results[0], Endpoint)

    def test_main_json_output(self):
        """Test main function produces JSON output"""
        csv_files = {
            'endpoints': self.endpoints_file,
            'vulnerabilities': self.vulnerabilities_file,
            'access_logs': self.access_logs_file,
            'data_sensitivity': self.sensitivity_file
        }

        main(csv_files, output_format='json')

        self.assertTrue(os.path.exists('protected_endpoints.json'))

    def test_main_csv_output(self):
        """Test main function produces CSV output"""
        csv_files = {
            'endpoints': self.endpoints_file,
            'vulnerabilities': self.vulnerabilities_file,
            'access_logs': self.access_logs_file,
            'data_sensitivity': self.sensitivity_file
        }

        main(csv_files, output_format='csv')

        self.assertTrue(os.path.exists('protected_endpoints.csv'))


if __name__ == '__main__':
    unittest.main()
