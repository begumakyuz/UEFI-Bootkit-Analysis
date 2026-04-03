import unittest
import os
import sys

# Script yolunu import edebilmek için sys.path güncellemesi
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scripts.security_check import check_env_configuration

class TestAnalysisConfiguration(unittest.TestCase):
    def setUp(self):
        # Test öncesi çevreyi sahte ayarlama
        os.environ["ANALYSIS_MODE"] = "strict"
        os.environ["YARA_RULES_PATH"] = "./yara/test_rule.yar"

    def test_env_strict_mode(self):
        """Test: analysis_mode 'strict' olduğunda script True dönmeli."""
        status, msg = check_env_configuration()
        self.assertTrue(status, "Strict mod aktifken testten geçmeli.")
        self.assertIn("Güvenlik tarama yapılandırması başarılı", msg)

    def test_env_loose_mode(self):
        """Test: analysis_mode 'loose' olduğunda script False dönerek hata vermeli."""
        os.environ["ANALYSIS_MODE"] = "loose"
        status, msg = check_env_configuration()
        self.assertFalse(status, "Loose mod aktifken hata vermeli.")
        self.assertIn("HATA", msg)

if __name__ == '__main__':
    unittest.main()
