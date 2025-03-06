import unittest
from unittest.mock import patch, MagicMock
from arp_spoof_detector import start_monitoring

class TestARPSpoofDetector(unittest.TestCase):
    @patch('arp_spoof_detector.sniff')
    @patch('arp_spoof_detector.ARP')
    def test_valid_parameters(self, mock_arp, mock_sniff):
        """测试合法参数执行"""
        mock_sniff.return_value = MagicMock()
        result = start_monitoring(interface='eth0', threshold=15, interval=60)
        self.assertTrue(result)

    def test_invalid_interface(self):
        """测试无效网卡名称"""
        with self.assertRaises(ValueError):
            start_monitoring(interface='invalid_eth', threshold=15, interval=60)

    def test_threshold_range(self):
        """测试检测阈值范围校验"""
        with self.assertRaises(ValueError):
            start_monitoring(interface='eth0', threshold=0, interval=30)

if __name__ == '__main__':
    unittest.main()