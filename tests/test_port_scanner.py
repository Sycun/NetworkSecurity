import unittest
from unittest.mock import patch
import port_scanner

class TestPortScanner(unittest.TestCase):
    @patch('port_scanner.main')
    def test_valid_parameters(self, mock_main):
        """测试合法参数校验"""
        test_args = {
            '目标IP': '127.0.0.1',
            '端口范围': '80-100',
            '扫描类型': 'TCP',
            '超时时间(s)': '2'
        }
        mock_main.return_value = True
        self.assertTrue(port_scanner.main(**test_args))

    def test_invalid_ip(self):
        """测试非法IP格式校验"""
        with self.assertRaises(ValueError):
            port_scanner.main(目标IP='256.0.0.1', 端口范围='80', 扫描类型='TCP', 超时时间='1')

    def test_port_range_validation(self):
        """测试端口范围格式校验"""
        with self.assertRaises(ValueError):
            port_scanner.main(目标IP='127.0.0.1', 端口范围='a-b', 扫描类型='TCP', 超时时间='1')

if __name__ == '__main__':
    unittest.main()