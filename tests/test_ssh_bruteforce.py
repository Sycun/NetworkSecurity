import unittest
from unittest.mock import patch, mock_open
from ssh_bruteforce import ssh_connect

class TestSSHBruteforce(unittest.TestCase):
    @patch('ssh_bruteforce.main')
    def test_valid_parameters(self, mock_main):
        """测试合法参数执行"""
        test_args = {
            '目标IP': '192.168.1.1',
            '用户名': 'admin',
            '密码字典': 'passwords.txt',
            '端口号': '22',
            '线程数': '5'
        }
        mock_main.return_value = True
        with patch('os.path.exists', return_value=True):
            self.assertTrue(ssh_bruteforce.main(**test_args))

    def test_invalid_port(self):
        """测试非法端口号校验"""
        with self.assertRaises(ValueError):
            result = ssh_connect('127.0.0.1', 'test', 'password')

    @patch('os.path.exists')
    def test_missing_dict_file(self, mock_exists):
        """测试字典文件不存在校验"""
        mock_exists.return_value = False
        with self.assertRaises(FileNotFoundError):
            ssh_bruteforce.main(目标IP='10.0.0.1', 用户名='root', 密码字典='missing.txt', 端口号='22', 线程数='3')

if __name__ == '__main__':
    unittest.main()