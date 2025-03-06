import platform
import os

class SystemAdapter:
    @staticmethod
    def get_interface_prefix():
        system = platform.system()
        if system == 'Darwin':
            return 'en'
        elif system == 'Linux':
            return 'eth'
        return 'eth'

    @staticmethod
    def get_sudo_command():
        if platform.system() == 'Darwin':
            return 'sudo'
        return 'sudo'

    @staticmethod
    def path_join(*args):
        return os.path.join(*args)

    @classmethod
    def get_default_interface(cls):
        try:
            if platform.system() == 'Darwin':
                # 使用 ifconfig 获取活动接口
                output = os.popen('ifconfig').read()
                interfaces = [line.split(':')[0] for line in output.splitlines() 
                             if 'flags=' in line and 'lo' not in line]
                active_ifaces = [iface for iface in interfaces 
                                if 'inet ' in os.popen(f'ifconfig {iface}').read()]
                return active_ifaces[0] if active_ifaces else 'en0'
            else:
                # 保留原有 Linux 检测逻辑
                prefix = cls.get_interface_prefix()
                interfaces = [f"{prefix}0", f"{prefix}1", "lo0"]
                for iface in interfaces:
                    if os.path.exists(f"/sys/class/net/{iface}"):
                        return iface
        except Exception as e:
            print(f"Interface detection failed: {e}")
        return 'lo0'

    @staticmethod
    def check_sip_permissions():
        """检测 macOS SIP 安全策略状态"""
        if platform.system() == 'Darwin':
            sip_status = os.popen('csrutil status').read().lower()
            return 'enabled' not in sip_status
        return True