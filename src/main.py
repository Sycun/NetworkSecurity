import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
                             QListWidget, QStackedWidget, QTextEdit, QPushButton,
                             QLabel, QLineEdit, QFormLayout)
from PyQt6.QtCore import Qt, pyqtSignal
from dns_monitor import DNSMonitor

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_module = None
        self.setWindowTitle("网络安全监控系统")
        self.setGeometry(100, 100, 1200, 800)
        
        # 主布局
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)

        # 左侧功能区 (20%)
        self.function_list = QListWidget()
        self.function_list.addItems(["DNS监控", "端口扫描", "流量分析", "ARP欺骗检测", "SSL/TLS分析", "漏洞扫描", "SSH爆破检测"])
        self.function_list.setFixedWidth(240)
        main_layout.addWidget(self.function_list)

        # 中间和右侧区域
        right_layout = QVBoxLayout()
        
        # 顶部控制按钮
        control_layout = QHBoxLayout()
        self.start_btn = QPushButton("开始执行")
        self.stop_btn = QPushButton("停止")
        self.start_btn.clicked.connect(self.execute_function)
        self.stop_btn.clicked.connect(self.stop_execution)
        control_layout.addStretch()
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        right_layout.addLayout(control_layout)

        # 中间内容区域
        content_layout = QHBoxLayout()
        
        # 参数配置区 (40%)
        self.param_stack = QStackedWidget()
        self.init_dns_params()
        self.init_portscan_params()
        self.init_traffic_params()
        self.init_arp_params()
        self.init_ssl_params()
        self.init_vuln_params()
        self.init_ssh_params()
        content_layout.addWidget(self.param_stack, 4)

        # 结果展示区 (40%)
        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)
        content_layout.addWidget(self.result_area, 4)
        
        right_layout.addLayout(content_layout)
        main_layout.addLayout(right_layout)

        # 功能切换事件
        self.function_list.currentRowChanged.connect(self.handle_function_change)
        
        # 初始化监控模块
        self.dns_monitor = DNSMonitor(self.update_result)

    def init_dns_params(self):
        dns_widget = QWidget()
        form = QFormLayout()
        
        self.domain_filter = QLineEdit()
        self.record_type = QLineEdit("A")
        
        form.addRow(QLabel("域名过滤:"), self.domain_filter)
        form.addRow(QLabel("记录类型:"), self.record_type)
        
        dns_widget.setLayout(form)
        self.param_stack.addWidget(dns_widget)

    def init_portscan_params(self):
        portscan_widget = QWidget()
        form = QFormLayout()
        
        self.target_ip = QLineEdit("192.168.1.1")
        self.port_range = QLineEdit("1-1024")
        
        form.addRow(QLabel("目标IP:"), self.target_ip)
        form.addRow(QLabel("端口范围:"), self.port_range)
        
        portscan_widget.setLayout(form)
        self.param_stack.insertWidget(1, portscan_widget)

    def init_traffic_params(self):
        traffic_widget = QWidget()
        form = QFormLayout()
        
        self.interface_select = QLineEdit("en0")
        self.protocol_filter = QLineEdit("tcp")
        
        form.addRow(QLabel("监控接口:"), self.interface_select)
        form.addRow(QLabel("协议过滤:"), self.protocol_filter)
        
        traffic_widget.setLayout(form)
        self.param_stack.insertWidget(2, traffic_widget)

    def init_vuln_params(self):
        vuln_widget = QWidget()
        form = QFormLayout()
        
        self.target_url = QLineEdit("http://example.com")
        self.thread_count = QLineEdit("10")
        
        form.addRow(QLabel("目标URL:"), self.target_url)
        form.addRow(QLabel("线程数:"), self.thread_count)
        
        vuln_widget.setLayout(form)
        self.param_stack.insertWidget(5, vuln_widget)

    def init_ssh_params(self):
        ssh_widget = QWidget()
        form = QFormLayout()
        
        self.ssh_host = QLineEdit("192.168.1.1")
        self.username_list = QLineEdit("users.txt")
        
        form.addRow(QLabel("SSH主机:"), self.ssh_host)
        form.addRow(QLabel("用户字典:"), self.username_list)
        
        ssh_widget.setLayout(form)
        self.param_stack.insertWidget(6, ssh_widget)

    def init_arp_params(self):
        arp_widget = QWidget()
        form = QFormLayout()
        
        self.interface_input = QLineEdit("en0")
        self.threshold_input = QLineEdit("15")
        
        form.addRow(QLabel("网络接口:"), self.interface_input)
        form.addRow(QLabel("检测阈值(包/秒):"), self.threshold_input)
        
        arp_widget.setLayout(form)
        self.param_stack.insertWidget(3, arp_widget)

    def init_ssl_params(self):
        ssl_widget = QWidget()
        form = QFormLayout()
        
        self.target_input = QLineEdit()
        self.ssl_version = QLineEdit("TLS1.2")
        
        form.addRow(QLabel("目标地址:"), self.target_input)
        form.addRow(QLabel("SSL版本:"), self.ssl_version)
        
        ssl_widget.setLayout(form)
        self.param_stack.insertWidget(4, ssl_widget)

    def update_result(self, message):
        self.result_area.append(message)

    def closeEvent(self, event):
        self.dns_monitor.stop_monitoring()
        super().closeEvent(event)

    def handle_function_change(self, index):
        self.param_stack.setCurrentIndex(index)
        module_map = {
            0: 'dns_monitor',
            1: 'port_scan',
            2: 'traffic_analysis',
            3: 'arp_detect',
            4: 'ssl_analysis',
            5: 'vuln_scan',
            6: 'ssh_brute'
        }
        self.current_module = module_map.get(index, None)

    def execute_function(self):
        if self.current_module == 'vuln_scan':
            self.start_vuln_scan()
        elif self.current_module == 'ssh_brute':
            self.start_ssh_bruteforce()
        elif self.current_module == 'arp_detect':
            self.start_arp_detection()
        elif self.current_module == 'dns_monitor':
            self.dns_monitor.start_monitoring()
        elif self.current_module == 'port_scan':
            pass  # 添加端口扫描功能实现
        elif self.current_module == 'traffic_analysis':
            pass  # 添加流量分析功能实现
        elif self.current_module == 'ssl_analysis':
            self.start_ssl_analysis()
        else:
            self.result_area.append("未选择有效功能模块")

    def start_vuln_scan(self):
        target_url = self.target_url.text()
        threads = int(self.thread_count.text())
        self.result_area.append(f"开始漏洞扫描：{target_url} 使用{threads}线程")

    def start_ssh_bruteforce(self):
        host = self.ssh_host.text()
        userfile = self.username_list.text()
        self.result_area.append(f"启动SSH爆破检测，目标：{host} 用户字典：{userfile}")

    def start_arp_detection(self):
        interface = self.interface_input.text()
        threshold = int(self.threshold_input.text())
        # 调用ARP检测模块
        self.result_area.append(f"开始ARP欺骗检测，接口：{interface}，阈值：{threshold}包/秒")

    def start_ssl_analysis(self):
        target = self.target_input.text()
        ssl_version = self.ssl_version.text()
        # 调用SSL分析模块
        self.result_area.append(f"开始SSL/TLS分析，目标：{target}，版本：{ssl_version}")

    def stop_execution(self):
        self.result_area.append("已停止当前操作")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())