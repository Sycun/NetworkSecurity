import pytest
from dns_monitor import DNSMonitor
from unittest.mock import MagicMock

def test_normal_dns_resolution():
    monitor = DNSMonitor()
    result = monitor.resolve('example.com')
    assert '93.184.216.34' in result


def test_dns_timeout_handling(monkeypatch):
    def mock_resolve(*args, **kwargs):
        raise TimeoutError('DNS resolution timed out')
    
    monitor = DNSMonitor(timeout=2)
    monkeypatch.setattr(monitor, '_resolve_implementation', mock_resolve)
    
    with pytest.raises(TimeoutError) as excinfo:
        monitor.resolve('example.com')
    assert 'timed out' in str(excinfo.value)


def test_invalid_domain_format():
    monitor = DNSMonitor()
    invalid_cases = [
        'invalid_domain',
        'example..com',
        'http://example.com',
        'example_com'
    ]
    for domain in invalid_cases:
        with pytest.raises(ValueError, match=r'Invalid domain format'):
            monitor.resolve(domain)


def test_special_chars_domain():
    mock_signal = MagicMock()
    monitor = DNSMonitor(output_signal=mock_signal)
    with pytest.raises(ValueError):
        monitor.resolve('exa$mple.com')