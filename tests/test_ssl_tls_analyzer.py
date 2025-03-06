import pytest
from ssl_tls_analyzer import tls_handler, version_name
from unittest.mock import Mock

class MockSSLPacket:
    def haslayer(self, layer):
        return True
    def __getitem__(self, key):
        return {'version':0x0303, 'ciphers':[0x1301], 'subject':'example.com'}

@pytest.fixture
def mock_ssl_packet():
    return MockSSLPacket()

def test_version_name():
    assert version_name(0x0303) == 'TLSv1.2'
    assert version_name(0x0304) == 'TLSv1.3'

def test_tls_handler_packet_processing():
    class MockPacket:
        def haslayer(self, layer):
            return True
        def __getitem__(self, key):
            return type('',(object,),{'version':0x0303,'ciphers':[0x0005]})()
    
    tls_handler(MockPacket())

def test_certificate_validation():
    result = tls_handler(MockSSLPacket())
    assert result['valid'] is True
    assert 'example.com' in result['subject']


def test_expired_certificate(mock_ssl_packet):
    with pytest.raises(Exception):
        tls_handler(mock_ssl_packet)


def test_protocol_support():
    result = tls_handler(MockSSLPacket())
    assert 'TLSv1.2' in result
    assert 'SSLv2' not in result['supported_protocols']
    assert 'TLSv1.3' in result['supported_protocols']