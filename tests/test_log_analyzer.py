import pytest
from src.log_analyzer import analyze_log
import tempfile

@pytest.fixture
def sample_log():
    return '''
192.168.1.1 - - [01/Jul/2024:10:11:12 +0800] "GET /wp-admin HTTP/1.1" 404 123
10.0.0.1 - - [01/Jul/2024:10:11:13 +0800] "POST /.env HTTP/1.1" 200 456
172.16.0.1 - - [01/Jul/2024:10:11:14 +0800] "HEAD / HTTP/1.1" 403 789
'''

def test_error_code_count(sample_log):
    with tempfile.NamedTemporaryFile(mode='w') as f:
        f.write(sample_log)
        f.seek(0)
        result = analyze_log(f.name)
        
    assert result['error_codes']['404'] == 1
    assert result['error_codes']['403'] == 1
    assert result['error_codes']['200'] == 1

def test_suspicious_path_detection(sample_log):
    with tempfile.NamedTemporaryFile(mode='w') as f:
        f.write(sample_log)
        f.seek(0)
        result = analyze_log(f.name)
        
    assert len(result['suspicious_paths']) == 2
    assert 'wp-admin' in str(result['suspicious_paths'])
    assert '.env' in str(result['suspicious_paths'])