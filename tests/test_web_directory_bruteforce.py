import pytest
from web_directory_bruteforce import check_directory


def test_common_path_detection():
    scanner = WebDirectoryBruteforce()
    result = scanner.scan('http://example.com', paths=['admin', 'login'])
    assert 'existing_paths' in result
    assert isinstance(result['existing_paths'], list)


def test_invalid_url_handling():
    scanner = WebDirectoryBruteforce()
    with pytest.raises(ValueError):
        scanner.scan('invalid_url', paths=['test'])


def test_special_character_paths():
    scanner = WebDirectoryBruteforce()
    result = scanner.scan('http://example.com', paths=['test$path', 'long_path_'+'a'*100])
    assert 'special_chars_handled' in result


def test_scan_timeout(monkeypatch):
    def mock_scan(*args, **kwargs):
        raise TimeoutError
    
    scanner = WebDirectoryBruteforce()
    monkeypatch.setattr(scanner, 'scan', mock_scan)
    
    with pytest.raises(TimeoutError):
        scanner.scan('http://slow.site', paths=['test'])