from hypothesis import given
from hypothesis.strategies import binary
import pnet
import pytest


@given(binary(min_size=6, max_size=6))
def test_parse_hwaddress(data):
    address = pnet.HWAddress(data)
    assert bytes(address) == data
    assert set(str(address)) <= set('0123456789abcdef:')


@pytest.mark.parametrize('data', [
    '00:11:22:33:44:55',
    '00-11-22-33-44-55',
    'aa:bb:cc:dd:ee:ff',
    'aa-bb-cc-dd-ee-ff'
])
def test_parse_valid_hwaddress_string(data):
    address = pnet.HWAddress(data)
    assert str(address) == data.replace('-', ':')


@pytest.mark.parametrize('data', [
    '00:11:22:33:44:55:66',
    '255:0:0:0:0:0',
    'bb:cc:dd:ee:ff:gg'
])
def test_parse_invalid_hwaddress_string(data):
    with pytest.raises(ValueError):
        pnet.HWAddress(data)
