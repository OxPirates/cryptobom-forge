import copy
import json
import pytest
from pathlib import Path
from unittest.mock import patch
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType


@pytest.fixture
def cbom():
    """Generate a sample CBOM for testing - replaces create_sample_cbom"""
    cbom = Bom()

    root_component = Component(
        bom_ref='root',
        name='springfield-nuclear-power-plant',
        type=ComponentType.APPLICATION
    )
    cbom.metadata.component = root_component
    return cbom


@pytest.fixture()
def aes():
    with open(Path(__file__).absolute().parent / 'data' / 'codeql' / 'aes.sarif') as data:
        data = json.load(data)
        return data['locations'][0]['physicalLocation']


@pytest.fixture
def make_aes_component(aes):

    def _make_component(start_line, end_line):
        data = copy.deepcopy(aes)
        data['region']['startLine'] = start_line
        data['region']['endLine'] = end_line

        data['contextRegion']['startLine'] = start_line - 2
        data['contextRegion']['endLine'] = end_line + 2
        return data

    return _make_component


@pytest.fixture()
def dsa():
    with open(Path(__file__).absolute().parent / 'data' / 'codeql' / 'dsa.sarif') as data:
        data = json.load(data)
        return data['locations'][0]['physicalLocation']


@pytest.fixture
def make_dsa_component(dsa):

    def _make_component(start_line, end_line):
        data = copy.deepcopy(dsa)
        data['region']['startLine'] = start_line
        data['region']['endLine'] = end_line

        data['contextRegion']['startLine'] = start_line - 2
        data['contextRegion']['endLine'] = end_line + 2
        return data

    return _make_component


@pytest.fixture()
def fernet():
    with open(Path(__file__).absolute().parent / 'data' / 'codeql' / 'fernet.sarif') as data:
        data = json.load(data)
        return data['locations'][0]['physicalLocation']


@pytest.fixture()
def rsa():
    with open(Path(__file__).absolute().parent / 'data' / 'codeql' / 'rsa.sarif') as data:
        data = json.load(data)
        return data['locations'][0]['physicalLocation']


@pytest.fixture
def make_rsa_component(rsa):

    def _make_component(start_line, end_line):
        data = copy.deepcopy(rsa)
        data['region']['startLine'] = start_line
        data['region']['endLine'] = end_line

        data['contextRegion']['startLine'] = start_line - 2
        data['contextRegion']['endLine'] = end_line + 2
        return data

    return _make_component


@pytest.fixture(autouse=True)
def setup_patches():
    """Setup mock patches for certificate and private key components"""
    with patch('cbom.parser.algorithm.certificate.parse_x509_certificate_details') as cert_mock, \
         patch('cbom.parser.algorithm.related_crypto_material.parse_private_key') as key_mock:
        
        cert_mock.return_value = Component(
            name='certificate-component', 
            type=ComponentType.CRYPTOGRAPHIC_ASSET
        )
        key_mock.return_value = Component(
            name='private-key-component', 
            type=ComponentType.CRYPTOGRAPHIC_ASSET
        )
        yield
