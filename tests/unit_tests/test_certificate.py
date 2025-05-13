import json
from cbom.parser.certificate import parse_x509_certificate_details
from cyclonedx.model.bom_ref import BomRef


def test_certificate__should_generate_distinguished_name(cbom, rsa):
    parse_x509_certificate_details(cbom, rsa)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.certificate_properties.subject_name == 'C=US, L=Springfield, O=Springfield Nuclear Power Plant, CN=springfield-nuclear.com'


def test_certificate__should_extract_certificate_algorithm(cbom, rsa):
    parse_x509_certificate_details(cbom, rsa)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.certificate_properties.signature_algorithm_ref == BomRef('SHA256')


def test_certificate__should_extract_signature_algorithm(cbom, rsa):
    parse_x509_certificate_details(cbom, rsa)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.certificate_properties.subject_public_key_ref == BomRef('SHA256')


def test_certificate__same_algorithm_with_overlapping_detection_contexts__should_update_existing_detection_context(cbom, make_rsa_component):
    rsa1 = make_rsa_component(start_line=10, end_line=20)
    rsa2 = make_rsa_component(start_line=15, end_line=25)

    parse_x509_certificate_details(cbom, rsa1)
    parse_x509_certificate_details(cbom, rsa2)


def test_certificate__different_algorithms_with_overlapping_detection_contexts__should_not_update_existing_component(cbom, make_rsa_component, make_dsa_component):
    rsa = make_rsa_component(start_line=10, end_line=20)
    dsa = make_dsa_component(start_line=10, end_line=20)

    parse_x509_certificate_details(cbom, rsa)
    parse_x509_certificate_details(cbom, dsa)

    assert len(cbom.components) == 1


def test_certificate_with_multiple_attributes(cbom):
    cbom = cbom
    finding = {
        'artifactLocation': {'uri': 'test.py'},
        'contextRegion': {
            'snippet': {'text': '''
                cert = X509()
                cert.COMMON_NAME = "example.com"
                cert.ORGANIZATION_NAME = "Test Org"
                cert.COUNTRY_NAME = "US"
                cert.STATE_OR_PROVINCE_NAME = "CA"
            '''},
            'startLine': 1,
            'endLine': 5
        }
    }
    result = parse_x509_certificate_details(cbom, finding)
    
    assert "CN=example.com" in result.crypto_properties.certificate_properties.subject_name
    assert "O=Test Org" in result.crypto_properties.certificate_properties.subject_name
    assert "C=US" in result.crypto_properties.certificate_properties.subject_name
    assert "ST=CA" in result.crypto_properties.certificate_properties.subject_name
