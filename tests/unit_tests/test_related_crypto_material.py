from cbom.parser.related_crypto_material import parse_private_key,parse_initialization_vector
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (RelatedCryptoMaterialType)


def test_private_key__should_extract_key_size_for_key(cbom, rsa):
    parse_private_key(cbom, rsa)

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.related_crypto_material_properties.size == 2048


def test_private_key__overlapping_detection_contexts__should_update_existing_detection_context(cbom, make_rsa_component):
    rsa1 = make_rsa_component(start_line=10, end_line=20)
    rsa2 = make_rsa_component(start_line=15, end_line=25)

    parse_private_key(cbom, rsa1)
    parse_private_key(cbom, rsa2)

    assert len(cbom.components) == 1
    assert len(cbom.components[0].evidence.occurrences) == 1


def test_initialization_vector_generation(cbom):
    
    finding = {
        'artifactLocation': {'uri': 'test.py'},
        'contextRegion': {
            'snippet': {'text': 'iv = os.urandom(16)'},
            'startLine': 1,
            'endLine': 1
        }
    }
    result = parse_initialization_vector(cbom, finding)
    
    assert result.crypto_properties.related_crypto_material_properties.type == RelatedCryptoMaterialType.INITIALIZATION_VECTOR
    assert len(cbom.components) == 1
