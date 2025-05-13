import pytest
from cbom.parser import algorithm, certificate, related_crypto_material

def test_complete_crypto_flow(cbom, rsa, aes):
    # Test complete flow of crypto detection
    alg_component = algorithm.parse_algorithm(cbom, rsa, "RSA detected")
    cert_component = certificate.parse_x509_certificate_details(cbom, rsa)
    
    # Verify dependencies are properly set
    assert cert_component in cbom.get_all_dependencies(alg_component)
    
    # Verify multiple algorithms
    aes_component = algorithm.parse_algorithm(cbom, aes, "AES detected")
    assert len(cbom.components) == 3

# ... more integration tests for complete flows
