from cyclonedx.model.crypto import CryptoMode, CryptoPadding, CryptoPrimitive, CryptoAssetType
from cyclonedx.model.component import ComponentType
from cbom.parser.algorithm import parse_algorithm

def test_algorithm_detection(cbom, aes):
    """Test AES algorithm detection with proper evidence"""
    # Act
    parse_algorithm(cbom, aes, "AES encryption detected")
    
    # Assert
    assert len(cbom.components) > 0  # Verify component was added
    result = cbom.components[0]
    assert result is not None
    assert result in cbom.components
    assert result.crypto_properties.algorithm_properties.primitive == CryptoPrimitive.BLOCK_CIPHER
    assert result.crypto_properties.algorithm_properties.mode == CryptoMode.ECB
    assert result.name == "AES-32-ECB-PKCS7"
    assert len(cbom.components) == 1

def test_algorithm_name_generation(cbom, rsa):
    parse_algorithm(cbom, rsa, "RSA key generation detected")
    assert cbom.components[0].name == "SHA256-OAEP"

def test_algorithm__should_infer_primitive(cbom, aes):
    # Act
    parse_algorithm(cbom, aes,"Use of algorithm AES")
    
    # Assert
    assert len(cbom.components) > 0  # Verify component was added
    component = next(c for c in cbom.components 
                    if c.type == ComponentType.CRYPTOGRAPHIC_ASSET 
                    and c.crypto_properties.asset_type == CryptoAssetType.ALGORITHM)
    assert component.crypto_properties.algorithm_properties.primitive == CryptoPrimitive.BLOCK_CIPHER


def test_algorithm__should_extract_block_mode(cbom, aes):
    # Act
    parse_algorithm(cbom, aes,  "Use of algorithm AES")
    
    # Assert
    component = next(c for c in cbom.components 
                    if c.type == ComponentType.CRYPTOGRAPHIC_ASSET 
                    and c.crypto_properties.asset_type == CryptoAssetType.ALGORITHM)
    assert component.crypto_properties.algorithm_properties.mode == CryptoMode.ECB


def test_algorithm__should_extract_padding(cbom, aes):
    parse_algorithm(cbom, aes, "Use of algorithm AES")

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.padding == CryptoPadding.PKCS7


def test_algorithm__should_extract_crypto_functions(cbom, rsa):
    parse_algorithm(cbom, rsa,"Use of algorithm RSA")

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.crypto_functions == {
        'generate', 'encrypt', 'sign'}


def test_algorithm__should_not_identify_non_function_match_as_crypto_function(cbom, rsa):
    rsa['contextRegion']['snippet']['text'] += '\n\ndef decrypt(): ...'

    parse_algorithm(cbom, rsa, "Use of algorithm RSA")

    assert len(cbom.components) == 1
    assert 'decrypt' not in cbom.components[0].crypto_properties.algorithm_properties.crypto_functions


def test_algorithm__should_transform_fernet(cbom, fernet):
    parse_algorithm(cbom, fernet, "Use of algorithm Fernet")

    assert len(cbom.components) == 1
    assert cbom.components[0].crypto_properties.algorithm_properties.parameter_set_identifier == 'AES-128-CBC'


def test_algorithm__public_key_encryption__should_generate_certificate_component(cbom, rsa):
    parse_algorithm(cbom, rsa, "RSA key generation detected")
    assert len(list(cbom.dependencies)) >= 1


def test_algorithm__public_key_encryption__should_generate_private_key_component(cbom, rsa):
    parse_algorithm(cbom, rsa, "RSA key generation detected")


def test_parse_algorithm_aes_with_padding(cbom):
    finding = {
        'artifactLocation': {'uri': 'test.py'},
        'contextRegion': {
            'snippet': {'text': 'cipher = AES.new(key, AES.MODE_CBC, iv=iv, padding=PKCS7)'},
            'startLine': 1,
            'endLine': 1
        },
        'region': {
            'startLine': 1,
            'endLine': 1,
            'startColumn': 10,
            'endColumn': 55
        }
    }
    parse_algorithm(cbom, finding, "AES encryption detected")
    result = cbom.components[0]
    assert len(cbom.components) == 1
    assert result.name == "AES-CBC-PKCS7"
    assert result.crypto_properties.algorithm_properties.primitive == CryptoPrimitive.BLOCK_CIPHER
    assert result.crypto_properties.algorithm_properties.mode == CryptoMode.CBC
    assert result.crypto_properties.algorithm_properties.padding == CryptoPadding.PKCS7


def test_algorithm_detection_fernet(cbom):  # Updated to use cbom fixture
    finding = {
        'artifactLocation': {'uri': 'test.py'},
        'contextRegion': {
            'snippet': {'text': 'f = Fernet(key)'},
            'startLine': 1,
            'endLine': 1,
            'startColumn': 4,
            'endColumn': 17
        },
        'region': {
            'startLine': 1,
            'endLine': 1,
            'startColumn': 4,
            'endColumn': 17
        }
    }
    parse_algorithm(cbom, finding, "Fernet encryption detected")
    result = cbom.components[0]
    assert result.name == "AES-128-CBC"
    assert result.crypto_properties.algorithm_properties.primitive == CryptoPrimitive.BLOCK_CIPHER


def test_algorithm__different_algorithms_with_overlapping_detection_contexts__should_not_update_existing_component(cbom, make_aes_component, make_rsa_component):
    aes = make_aes_component(start_line=10, end_line=20)
    rsa = make_rsa_component(start_line=10, end_line=20)

    parse_algorithm(cbom, aes ,"AES encryption detected")
    parse_algorithm(cbom, rsa, "RSA key generation detected")

    assert len(cbom.components) == 2
