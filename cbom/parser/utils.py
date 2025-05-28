import re
from difflib import SequenceMatcher

from typing import Optional
from cryptography.hazmat.primitives import hashes
from asn1crypto.algos import DigestAlgorithmId
from asn1crypto.core import ObjectIdentifier

from cyclonedx.model import Copyright
from cyclonedx.model.component_evidence import (AnalysisTechnique, CallStack,
                                       ComponentEvidence, Identity,
                                       IdentityFieldType, Method, Occurrence,
                                       StackFrame)

from cbom import lib_utils

# Predefined OID map for crypto/hashing algorithms
CUSTOM_OID_MAP = {
    # Hashes
    'md5': '1.2.840.113549.2.5',
    'sha1': '1.3.14.3.2.26',
    'sha224': '2.16.840.1.101.3.4.2.4',
    'sha256': '2.16.840.1.101.3.4.2.1',
    'sha384': '2.16.840.1.101.3.4.2.2',
    'sha512': '2.16.840.1.101.3.4.2.3',
    'sha3-256': '2.16.840.1.101.3.4.2.8',
    'sha3-384': '2.16.840.1.101.3.4.2.9',
    'sha3-512': '2.16.840.1.101.3.4.2.10',
    'blake2b': '1.3.6.1.4.1.1722.12.2.1.16',
    'blake2s': '1.3.6.1.4.1.1722.12.2.2.8',
    # Ciphers
    'aes': '2.16.840.1.101.3.4.1',
    'des': '1.3.14.3.2.7',
    '3des': '1.2.840.113549.3.7',
    # Asymmetric
    'rsa': '1.2.840.113549.1.1.1',
    'rsa-oaep': '1.2.840.113549.1.1.7',
    'dsa': '1.2.840.10040.4.1',
    'ecdsa': '1.2.840.10045.2.1',
    'ed25519': '1.3.101.112',
    'ed448': '1.3.101.113',
    'dh': '1.2.840.113549.1.3.1',
    'ecdh': '1.3.132.1.12',
    # HMACs (alias to hash OIDs)
    'hmac-md5': '1.2.840.113549.2.5',
    'hmac-sha1': '1.3.14.3.2.26',
    'hmac-sha256': '2.16.840.1.101.3.4.2.1',
    'hmac-sha384': '2.16.840.1.101.3.4.2.2',
    'hmac-sha512': '2.16.840.1.101.3.4.2.3',

    'tripledes': '1.2.840.113549.3.7',               # 3DES (DES-EDE3-CBC)
    'arc4': '1.2.840.113549.3.4',                    # RC4
    'brainpoolp256r1': '1.3.36.3.3.2.8.1.1.7',
    'brainpoolp384r1': '1.3.36.3.3.2.8.1.1.11',
    'brainpoolp512r1': '1.3.36.3.3.2.8.1.1.13',
    'camellia': '1.2.392.200011.61.1.1.1.2',         # Camellia-128-CBC (example)
    'cast5': '1.2.840.113533.7.66.10',               # CAST5-CBC
    'chacha20': '1.3.6.1.4.1.3029.1.2.1',            # Draft OID (OpenSSH)
    'chacha20poly1305': '1.3.6.1.4.1.11591.13.1',    # Used in OpenPGP (draft)
    'concatkdfhash': '1.2.840.113549.1.9.16.3.28',   # RFC 7518 KDF
    'concatkdfhmac': '1.2.840.113549.1.9.16.3.29',
    'diffiehellman': '1.2.840.113549.1.3.1',
    'eddsa': '1.3.101.100',                          # OID arc for EdDSA (RFC 8410)
    'hkdf': '1.2.840.113549.1.9.16.3.28',
    'hkdfexpand': '1.2.840.113549.1.9.16.3.29',
    'idea': '1.3.6.1.4.1.188.7.1.1.2',               # IDEA-CBC
    'kbkdfcmac': '1.3.6.1.5.2.3.3',
    'kbkdfhmac': '1.3.6.1.5.2.3.2',
    'pbkdf2hmac': '1.2.840.113549.1.5.12',
    'pss': '1.2.840.113549.1.1.10',
    'rc2': '1.2.840.113549.3.2',
    'rijndael': '2.16.840.1.101.3.4.1',              # Alias to AES (Rijndael base)
    'scrypt': '1.3.6.1.4.1.11591.4.11',
    'seed': '1.2.410.200004.1.4',
    'sha512224': '2.16.840.1.101.3.4.2.5',
    'sha512256': '2.16.840.1.101.3.4.2.6',
    'sm3': '1.2.156.10197.1.401',
    'sm4': '1.2.156.10197.1.104.1',
    'x963kdf': '1.3.133.16.840.63.0.16',

    # SECG Named Curves
    'secp192r1': '1.2.840.10045.3.1.1',
    'secp224r1': '1.3.132.0.33',
    'secp256k1': '1.3.132.0.10',
    'secp256r1': '1.2.840.10045.3.1.7',
    'secp384r1': '1.3.132.0.34',
    'secp521r1': '1.3.132.0.35',
    'sect163k1': '1.3.132.0.1',
    'sect163r2': '1.3.132.0.15',
    'sect233k1': '1.3.132.0.26',
    'sect233r1': '1.3.132.0.27',
    'sect283k1': '1.3.132.0.16',
    'sect283r1': '1.3.132.0.17',
    'sect409k1': '1.3.132.0.36',
    'sect409r1': '1.3.132.0.37',
    'sect571k1': '1.3.132.0.38',
    'sect571r1': '1.3.132.0.39',

}

# Security level map: classical bits, NIST quantum security level category (0 = none)
# 🔐 Reference: NIST SP 800-57 Part 1 Revision 5
# 📄 Title: "Recommendation for Key Management – Part 1: General"
# 📚 Table 2: Comparable Algorithm Strengths
#
# +----------------+-------------------------+-------------------------------+---------------------------+-----------------------------+
# | Security Bits  | Symmetric Key Algorithm | Finite Field/Discrete Logarithm| Integer Factorization (RSA)| Elliptic Curve (ECDSA, ECDH)|
# +----------------+-------------------------+-------------------------------+---------------------------+-----------------------------+
# | 80             | 2TDEA (deprecated)      | L=1024, N=160                 | k=1024                    | f=160–223                   |
# | 112            | 3TDEA                   | L=2048, N=224                 | k=2048                    | f=224–255                   |
# | 128            | AES-128                 | L=3072, N=256                 | k=3072                    | f=256–383                   |
# | 192            | AES-192                 | L=7680, N=384                 | k=7680                    | f=384–511                   |
# | 256            | AES-256                 | L=15360, N=512                | k=15360                   | f=512+                      |
# +----------------+-------------------------+-------------------------------+---------------------------+-----------------------------+
#
# Legend:
# - L: modulus length in bits
# - N: subgroup order in bits
# - k: RSA modulus size in bits
# - f: ECC field size in bits
#
# 🔗 Source: https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final

# 🛡️ NIST Post-Quantum Security Strength Levels (Categories)
#
# Level 1:
#   - Equivalent to the security strength of AES-128 (exhaustive key search).
#   - Represents the lowest acceptable security level under NIST PQC standards.
#
# Level 2:
#   - Equivalent to the security strength of SHA-256 or SHA3-256 (collision resistance).
#   - Offers a moderate level of security.
#
# Level 3:
#   - Equivalent to the security strength of AES-192 (exhaustive key search).
#   - Provides a higher level of security than Level 2.
#
# Level 4:
#   - Equivalent to the security strength of SHA-384 or SHA3-384 (collision resistance).
#   - Represents a very high level of security.
#
# Level 5:
#   - Equivalent to the security strength of AES-256 (exhaustive key search).
#   - The highest security level defined under the NIST PQC framework.
#
# 🔗 Source: https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria)


ALGORITHM_SECURITY_LEVELS = {
    # TripleDES and aliases
    'tripledes':        {'classical': 112, 'nist_qsl': 0},
    '3des':             {'classical': 112, 'nist_qsl': 0},
    'des3':             {'classical': 112, 'nist_qsl': 0},
    'des':              {'classical': 56,  'nist_qsl': 0},
    'desede':           {'classical': 112, 'nist_qsl': 0},

    # AES family
    'aes-128':          {'classical': 128, 'nist_qsl': 1},
    'aes-192':          {'classical': 192, 'nist_qsl': 3},
    'aes-256':          {'classical': 256, 'nist_qsl': 5},

    # Stream and block ciphers
    'arc4':             {'classical': 40,  'nist_qsl': 0},  # weak, legacy
    'camellia':         {'classical': 128, 'nist_qsl': 0},
    'cast5':            {'classical': 112, 'nist_qsl': 0},
    'chacha20':         {'classical': 256, 'nist_qsl': 0},
    'chacha20poly1305': {'classical': 256, 'nist_qsl': 0},
    'rijndael':         {'classical': 256, 'nist_qsl': 0},  # AES variant
    'rc2':              {'classical': 64,  'nist_qsl': 0},
    'seed':             {'classical': 128, 'nist_qsl': 0},
    'idea':             {'classical': 128, 'nist_qsl': 0},
    'sm4':              {'classical': 128, 'nist_qsl': 0},

   # Hashes
    'md5':               {'classical': 64,  'nist_qsl': 0},   # Broken (collision resistance)
    'hmac-md5':          {'classical': 64,  'nist_qsl': 0},   # Also broken, not secure
    'sha1':              {'classical': 80,  'nist_qsl': 0},   # Deprecated by NIST
    'sha224':            {'classical': 112, 'nist_qsl': 0},
    'sha256':            {'classical': 128, 'nist_qsl': 1},
    'sha384':            {'classical': 192, 'nist_qsl': 3},
    'sha512':            {'classical': 256, 'nist_qsl': 5},
    'sha512-224':        {'classical': 112, 'nist_qsl': 0},
    'sha512-256':        {'classical': 128, 'nist_qsl': 1},
    'sha3224':           {'classical': 112, 'nist_qsl': 0},
    'sha3256':           {'classical': 128, 'nist_qsl': 1},
    'sha3384':           {'classical': 192, 'nist_qsl': 3},
    'sha3512':           {'classical': 256, 'nist_qsl': 5},
    'sha3-224':          {'classical': 112, 'nist_qsl': 0},
    'sha3-256':          {'classical': 128, 'nist_qsl': 1},
    'sha3-384':          {'classical': 192, 'nist_qsl': 3},
    'sha3-512':          {'classical': 256, 'nist_qsl': 5},
    'shake':             {'classical': 256, 'nist_qsl': 5},   # Generic alias for XOF (usually shake256)
    'shake128':          {'classical': 128, 'nist_qsl': 1},   # XOF w/ 128-bit security
    'shake256':          {'classical': 256, 'nist_qsl': 5},
    'blake2s':           {'classical': 128, 'nist_qsl': 0},
    'blake2b':           {'classical': 256, 'nist_qsl': 0},
    'sm3':               {'classical': 128, 'nist_qsl': 0},   # Chinese hash standard


    # Asymmetric algorithms
    'rsa-2048':         {'classical': 112, 'nist_qsl': 0},
    'rsa-3072':         {'classical': 128, 'nist_qsl': 0},
    'rsa-4096':         {'classical': 152, 'nist_qsl': 0},
    'rsa':              {'classical': 112, 'nist_qsl': 0},  # defaulting to RSA-2048
    'dsa':              {'classical': 112, 'nist_qsl': 0},
    'pss':              {'classical': 112, 'nist_qsl': 0},  # depends on RSA key size

    # ECC and curves
    'ecdsa':            {'classical': 128, 'nist_qsl': 0},  # defaulting to P-256
    'eddsa':            {'classical': 128, 'nist_qsl': 0},  # ed25519 classically ~128
    'secp192r1':        {'classical': 96,  'nist_qsl': 0},
    'secp224r1':        {'classical': 112, 'nist_qsl': 0},
    'secp256k1':        {'classical': 128, 'nist_qsl': 0},
    'secp256r1':        {'classical': 128, 'nist_qsl': 0},
    'secp384r1':        {'classical': 192, 'nist_qsl': 0},
    'secp521r1':        {'classical': 256, 'nist_qsl': 0},

    'sect163k1':        {'classical': 80,  'nist_qsl': 0},
    'sect163r2':        {'classical': 80,  'nist_qsl': 0},
    'sect233k1':        {'classical': 112, 'nist_qsl': 0},
    'sect233r1':        {'classical': 112, 'nist_qsl': 0},
    'sect283k1':        {'classical': 128, 'nist_qsl': 0},
    'sect283r1':        {'classical': 128, 'nist_qsl': 0},
    'sect409k1':        {'classical': 192, 'nist_qsl': 0},
    'sect409r1':        {'classical': 192, 'nist_qsl': 0},
    'sect571k1':        {'classical': 256, 'nist_qsl': 0},
    'sect571r1':        {'classical': 256, 'nist_qsl': 0},

    'brainpoolp256r1':  {'classical': 128, 'nist_qsl': 0},
    'brainpoolp384r1':  {'classical': 192, 'nist_qsl': 0},
    'brainpoolp512r1':  {'classical': 256, 'nist_qsl': 0},

    # Key Derivation & Auth
    'hkdf':             {'classical': 128, 'nist_qsl': 0},
    'hkdfexpand':       {'classical': 128, 'nist_qsl': 0},
    'pbkdf2hmac':       {'classical': 128, 'nist_qsl': 0},
    'concatkdfhash':    {'classical': 128, 'nist_qsl': 0},
    'concatkdfhmac':    {'classical': 128, 'nist_qsl': 0},
    'x963kdf':          {'classical': 128, 'nist_qsl': 0},
    'kbkdfcmac':        {'classical': 128, 'nist_qsl': 0},
    'kbkdfhmac':        {'classical': 128, 'nist_qsl': 0},

    # Other
    'scrypt':           {'classical': 128, 'nist_qsl': 0},  # strength depends on params
    'fernet':           {'classical': 128, 'nist_qsl': 0},  # based on AES-128
    'diffiehellman':    {'classical': 112, 'nist_qsl': 0},  # based on DH-2048
    'dh':               {'classical': 112, 'nist_qsl': 0},
}




_ALGORITHM_REGEX = re.compile(
    f"{'|'.join(lib_utils.get_algorithms())}", flags=re.IGNORECASE)
key_lengths = [str(k) for k in lib_utils.get_key_lengths()]
pattern = r"(?<!\d)(" + "|".join(key_lengths) + r")(?!\d)"
_KEY_LENGTH_REGEX = _KEY_LENGTH_REGEX = re.compile(pattern)

'''_KEY_LENGTH_REGEX = re.compile(
    r'(?:key_?size\s*=\s*(\d+)|generate_private_key\([^)]*key_?size\s*=\s*(\d+)|generate\((\d+)|urandom\((\d+)|[\-_](\d+)(?:\)|[\-_]|$))',
    flags=re.IGNORECASE
)'''


def get_algorithm(code_snippet):
    match = _ALGORITHM_REGEX.search(code_snippet)
    if match:
        algorithm = match.group().upper()
        # return full algorithm name if algorithm is aliased e.g. diffiehellman instead of dh
        return lib_utils.get_algorithms().get(algorithm) or algorithm
    return 'unknown'


def get_detection_context(physical_location):
    file_path = physical_location['artifactLocation']['uri']
    if context_region := physical_location.get('contextRegion'):
        line_numbers = list(
            range(context_region['startLine'], context_region['endLine'] + 1))
        lines = ' '.join([str(s) for s in line_numbers])
        code_snippet = context_region.get('snippet').get('text')

        occurance = [Occurrence(
            location=file_path, line=lines, additional_context=code_snippet)]
        method = [Method(technique=AnalysisTechnique.OTHER,
                         confidence=0.8, value="other")]
        # occurance = [Occurrence(field=IdentityFieldType.Name, confidence=0.8, concludedValue="sammple")]
        identity = [Identity(field=IdentityFieldType.NAME, confidence=0.8,
                             concluded_value="sammple", methods=method, tools=["codeql"])]
        stackframe = [StackFrame(package="java", module="module", function="function", parameters=[
                                 "param1", "param2"], line=10, column=30, full_filename=file_path)]
        callstack = CallStack(frames=stackframe)
        copyright = Copyright(text="(c) 2023")
        from cyclonedx.model.license import DisjunctiveLicense
        license = DisjunctiveLicense(id="MIT")
        # return ComponentEvidence(occurrences=occurance,callstack=callstack,identity=identity,licenses=[license],copyright=[copyright])
        # return ComponentEvidence(occurrences=occurance,callstack=callstack,identity=identity,licenses=[license])
        # return ComponentEvidence(occurrences=occurance,callstack=callstack,identity=identity)
        return ComponentEvidence(occurrences=occurance)
        #return ComponentEvidence(identity=identity)


'''def get_key_size(code_snippet):
    match = _KEY_LENGTH_REGEX.search(code_snippet)
    if match:
        # Return first non-None group - handles all capture groups
        return next((g for g in match.groups() if g is not None), None)
    return None'''
def get_key_size(code_snippet):
    match = _KEY_LENGTH_REGEX.search(code_snippet)
    if match:
        return _KEY_LENGTH_REGEX.sub('\\1', match.group())

def string_to_integer_array_set(s):
    # Split the string on whitespace
    number_strings = s.split()
    # Convert each number string into an integer
    integer_array = [int(num) for num in number_strings]
    return set(integer_array)

def string_to_integer_array(s):
    # Split the string on whitespace
    number_strings = s.split()
    # Convert each number string into an integer
    integer_array = [int(num) for num in number_strings]
    return integer_array

def union_to_string(union_set):
    # Convert the set to a string with whitespace separation
    result_string = ' '.join(map(str, union_set))
    
    return result_string

def is_existing_detection_context_match(component, new_context):
    for context in component.evidence.occurrences:
        if context.location == new_context.location and string_to_integer_array_set(context.line).intersection(string_to_integer_array_set(new_context.line)):
            return context


def merge_code_snippets(dc1, dc2):
    first = (dc1 if min(string_to_integer_array(dc1.line)) < min(
        string_to_integer_array(dc2.line)) else dc2).additional_context
    second = (dc1 if max(string_to_integer_array(dc1.line)) > max(
        string_to_integer_array(dc2.line)) else dc2).additional_context

    match = SequenceMatcher(None, first, second).find_longest_match()
    return f'{first[:match.a]}{second[:match.size]}{second[match.size:]}'


def extract_precise_snippet(snippet, region):
    """Extract precise code snippet based on region information."""
    line_start = region['startLine']
    line_end = region.get('endLine')
    line_start_col = region.get('startColumn', 1)
    line_end_col = region['endColumn']

    # Split snippet into lines and remove empty first line if exists
    array_of_lines = snippet.strip().split('\n')
    
    # Convert 1-based line numbers to 0-based array indices
    line_start_idx = line_start - 1 if line_start > 0 else 0
    
    # Handle single line case
    if not line_end or line_end == line_start:
        if 0 <= line_start_idx < len(array_of_lines):
            return array_of_lines[line_start_idx][line_start_col - 1:line_end_col]
        return ""
    
    # Handle multi-line case
    if line_start_idx < len(array_of_lines):
        actual_lines = array_of_lines[line_start_idx:line_end]
        if actual_lines:
            if line_start_col > 1:
                actual_lines[0] = actual_lines[0][line_start_col - 1:]
            if len(actual_lines) > 0:
                actual_lines[-1] = actual_lines[-1][:line_end_col]
            return '\n'.join(actual_lines)
    return ""

def is_existing_component_overlap(cbom, component, asset_type):
    """Generic function to check for existing component overlap"""
    components = (c for c in cbom.components if c.crypto_properties.asset_type == asset_type)

    if component.evidence:
        for existing_component in components:
            if is_existing_detection_context_match(existing_component, component.evidence.occurrences[0]):
                return existing_component
    return None

def update_existing_component(existing_component, component, properties_field=None):
    """Generic function to update existing component with new data"""
    context = component.evidence.occurrences[0]

    if existing_context := is_existing_detection_context_match(existing_component, context):
        existing_context.additional_context = merge_code_snippets(
            existing_context, context)
        existing_context.line = union_to_string(
            string_to_integer_array_set(existing_context.line).union(
                string_to_integer_array_set(context.line)))

        if properties_field and hasattr(component.crypto_properties, properties_field):
            source_props = getattr(component.crypto_properties, properties_field)
            target_props = getattr(existing_component.crypto_properties, properties_field)
            
            for field in vars(source_props):
                if not getattr(target_props, field):
                    field_value = getattr(source_props, field)
                    setattr(target_props, field, field_value)

        return existing_component



# Normalize input and extract base algorithm name
def normalize_algorithm_name(name: str) -> str:
    """
    Normalize the input algorithm name into a canonical form suitable for lookup.
    Examples: 'SHA_256', 'sha-256', 'AES-128-CBC' → 'sha256', 'aes'
    """
    name = name.strip().lower()
    name = re.sub(r'[^a-z0-9]+', '-', name)
    
    if 'sha3' in name:
        if '256' in name:
            return 'sha3-256'
        elif '384' in name:
            return 'sha3-384'
        elif '512' in name:
            return 'sha3-512'
    if 'sha-256' in name or 'sha256' in name:
        return 'sha256'
    if 'sha-384' in name or 'sha384' in name:
        return 'sha384'
    if 'sha-512' in name or 'sha512' in name:
        return 'sha512'
    if 'sha-1' in name or 'sha1' in name:
        return 'sha1'
    if 'md5' in name:
        return 'md5'
    if 'blake2b' in name:
        return 'blake2b'
    if 'blake2s' in name:
        return 'blake2s'
    if 'aes' in name:
        return 'aes'
    if 'rsa-oaep' in name:
        return 'rsa-oaep'
    if 'rsa' in name:
        return 'rsa'
    if 'ecdsa' in name:
        return 'ecdsa'
    if 'dsa' in name:
        return 'dsa'
    if 'ed25519' in name:
        return 'ed25519'
    if 'ed448' in name:
        return 'ed448'
    if 'dh' in name:
        return 'dh'
    if 'ecdh' in name:
        return 'ecdh'
    if '3des' in name or 'tripledes' in name:
        return '3des'
    if 'des' in name:
        return 'des'
    if 'hmac' in name:
        # Try extract hash name after hmac
        match = re.match(r'hmac-?([a-z0-9\-]+)', name)
        if match:
            return f'hmac-{match.group(1)}'

    return name


def get_oid_from_name(name: str) -> Optional[str]:
    """
    Return the OID for a given algorithm name. Returns None if not found.
    """
    normalized = normalize_algorithm_name(name)

    # 1. Check custom static map
    if normalized in CUSTOM_OID_MAP:
        return CUSTOM_OID_MAP[normalized]

    # 2. Try from `cryptography` if available
    if hashes:
        try:
            cls = getattr(hashes, normalized.replace('-', '').upper(), None)
            if cls:
                return cls().algorithm_oid.dotted_string
        except Exception:
            pass

    # 3. Try from `asn1crypto` if available
    if DigestAlgorithmId:
        try:
            return DigestAlgorithmId(normalized).dotted
        except Exception:
            pass

    # 4. Try parsing raw dotted OID
    if ObjectIdentifier:
        try:
            oid = ObjectIdentifier(name)
            return oid.dotted
        except Exception:
            pass

    return None

def get_security_levels(alg_name: str) -> dict[str, int]:
    name = get_algorithm(alg_name)
    name=name.lower()
    bits = get_key_size(alg_name)
    name = f"{name}-{bits}" if bits else name
    return ALGORITHM_SECURITY_LEVELS.get(name, {'classical': 0, 'nist_qsl': 0})
