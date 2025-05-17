import re
import uuid

from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (AlgorithmProperties, CryptoAssetType,
                                    CryptoMode, CryptoPadding, CryptoPrimitive,
                                    CryptoProperties)

from cbom import lib_utils
from cbom.parser import certificate, related_crypto_material, utils

_BLOCK_MODE_REGEX = re.compile(
    f"{'|'.join(lib_utils.get_block_modes())}", flags=re.IGNORECASE)
_FUNCTION_REGEX = re.compile(
    f"\\.[A-Z_\\d]*({'|'.join(lib_utils.get_functions())})[A-Z_\\d]*")
_PADDING_REGEX = re.compile(
    f"{'|'.join(lib_utils.get_padding_schemes())}", flags=re.IGNORECASE)


def parse_algorithm(cbom, finding,message):
    crypto_properties = _generate_crypto_component(finding,message)
    if (padding := crypto_properties.algorithm_properties.padding) not in [CryptoPadding.OTHER, CryptoPadding.UNKNOWN]:
        name = f'{crypto_properties.algorithm_properties.parameter_set_identifier}-{padding.value.upper()}'
    else:
        name = crypto_properties.algorithm_properties.parameter_set_identifier
    crypto_properties.oid=utils.get_oid_from_name(name)
    security_level = utils.get_security_levels(name)
    crypto_properties.algorithm_properties.classical_security_level = security_level.get('classical')
    crypto_properties.algorithm_properties.nist_quantum_security_level = security_level.get('nist_qsl')
    algorithm_component = Component(
        bom_ref=f'cryptography:{CryptoAssetType.ALGORITHM}:{uuid.uuid4()}',
        name=name,
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        crypto_properties=crypto_properties,
        evidence=utils.get_detection_context(finding),
    )

    if not (existing_component := _is_existing_component_overlap(cbom, algorithm_component)):
        cbom.components.add(algorithm_component)
        cbom.register_dependency(cbom.metadata.component, depends_on=[
                                 algorithm_component])
    else:
        algorithm_component = _update_existing_component(
            existing_component, algorithm_component)

    if crypto_properties.algorithm_properties.primitive == CryptoPrimitive.PKE:
        code_snippet = finding['contextRegion']['snippet']['text']
        if 'key' in code_snippet.lower():
            private_key_component = related_crypto_material.parse_private_key(
                cbom, finding)
            #print(private_key_component)
            #print(algorithm_component)
            cbom.register_dependency(algorithm_component, depends_on=[
                                     private_key_component]) #algorithm_component

        if 'x509' in code_snippet.lower() or 'x.509' in code_snippet.lower():
            certificate_component = certificate.parse_x509_certificate_details(
                cbom, finding)
            cbom.register_dependency(algorithm_component, depends_on=[
                                     certificate_component]) #


def _generate_crypto_component(finding,message):
    code_snippet = finding['contextRegion']['snippet']['text']
    algorithm = utils.get_algorithm(message)
   
    '''print(algorithm)
    print(code_snippet)
    print(finding['region'])'''
    if algorithm == 'unknown':
        algorithm =  algorithm = utils.get_algorithm(
        utils.extract_precise_snippet(code_snippet, finding['region']))
    if algorithm == 'unknown':
        algorithm = utils.get_algorithm(code_snippet)

    if algorithm == 'FERNET':
        algorithm, key_size, mode = 'AES', '128', CryptoMode.CBC
        primitive = CryptoPrimitive.BLOCK_CIPHER
    else:
        primitive = _infer_primitive(algorithm)
        if 'key' in code_snippet.lower() and primitive != CryptoPrimitive.HASH:
            key_size = utils.get_key_size(code_snippet)
        else:
            key_size = None

        try:
            if primitive == CryptoPrimitive.BLOCK_CIPHER:
                mode = _extract_mode(code_snippet)
                mode = CryptoMode(mode.lower()) if mode else CryptoMode.UNKNOWN
            else:
                mode = None
        except ValueError:
            mode = CryptoMode.OTHER

    try:
        padding = _extract_padding(code_snippet)
        padding = CryptoPadding(
            padding.lower()) if padding else CryptoPadding.UNKNOWN
    except ValueError:
        padding = CryptoPadding.OTHER

    return CryptoProperties(
        asset_type=CryptoAssetType.ALGORITHM,
        algorithm_properties=AlgorithmProperties(
            primitive=primitive,
            parameter_set_identifier=_build_variant(
                algorithm, key_size=key_size, block_mode=mode),
            mode=mode,
            padding=padding,
            crypto_functions=_extract_crypto_functions(code_snippet)
        ),
        # detection_context=[utils.get_detection_context(finding)]
    )


def _build_variant(algorithm, *, key_size=None, block_mode=None):
    variant = algorithm.upper()
    if key_size:
        variant += f'-{key_size}'
    if block_mode and block_mode not in [CryptoMode.OTHER, CryptoMode.UNKNOWN]:
        variant += f'-{block_mode.value.upper()}'
    return variant


def _extract_crypto_functions(code_snippet):
    matches = _FUNCTION_REGEX.findall(''.join(code_snippet.split()))
    matches = [_FUNCTION_REGEX.sub('\\1', m) for m in matches]
    return set(matches)


def _extract_mode(code_snippet):
    match = _BLOCK_MODE_REGEX.search(code_snippet)
    if match:
        return match.group()


def _extract_padding(code_snippet):
    match = _PADDING_REGEX.search(code_snippet)
    if match:
        return match.group()


def _infer_primitive(algorithm, additional_context=None):
    primitive = lib_utils.get_primitive_mapping(algorithm.lower())
    return CryptoPrimitive(primitive)


def _is_existing_component_overlap(cbom, component):
    algorithm_components = (
        c for c in cbom.components if c.crypto_properties.asset_type == CryptoAssetType.ALGORITHM)

    for existing_component in algorithm_components:
        if existing_component.name == component.name:
            return existing_component


def _update_existing_component(existing_component, component):
    new_context = component.evidence.occurrences[0] # crypto_properties.detection_context[0]

    if existing_context := utils.is_existing_detection_context_match(existing_component, new_context):
        existing_context.additional_context = utils.merge_code_snippets(existing_context, new_context)
        existing_context.line = utils.union_to_string(utils.string_to_integer_array_set(existing_context.line).union(
            utils.string_to_integer_array_set(new_context.line)))
        #existing_context.line_numbers = existing_context.line_numbers.union(new_context.line_numbers)
        return existing_component
    else:
        existing_component.crypto_properties.algorithm_properties.crypto_functions.update(component.crypto_properties.algorithm_properties.crypto_functions)
        existing_component.evidence.occurrences.add(new_context)
        return existing_component
