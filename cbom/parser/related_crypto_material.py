import uuid

from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (CryptoAssetType, CryptoProperties,
                                    RelatedCryptoMaterialProperties,
                                    RelatedCryptoMaterialType)

from cbom.parser import utils


def parse_initialization_vector(cbom, finding):
    crypto_properties = _generate_crypto_component(
        finding, RelatedCryptoMaterialType.INITIALIZATION_VECTOR)
    unique_identifier = uuid.uuid4()

    component = Component(
        bom_ref=f'cryptography:iv:{unique_identifier}',
        name=str(unique_identifier),
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        crypto_properties=crypto_properties
    )
    cbom.components.add(component)
    return component


def parse_private_key(cbom, finding):
    print(finding['contextRegion']['snippet']['text']  )
    key_size = utils.get_key_size(finding['contextRegion']['snippet']['text'])
    print(key_size)
    if key_size:
        key_size = int(key_size)

    crypto_properties = _generate_crypto_component(
        finding, RelatedCryptoMaterialType.PRIVATE_KEY, size=key_size)
    unique_identifier = uuid.uuid4()

    component = Component(
        bom_ref=f'cryptography:{CryptoAssetType.RELATED_CRYPTO_MATERIAL}:{unique_identifier}',
        name= str(unique_identifier),
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        crypto_properties=crypto_properties,
        evidence=utils.get_detection_context(finding)
    )
    if not (existing_component := _is_existing_component_overlap(cbom, component)):
        cbom.components.add(component)
    else:
        component = _update_existing_component(existing_component, component)
    return component


def _generate_crypto_component(component, material_type, *, size=None):
    return CryptoProperties(
        asset_type=CryptoAssetType.RELATED_CRYPTO_MATERIAL,
        related_crypto_material_properties=RelatedCryptoMaterialProperties(
            type=material_type,
            size=size
        ),
        #detection_context=[utils.get_detection_context(component)]
    )


def _is_existing_component_overlap(cbom, component):
    return utils.is_existing_component_overlap(cbom, component, CryptoAssetType.RELATED_CRYPTO_MATERIAL)


def _update_existing_component(existing_component, component):
    return utils.update_existing_component(existing_component, component, 'related_crypto_material_properties')
