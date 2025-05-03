import json
import pathlib
import re
import traceback

import click
from click import Path
from cyclonedx.builder.this import this_component as cdx_lib_component
from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model.bom import Bom, Tool
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output.json import JsonV1Dot6

from cbom import __version__
from cbom.cryptocheck import cryptocheck
from cbom.parser import algorithm


@click.group(context_settings={
    'max_content_width': 120,
    'show_default': True
})
@click.version_option(__version__, '--version', '-v')
def cryptobom():
    """\b
                               _           _                                 __ \b
                              | |         | |                               / _| \b
      ___  _ __  _   _  _ __  | |_   ___  | |__    ___   _ __ ___          | |_   ___   _ __   __ _   ___ \b
     / __|| '__|| | | || '_ \ | __| / _ \ | '_ \  / _ \ | '_ ` _ \  ______ |  _| / _ \ | '__| / _` | / _ \ \b
    | (__ | |   | |_| || |_) || |_ | (_) || |_) || (_) || | | | | ||______|| |  | (_) || |   | (_| ||  __/ \b
     \___||_|    \__, || .__/  \__| \___/ |_.__/  \___/ |_| |_| |_|        |_|   \___/ |_|    \__, | \___| \b
                  __/ || |                                                                     __/ | \b
                 |___/ |_|                                                                    |___/

    Welcome to cryptobom-forge!

    This script is intended to be used in conjunction with the SARIF output from the CodeQL cryptography experimental
    queries.

    You can use this script to generate a cryptographic bill of materials (CBOM) for a repository, and analyse your
    cryptographic inventory for weak and non-pqc-safe cryptography.
    """


@cryptobom.command(context_settings={
    'default_map': {
        'application_name': 'root',
        'cryptocheck_output_file': 'cryptocheck.sarif'
    }
})
@click.argument('path', type=Path(exists=True, path_type=pathlib.Path), required=True)
@click.option('--application-name', '-n', help='Root application name')
@click.option('--cryptocheck', '-cc', 'enable_cryptocheck', is_flag=True, help='Enable crypto vulnerability scanning')
@click.option('--exclude', '-e', 'exclusion_pattern', metavar='REGEX', help='Exclude CodeQL findings in file paths that match <REGEX>')
@click.option('--output-file', '-o', help='CBOM output file')
@click.option('--rules-file', '-r', type=Path(exists=True, path_type=pathlib.Path), help='Custom ruleset for cryptocheck analysis')
@click.option('--cryptocheck-output-file', help='Cryptocheck analysis output file')
def generate(path, application_name, enable_cryptocheck, exclusion_pattern, output_file, rules_file, cryptocheck_output_file):
    """Generate a CBOM from CodeQL SARIF output."""
    cbom = Bom()
    lc_factory = LicenseFactory()
    cbom.metadata.tools.components.add(cdx_lib_component())
    cbom.metadata.tools.components.add(Component(
        name='gs-product-cbom-generator',
        type=ComponentType.APPLICATION,
    ))

    cbom.metadata.component = root_component = Component(
        name=application_name,
        type=ComponentType.APPLICATION,
        licenses=[lc_factory.make_from_string('MIT')],
        bom_ref='myApp',
    )

    if exclusion_pattern:
        exclusion_pattern = re.compile(exclusion_pattern)

    if path.is_file():
        _process_file(cbom, path, exclusion_pattern=exclusion_pattern)
    else:
        for file_path in [*list(path.glob('*.sarif')), *list(path.glob('*.json'))]:
            _process_file(cbom, file_path, exclusion_pattern=exclusion_pattern)

    if enable_cryptocheck:
        cryptocheck_output = cryptocheck.validate_cbom(cbom, rules_file)
        with open(cryptocheck_output_file, 'w') as file:
            click.echo(message=json.dumps(cryptocheck_output,
                       indent=4, sort_keys=True), file=file)

    #print(json.dumps(cbom, indent=4, sort_keys=True))
 
    '''for component in cbom.components:
        if component.type == ComponentType.CRYPTOGRAPHIC_ASSET:
            click.echo(f"bom-ref: {component.bom_ref}")
            click.echo(f"Component: {component.name}")
            click.echo(f"  Type: {component.type}")
            click.echo(f"  name: {component.name}")
            click.echo(f"  Crypto Properties:")
            click.echo(f"    Asset Type: {component.crypto_properties.asset_type}")
            click.echo(f"    Algorithm Properties: {component.crypto_properties.algorithm_properties}")
            click.echo(f"    Certificate Properties: {component.crypto_properties.certificate_properties}")
            click.echo(f"    Related Crypto Material Properties: {component.crypto_properties.related_crypto_material_properties}")
            #click.echo(f"    Evidence: {component.evidence.occurrences[0]}")
            #click.echo(f"    Evidence: {component.evidence.occurrences[0].additional_context}")'''

    cbom = json.loads(JsonV1Dot6(cbom).output_as_string())
    if output_file:
        with open(output_file, 'w') as file:
            click.echo(message=json.dumps(cbom, indent=4), file=file)
    else:
        click.echo(message=json.dumps(cbom, indent=4))


def start():
    try:
        cryptobom()
    except Exception as e:
        click.secho(f"Error: {str(e)}", fg='red')
        click.secho("\nTraceback:", fg='red')
        click.secho(traceback.format_exc(), fg='red')


def _process_file(cbom, query_file, exclusion_pattern=None):
    with open(query_file) as query_output:
        query_output = json.load(query_output)['runs'][0]

        driver = query_output['tool']['driver']
        tool = Component(
            type=ComponentType.LIBRARY,
            # vendor=driver['organization'],
            name=driver['name'],
            version=driver.get('version', driver.get(
                'semanticVersion'))  # fixme: sarif misaligned
        )
        # ToolRepository uses add() method
        cbom.metadata.tools.components.add(tool)

        for result in query_output['results']:
            result = result['locations'][0]['physicalLocation']
            if not exclusion_pattern or not exclusion_pattern.fullmatch(result['artifactLocation']['uri']):
                algorithm.parse_algorithm(cbom, result)


if __name__ == '__main__':
    start()
