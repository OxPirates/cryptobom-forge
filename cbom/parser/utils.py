import re
from difflib import SequenceMatcher

from cyclonedx.model import Copyright
from cyclonedx.model.component import (AnalysisTechnique, CallStack,
                                       ComponentEvidence, Identity,
                                       IdentityFieldType, Method, Occurrence,
                                       StackFrame)

from cbom import lib_utils

_ALGORITHM_REGEX = re.compile(
    f"{'|'.join(lib_utils.get_algorithms())}", flags=re.IGNORECASE)
_KEY_LENGTH_REGEX = re.compile(
    r'(?:key_?size\s*=\s*(\d+)|generate_private_key\([^)]*key_?size\s*=\s*(\d+)|generate\((\d+)|urandom\((\d+)|[\-_](\d+)(?:\)|[\-_]|$))',
    flags=re.IGNORECASE
)


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


def get_key_size(code_snippet):
    match = _KEY_LENGTH_REGEX.search(code_snippet)
    if match:
        # Return first non-None group - handles all capture groups
        return next((g for g in match.groups() if g is not None), None)
    return None

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
