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
    f"\\D({'|'.join([str(key_length) for key_length in lib_utils.get_key_lengths()])})\\D")


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
                             concludedValue="sammple", methods=method, tools=["codeql"])]
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
        return _KEY_LENGTH_REGEX.sub('\\1', match.group())


def is_existing_detection_context_match(component, new_context):
    for context in component.evidence.occurrences:
        if context.location == new_context.location and map(int, context.line.split()).intersection(map(int, new_context.line.split())):
            return context


def merge_code_snippets(dc1, dc2):
    first = (dc1 if min(map(int, dc1.line.split())) < min(
        map(int, dc2.line.split())) else dc2).additional_context
    second = (dc1 if max(map(int, dc1.line.split())) > max(
        map(int, dc2.line.split())) else dc2).additional_context

    match = SequenceMatcher(None, first, second).find_longest_match()
    return f'{first[:match.a]}{second[:match.size]}{second[match.size:]}'


def extract_precise_snippet(snippet, region):
    line_start = region['startLine']
    line_end = region.get('endLine')
    line_start_col = region.get('startColumn', 1)
    line_end_col = region['endColumn']

    match line_start:
        case 1:
            array_of_lines = snippet.split('\n')
        case 2:
            array_of_lines = snippet.split('\n')[1:]
        case _:
            array_of_lines = snippet.split('\n')[2:]

    if not line_end:
        actual_line = array_of_lines[0]
        return actual_line[line_start_col - 1:line_end_col]
    else:
        end_line_index = (line_end - line_start)
        actual_lines = array_of_lines[:end_line_index + 1]
        actual_lines[0] = actual_lines[0][line_start_col - 1:]
        actual_lines[-1] = actual_lines[-1][:line_end_col]
        return '\n'.join(actual_lines)
