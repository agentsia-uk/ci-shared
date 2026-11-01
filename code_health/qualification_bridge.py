"""Execute a single policy operation inside the candidate sandbox.

All output is untrusted: only the external controller evaluates it.
"""
import json
import sys

MAX_REQUEST_BYTES = 64 * 1024


def observe(request, policy):
    if (not isinstance(request, dict) or set(request) != {'schemaVersion', 'caseId', 'operation', 'arguments'} or
            type(request['schemaVersion']) is not int or request['schemaVersion'] != 1 or
            not isinstance(request['caseId'], str) or not isinstance(request['arguments'], dict)):
        raise ValueError('invalid qualification request')
    operation, args = request['operation'], request['arguments']
    try:
        if operation == 'validate-config' and set(args) == {'config'}:
            policy.validate_config(args['config'])
            value = None
        elif operation == 'validate-transition' and set(args) == {'base', 'head', 'upgrade'}:
            policy.validate_transition(args['base'], args['head'], upgrade=args['upgrade'])
            value = None
        elif operation == 'validate-language-coverage' and set(args) == {'files', 'areas'}:
            policy.validate_language_coverage(args['files'], args['areas'])
            value = None
        elif operation == 'compare' and set(args) == {'baseStatus', 'baseState', 'headStatus', 'headState', 'touched', 'renames', 'language'}:
            value = policy.compare(args['baseStatus'], args['baseState'], args['headStatus'], args['headState'],
                                   set(args['touched']), args['renames'], args['language'])
        else:
            raise RuntimeError('unknown qualification operation')
    except ValueError:
        return {'schemaVersion': 1, 'caseId': request['caseId'], 'outcome': 'rejected', 'value': None}
    return {'schemaVersion': 1, 'caseId': request['caseId'], 'outcome': 'returned', 'value': value}


def main():
    data = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError('qualification request exceeds size limit')
    request = json.loads(data)
    sys.path.insert(0, '/candidate')
    from code_health import cli as policy
    response = observe(request, policy)
    sys.stdout.write(json.dumps(response, allow_nan=False, separators=(',', ':')) + '\n')


if __name__ == '__main__':
    main()
