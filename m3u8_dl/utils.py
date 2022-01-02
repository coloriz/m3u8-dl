from requests_toolbelt.utils.dump import dump_all


def format_size(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return f'{num:.1f} {unit}{suffix}'
        num /= 1024.0
    return f'{num:.1f} Yi{suffix}'


def hex_string_to_bytes(s: str):
    return bytes.fromhex(s[2:] if s.startswith('0x') else s)


def dump_response(response):
    return dump_all(response, b'> ', b'< ').decode('utf-8')
