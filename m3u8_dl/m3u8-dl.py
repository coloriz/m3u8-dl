import json
import logging
from argparse import ArgumentParser, FileType
from pathlib import Path
from queue import Queue, Empty
from threading import Thread, Event, get_ident
from time import sleep
from typing import Dict, List
from urllib.parse import urlparse

import coloredlogs
import m3u8
from Crypto.Cipher import AES
from easydict import EasyDict
from requests import HTTPError, Session
from requests.adapters import HTTPAdapter
from requests_toolbelt.utils import dump
from urllib3 import Retry

PROG = 'm3u8_downloader'
__author__ = 'coloriz'
__license__ = 'MIT'
__version__ = '1.0.0'

logger = logging.getLogger(PROG)
coloredlogs.install(
    logging.DEBUG,
    logger=logger,
    fmt='%(asctime)s %(name)s @ %(threadName)s: [%(levelname)s] %(message)s')


class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.timeout = None
        if 'timeout' in kwargs:
            self.timeout = kwargs['timeout']
            del kwargs['timeout']
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        timeout = kwargs.get('timeout')
        if timeout is None:
            kwargs['timeout'] = self.timeout
        return super().send(request, **kwargs)


def format_size(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return f'{num:.1f} {unit}{suffix}'
        num /= 1024.0
    return f'{num:.1f} Yi{suffix}'


def hex_string_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith('0x') else s)


def worker(terminated: Event, jobs: Queue, s: Session, output: Path):
    logger.debug(f'New thread started (id=0x{get_ident():x})')

    last_key_uri = ''
    last_key = hex_string_to_bytes('00' * 16)
    last_iv = hex_string_to_bytes('00' * 16)

    cipher = AES.new(last_key, AES.MODE_CBC, last_iv)

    while not terminated.is_set():
        # Get new segment
        try:
            segment = jobs.get(block=True, timeout=1)
            r = s.get(segment.absolute_uri)
            r.raise_for_status()
            stream = r.content
            # Check encryption
            if segment.key:
                # Update cipher if key or iv changed
                key_uri = segment.key.absolute_uri
                iv = hex_string_to_bytes(segment.key.iv)
                changed = False
                if key_uri != last_key_uri:
                    changed = True
                    r = s.get(key_uri)
                    r.raise_for_status()
                    last_key = r.content
                    last_key_uri = key_uri
                    logger.debug(f'AES Key changed: {last_key.hex()} ({last_key_uri})')
                if iv != last_iv:
                    changed = True
                    last_iv = iv
                    logger.debug(f'AES IV changed: {last_iv.hex()}')
                if changed:
                    cipher = AES.new(last_key, AES.MODE_CBC, last_iv)
                # Decrypt
                stream = cipher.decrypt(stream)
        except Empty:  # No new segment
            continue
        except HTTPError as e:
            logger.error(e)
            break

        # Get filename
        # TODO: set filename based on its uri, not its name
        filename = Path(urlparse(segment.uri).path).name
        # Save file to disk
        if not output.is_dir():
            output.mkdir(parents=True, exist_ok=True)
        bytes_written = (output / filename).write_bytes(stream)
        logger.info(f'Downloaded: {filename} ({format_size(bytes_written)})')
        # Indicate this segment is complete
        jobs.task_done()

    logger.debug(f'Thread terminating... (id=0x{get_ident():x})')


def parse_cookies(cookies: List[str]) -> Dict[str, str]:
    cookie_dict = {}
    for c in cookies:
        k, v = c.split('=', 1)
        cookie_dict[k] = v
    return cookie_dict


def parse_headers(headers: List[str]) -> Dict[str, str]:
    header_dict = {}
    for h in headers:
        k, v = h.split(':', 1)
        header_dict[k.strip()] = v.strip()
    return header_dict


if __name__ == '__main__':
    # region Argument parsing
    options = EasyDict({
        'cookie': {
            'parser': parse_cookies,
            'name': ['-b', '--cookie'],
            'action': 'append',
            'type': str,
            'default': {},
            'metavar': '<cookie>',
            'help': '(HTTP) Pass the data to the HTTP server in the Cookie header. '
                    'The cookie should be in the format "NAME=VALUE". '
                    'This option can be used multiple times to add multiple cookies.'
        },
        'header': {
            'parser': parse_headers,
            'name': ['-H', '--header'],
            'action': 'append',
            'type': str,
            'default': {},
            'metavar': '<header>',
            'help': '(HTTP) Extra header to include in the request when sending HTTP to a server. '
                    'Note that if you should add a custom header that has the same name as one of '
                    'the internal ones program would use, your externally set header will be used '
                    'instead of the internal one. '
                    'The header should be in the format "HEADER: VALUE". '
                    'This option can be used multiple times to add multiple headers.'
        },
        'interval': {
            'name': ['--interval'],
            'type': float,
            'metavar': '<seconds>',
            'help': '(m3u8) m3u8 file request interval in seconds. '
                    'If not specified, #EXT-X-TARGETDURATION is used instead.'
        },
        'no_decrypt': {
            'name': ['--no-decrypt'],
            'action': 'store_true',
            'help': 'Save segments without decryption even if encrypted.'
        },
        'output': {
            'name': ['-o', '--output'],
            'type': str,
            'required': True,
            'metavar': '<folder>',
            'help': 'Directory to write transport stream chunks in.'
        },
        'retry': {
            'name': ['--retry'],
            'type': int,
            'default': 3,
            'metavar': '<num>',
            'help': 'The number of times before giving up when transient error is returned.'
        },
        'timeout': {
            'name': ['--timeout'],
            'type': float,
            'default': 5,
            'metavar': '<seconds>',
            'help': 'Maximum time in seconds for connect and read timeouts.'
        },
        'url': {
            'name': ['--url'],
            'type': str,
            'required': True,
            'metavar': '<url>',
            'help': 'Specify a M3U8 URL to fetch.'
        },
        'workers': {
            'name': ['-w', '--workers'],
            'type': int,
            'default': 4,
            'metavar': '<num>',
            'help': 'The number of workers when downloading segments.'
        }
    })
    parser = ArgumentParser(prog=PROG)
    parser.add_argument('-c', '--config', type=FileType('r'), metavar='<file>',
                        help='Specify a JSON-format text file to read program arguments from.')
    parser.add_argument('-l', '--log-path', type=Path, metavar='<file>',
                        help='Full path of the log file.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Increase verbosity level during the operation.')
    parser.add_argument('-V', '--version', action='version', version=f'%(prog)s {__version__}',
                        help='Displays information about this program.')

    # Add options to parser
    for v in options.values():
        # Pass only values that ArgumentParser can understand
        kw = {k: v[k] for k in v if k in ['action', 'type', 'metavar', 'help']}
        # If there is a default value, put it in the help message
        if 'default' in v:
            kw['help'] += f' (default: {v.default})'
        parser.add_argument(*v.name, **kw)

    # Parse command-line arguments
    _opt = parser.parse_args()
    # Adjust verbosity if necessary
    if not _opt.verbose:
        for handler in logger.handlers:
            handler.setLevel(logging.INFO)
    # Log file path
    if _opt.log_path:
        handler = logging.FileHandler(_opt.log_path)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter('%(asctime)s %(name)s @ %(threadName)s: [%(levelname)s] %(message)s'))
        logger.addHandler(handler)

    # 1. Fill options with its default values
    opt = EasyDict()
    for k, v in options.items():
        opt[k] = v.get('default')

    # 2. Process config file before command line arguments
    if _opt.config:
        config = json.load(_opt.config)

        for k in filter(lambda k: k in config, options):
            v = config.pop(k)
            opt[k] = v

        # Check if all keys are processed
        if config:
            logger.warning(f'Following keys are not processed: {list(config)}')

    # 3. Parse command line arguments
    for k, spec in options.items():
        v = getattr(_opt, k)
        # Skip not specified options
        if v is None:
            continue
        # If any defined parser exists, use it
        if digest := spec.get('parser'):
            v = digest(v)
        opt[k] = v

    # Check if required options are set
    for k, v in options.items():
        if v.get('required') and not opt[k]:
            logger.error(f"Option '{k}' is empty!")
            exit(-1)

    # Print options
    logger.info(f'{PROG} options')
    for line in json.dumps(opt, indent=2).splitlines():
        logger.info(line)

    # Notify user if no_decrypt option is set
    if opt.no_decrypt:
        logger.warning('No decrypt option is set!')
    # Change path-strings to Path objects
    opt.output = Path(opt.output)
    # endregion

    # Create an HTTP adapter
    retry_strategy = Retry(total=opt.retry, status_forcelist=[413, 429, 500, 502, 503, 504], backoff_factor=1)
    adapter = TimeoutHTTPAdapter(timeout=opt.timeout, max_retries=retry_strategy)

    # The one and only global session
    s = Session()
    # Mount the new adapter
    s.mount('https://', adapter)
    s.mount('http://', adapter)
    # Update cookies and headers
    s.cookies.update(opt.cookie)
    s.headers.update(opt.header)

    # Job queue
    jobs = Queue()
    done = set()

    # Test url and log req, res
    r = s.get(opt.url)
    logger.debug(f'Initial request/response dump')
    for line in dump.dump_all(r, b'> ', b'< ').decode('utf-8').splitlines():
        logger.debug(line)

    # Parse m3u8 before starting worker threads
    # If something is wrong with this m3u8, it won't go any further.
    playlist = m3u8.loads(r.text, uri=opt.url)
    if not playlist.segments:
        logger.error('No segments!')
        exit(-2)
    # Log media sequence
    media_sequence = playlist.media_sequence
    # Set m3u8 request interval if not set
    if opt.interval is None:
        opt.interval = playlist.target_duration or 2.0  # Fallback value
        logger.info(f'Fetch interval changed to {opt.interval} s')
    # Put segments in jobs queue
    for seg in playlist.segments:
        logger.debug(f'New segment: {seg.uri}')
        if opt.no_decrypt:
            seg.key = None
        jobs.put(seg)
        done.add(seg.uri)

    # Synchronous termination of threads
    terminated = Event()
    # Worker threads
    threads = [Thread(target=worker, name=f'worker-{i}', args=(terminated, jobs, s, opt.output)) for i in range(opt.workers)]
    for t in threads:
        t.start()

    try:
        # Stop when all threads are terminated
        while any(map(lambda t: t.is_alive(), threads)):
            # Is this endlist?
            if playlist.is_endlist:
                logger.info('#EXT-X-ENDLIST detected')
                jobs.join()
                break
            # Sleep
            sleep(opt.interval)
            # Fetch new playlist
            r = s.get(opt.url)
            # Parse m3u8 and put new jobs
            playlist = m3u8.loads(r.text, uri=opt.url)
            # Log latest media_sequence
            if playlist.media_sequence < media_sequence:
                logger.warning(f'#EXT-X-MEDIA-SEQUENCE decreased! ({media_sequence} -> {playlist.media_sequence})')
            media_sequence = playlist.media_sequence
            # Put new segment to job queue.
            for seg in playlist.segments:
                if seg.uri not in done:
                    logger.debug(f'New segment: {seg.uri}')
                    if opt.no_decrypt:
                        seg.key = None
                    jobs.put(seg)
                    done.add(seg.uri)
    except KeyboardInterrupt:
        logger.info('KeyboardInterrupt received. Gracefully quitting...')
    finally:
        terminated.set()
        for t in threads:
            t.join()
