import copy
import sys
import textwrap
from argparse import ArgumentParser
from itertools import groupby
from operator import attrgetter
from pathlib import Path

from .__version__ import __version__

KNOWN_SETTINGS = []


class SettingMeta(type):
    def __new__(mcs, name, bases, namespace):
        parents = [b for b in bases if isinstance(b, SettingMeta)]
        if not parents:
            return super().__new__(mcs, name, bases, namespace)

        namespace['_order'] = len(KNOWN_SETTINGS)
        validator = namespace['validator']
        if not isinstance(validator, staticmethod):
            namespace['validator'] = staticmethod(validator)

        new_class = super().__new__(mcs, name, bases, namespace)
        new_class.fmt_desc(namespace.get('desc', ''))
        KNOWN_SETTINGS.append(new_class)
        return new_class

    def fmt_desc(cls, desc):
        desc = textwrap.dedent(desc).strip()
        setattr(cls, 'desc', desc)
        setattr(cls, 'short', desc.splitlines()[0])


class Setting(metaclass=SettingMeta):
    name = None
    section = None
    cli = None
    validator = None
    type = str
    required = False
    meta = None
    action = 'store'
    default = None
    short = None
    desc = None
    nargs = None
    const = None

    _value = None
    _order = -1

    def __init__(self):
        if self.default is not None:
            self.value = self.default

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        if not callable(self.validator):
            raise TypeError(f'Invalid validator: {self.name}')
        self._value = self.validator(value)

    @property
    def order(self):
        return self._order

    def add_option(self, parser: ArgumentParser):
        if not self.cli:
            return
        args = tuple(self.cli)

        help_txt = self.short
        if self.default is not None:
            help_txt += f' (default: {self.default})'

        kwargs = {
            'dest': self.name,
            'action': self.action,
            'type': self.type,
            'default': None,
            'help': help_txt,
        }

        if self.meta is not None:
            kwargs['metavar'] = self.meta

        if kwargs['action'] != 'store':
            kwargs.pop('type')

        if self.nargs is not None:
            kwargs['nargs'] = self.nargs

        if self.const is not None:
            kwargs['const'] = self.const

        parser.add_argument(*args, **kwargs)

    def copy(self):
        return copy.copy(self)

    def __lt__(self, other):
        return self.section == other.section and self.order < other.order

    def __repr__(self):
        cls = self.__class__
        return f'<{cls.__module__}.{cls.__name__} object at {id(self)} with value {self._value!r}>'


def validate_bool(val):
    if not isinstance(val, bool):
        raise TypeError(f'Value is not a bool: {val!r}')
    return val


def validate_dict(val):
    if not isinstance(val, dict):
        raise TypeError(f'Value is not a dictionary: {val!r}')
    return val


def validate_min(n):
    def _validate_min(val):
        if val < n:
            raise ValueError(f'Value must be greater than or equal to {n}: {val}')
        return val
    return _validate_min


def validate_max(n):
    def _validate_max(val):
        if val > n:
            raise ValueError(f'Value must be less than or equal to {n}: {val}')
        return val
    return _validate_max


def validate_gt(n):
    def _validate_gt(val):
        if val <= n:
            raise ValueError(f'Value must be greater than {n}: {val}')
        return val
    return _validate_gt


def validate_lt(n):
    def _validate_lt(val):
        if val >= n:
            raise ValueError(f'Value must be less than {n}: {val}')
        return val
    return _validate_lt


def validate_int(val):
    if not isinstance(val, int):
        raise TypeError(f'Value is not a int: {val!r}')
    return val


def validate_float(val):
    if not isinstance(val, (int, float)):
        raise TypeError(f'Value is not a float: {val!r}')
    return float(val)


def validate_string(val):
    if not isinstance(val, str):
        raise TypeError(f'Not a string: {val!r}')
    return val


def validate_not_empty_string(val):
    val = validate_string(val)
    if not val:
        raise ValueError(f'Empty string: {val!r}')
    return val


def validate_path(val):
    val = validate_not_empty_string(val)
    return Path(val)


def validate_cookie(val):
    cookies = {}
    if isinstance(val, dict):
        for k, v in val.items():
            k = str(k).strip()
            v = str(v).strip()
            cookies[k] = v
    elif isinstance(val, list):
        val = [validate_not_empty_string(c) for c in val]
        for c in val:
            i = c.find('=')
            if i < 0:
                raise ValueError(f'Invalid cookie format: {c}')
            k = c[:i].strip()
            v = c[i+1:].strip()
            cookies[k] = v
    else:
        raise TypeError(f'Value must be either dict or list of string: {val}')

    return cookies


def validate_header(val):
    headers = {}
    if isinstance(val, dict):
        for k, v in val.items():
            k = str(k).strip()
            v = str(v).strip()
            headers[k] = v
    elif isinstance(val, list):
        val = [validate_not_empty_string(c) for c in val]
        for h in val:
            i = h.find(':')
            if i < 0:
                raise ValueError(f'Invalid header format: {h}')
            k = h[:i].strip()
            v = h[i+1:].strip()
            headers[k] = v
    else:
        raise TypeError(f'Value must be either dict or list of string: {val}')

    return headers


class ConfigFile(Setting):
    name = 'config'
    section = 'Config File'
    cli = ['-c', '--config']
    validator = validate_path
    meta = 'CONFIG'
    default = './m3u8-dl.conf.py'
    desc = """\
        m3u8-dl config file.

        A string of the form ``PATH``.

        By default, a file named `m3u8-dl.conf.py` will be read from the same
        directory where application is being run.
        """


class RequestCookie(Setting):
    name = 'cookie'
    section = 'HTTP'
    cli = ['-b', '--cookie']
    validator = validate_cookie
    meta = '<cookie>'
    action = 'append'
    default = {}
    desc = """\
        Pass the data to the HTTP server in the Cookie header.
        The cookie should be in the format "NAME=VALUE".
        This option can be used multiple times to add multiple cookies.
        """


class RequestHeader(Setting):
    name = 'header'
    section = 'HTTP'
    cli = ['-H', '--header']
    validator = validate_header
    meta = '<header>'
    action = 'append'
    default = {}
    desc = """\
        Extra header to include in the request when sending HTTP to a server.
        Note that if you should add a custom header that has the same name as one of
        the internal ones program would use, your externally set header will be used
        instead of the internal one.
        The header should be in the format "HEADER: VALUE".
        This option can be used multiple times to add multiple headers.
        """


class MaxRetry(Setting):
    name = 'retry'
    section = 'HTTP'
    cli = ['--retry']
    type = int
    meta = '<num>'
    default = 3
    desc = """\
        The number of times before giving up when transient error is returned.
        """

    @staticmethod
    def validator(val):
        val = validate_int(val)
        val = validate_min(1)(val)
        return val


class RequestTimeout(Setting):
    name = 'timeout'
    section = 'HTTP'
    cli = ['--timeout']
    type = float
    meta = '<seconds>'
    default = 5
    desc = """\
        Maximum time in seconds for connect and read timeouts.
        """

    @staticmethod
    def validator(val):
        val = validate_float(val)
        val = validate_gt(0)(val)
        return val


class URL(Setting):
    name = 'url'
    section = 'M3U8'
    cli = ['--url']
    validator = validate_not_empty_string
    required = True
    meta = '<url>'
    desc = """\
        Specify a M3U8 URL to fetch.
        """


class Interval(Setting):
    name = 'interval'
    section = 'M3U8'
    cli = ['--interval']
    type = float
    meta = '<seconds>'
    default = 0
    desc = """\
        M3U8 index file request interval in seconds.
        If set to 0, #EXT-X-TARGETDURATION is used instead.
        """

    @staticmethod
    def validator(val):
        val = validate_float(val)
        val = validate_min(0)(val)
        return val


class NoDecrypt(Setting):
    name = 'no_decrypt'
    section = 'M3U8'
    cli = ['--no-decrypt']
    validator = validate_bool
    action = 'store_true'
    default = False
    desc = """\
        Save segments without decryption even if encrypted.
        """


class OutputPath(Setting):
    name = 'output_path'
    section = 'M3U8'
    cli = ['-o', '--output']
    validator = validate_path
    meta = '<folder>'
    default = './outputs'
    desc = """\
        Directory to write transport stream chunks in.
        """


class NumWorkers(Setting):
    name = 'n_workers'
    section = 'M3U8'
    cli = ['-w', '--workers']
    meta = '<num>'
    default = 4
    desc = """\
        The number of workers when downloading segments.
        """

    @staticmethod
    def validator(val):
        val = validate_int(val)
        val = validate_min(1)(val)
        return val


class LogFile(Setting):
    name = 'logfile'
    section = 'Logging'
    cli = ['--log-file']
    meta = '<file>'
    validator = validate_path
    desc = """\
        The log file to write to.
        
        The log level of this file is always ``'DEBUG'``. 
        """


class LogLevel(Setting):
    name = 'loglevel'
    section = 'Logging'
    cli = ['--log-level']
    meta = '<level>'
    default = 'INFO'
    desc = """\
        The granularity of console log outputs.
        
        Valid level names are:
        
        * ``'DEBUG'``
        * ``'INFO'``
        * ``'WARNING'``
        * ``'ERROR'``
        * ``'CRITICAL'``
        """

    @staticmethod
    def validator(val):
        val = validate_not_empty_string(val)
        if val not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            raise ValueError(f'Unknown log level: {val}')
        return val


class PrintConfig(Setting):
    name = 'print_config'
    section = 'Debugging'
    cli = ['--print-config']
    validator = validate_bool
    action = 'store_true'
    default = False
    desc = """\
        Print the configuration settings as fully resolved and exit.
        """


def get_default_config_file():
    config_path = Path.cwd() / ConfigFile.default
    if config_path.is_file():
        return config_path
    return None


def make_settings(ignore=None):
    settings = {}
    ignore = ignore or ()
    for s in KNOWN_SETTINGS:
        setting = s()
        if setting.name in ignore:
            continue
        settings[setting.name] = setting.copy()
    return settings


class Config:
    def __init__(self, usage=None, prog=None):
        self.settings: dict[str, Setting] = make_settings()
        self.usage = usage
        self.prog = prog or Path(sys.argv[0]).name

    def __str__(self):
        lines = []
        kmax = max(len(k) for k in self.settings)
        settings = sorted(self.settings.values())
        for section, group in groupby(settings, attrgetter('section')):
            lines.append(f'[{section}]')
            for s in group:
                v = s.value
                if callable(v):
                    v = f'<{v.__qualname__}()>'
                else:
                    v = repr(v)
                lines.append(f'  {s.name:{kmax}} = {v}')
        return '\n'.join(lines)

    def __getattr__(self, name):
        if name not in self.settings:
            raise AttributeError(f'No configuration setting for: {name}')
        return self.settings[name].value

    def __setattr__(self, name, value):
        if name != 'settings' and name in self.settings:
            raise AttributeError('Invalid access!')
        super().__setattr__(name, value)

    def set(self, name, value):
        if name not in self.settings:
            raise AttributeError(f'No configuration setting for: {name}')
        try:
            self.settings[name].value = value
        except Exception:
            print(f'Invalid value for {name!r}: {value!r}', file=sys.stderr)
            sys.stderr.flush()
            raise

    def parser(self):
        kwargs = {
            'usage': self.usage,
            'prog': self.prog,
        }
        parser = ArgumentParser(**kwargs)
        parser.add_argument('-v', '--version',
                            action='version', version=f'%(prog)s (version {__version__})')

        keys = sorted(self.settings, key=self.settings.__getitem__)
        for k in keys:
            self.settings[k].add_option(parser)

        return parser
