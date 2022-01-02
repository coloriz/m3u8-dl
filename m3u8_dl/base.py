import importlib.util
import sys
import traceback
from abc import ABC, abstractmethod
from os import PathLike
from pathlib import Path
from typing import Optional

from .config import Config, get_default_config_file
from .errors import ConfigError


class BaseApplication(ABC):
    """
    An application interface for configuring and loading
    the various necessities for any given application.
    """
    def __init__(self, usage=None, prog=None):
        self.usage = usage
        self.cfg: Optional[Config] = None
        self.prog = prog
        self.do_load_config()

    def do_load_config(self):
        try:
            self.load_default_config()
            self.load_config()
        except Exception as e:
            print(f'Error: {e}', file=sys.stderr)
            sys.stderr.flush()
            sys.exit(1)

    def load_default_config(self):
        self.cfg = Config(self.usage, self.prog)

    @abstractmethod
    def load_config(self):
        ...

    def init(self):
        ...

    def main(self):
        ...

    def reload(self):
        self.do_load_config()

    def run(self):
        self.init()
        self.main()


class Application(BaseApplication):
    def load_config_from_filename(self, filename: PathLike) -> None:
        file = Path(filename)
        if not file.is_file():
            raise FileNotFoundError(file)

        if file.suffix not in ('.py', '.pyc'):
            raise ValueError(f'Configuration file should have a valid Python extension.')

        try:
            module_name = '__config__'
            spec = importlib.util.spec_from_file_location(module_name, file)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = mod
            spec.loader.exec_module(mod)
        except Exception:
            print(f'Error occured during reading config file: {file}', file=sys.stderr)
            traceback.print_exc()
            sys.stderr.flush()
            sys.exit(1)

        cfg = vars(mod)

        for k, v in cfg.items():
            # Ignore unknown names
            if k not in self.cfg.settings:
                continue
            self.cfg.set(k, v)

    def load_config(self) -> None:
        # Parse command line args
        parser = self.cfg.parser()
        args = parser.parse_args()

        # Update configuration from config file
        if args.config:
            self.load_config_from_filename(args.config)
        else:
            default_config = get_default_config_file()
            if default_config is not None:
                self.load_config_from_filename(default_config)

        # Update configuration with any command line settings
        for k, v in vars(args).items():
            if v is None:
                continue
            self.cfg.set(k, v)

        # Check required settings
        for k in sorted(self.cfg.settings):
            s = self.cfg.settings[k]
            if s.required and s.value is None:
                raise ConfigError(f'The setting {s.name!r} is required.')

    def run(self):
        if self.cfg.print_config:
            print(self.cfg)
            sys.exit(0)
        super().run()
