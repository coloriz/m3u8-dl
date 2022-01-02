import logging
import queue
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import coloredlogs
import m3u8
import requests
from Crypto.Cipher import AES
from urllib3 import Retry

from . import utils
from .adapters import TimeoutHTTPAdapter
from .base import Application

DEFAULT_TARGET_DURATION = 5.0


class M3U8Downloader(Application):
    def init(self):
        cfg = self.cfg

        # Configure logging facility
        log = logging.getLogger('m3u8-dl')
        fmt = '%(asctime)s %(name)s @ %(threadName)s: [%(levelname)s] %(message)s'
        coloredlogs.install(logging.DEBUG, logger=log, fmt=fmt)
        for handler in log.handlers:
            handler.setLevel(cfg.loglevel)

        if cfg.logfile:
            file_handler = logging.FileHandler(cfg.logfile)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(logging.Formatter(fmt))
            log.addHandler(file_handler)

        self.log = log

        # Configure session
        session = requests.Session()
        retry_strategy = Retry(total=cfg.retry, status_forcelist=[413, 429, 500, 502, 503, 504], backoff_factor=1)
        adapter = TimeoutHTTPAdapter(timeout=cfg.timeout, max_retries=retry_strategy)
        session.mount('https://', adapter)
        session.mount('http://', adapter)
        session.cookies.update(cfg.cookie)
        session.headers.update(cfg.header)

        self.session = session

        # Job queue
        self.jobs = queue.Queue()
        self.done_jobs = set()
        # Workers
        self.terminated = threading.Event()

    def main(self):
        cfg = self.cfg
        log = self.log
        session = self.session
        jobs = self.jobs
        done_jobs = self.done_jobs
        terminated = self.terminated

        if cfg.no_decrypt:
            log.warning("Flag 'no_decrypt' is set!")

        # Test url and log request and response
        res = session.get(cfg.url)
        log.debug('Initial request/response dump')
        for line in utils.dump_response(res).splitlines():
            log.debug(line)

        playlist = m3u8.loads(res.text, uri=cfg.url)
        if not playlist.segments:
            log.error('No segments!')
            sys.exit(-2)

        media_sequence = playlist.media_sequence
        # Set m3u8 request interval if not set
        if not cfg.interval:
            cfg.set('interval', playlist.target_duration or DEFAULT_TARGET_DURATION)
            log.info(f'Fetch interval changed to {cfg.interval}s')
        # Put segments in jobs queue
        for seg in playlist.segments:
            log.debug(f'New segment: {seg.uri}')
            if cfg.no_decrypt:
                seg.key = None
            jobs.put(seg)
            done_jobs.add(seg.uri)

        threads = []
        for i in range(cfg.n_workers):
            t = threading.Thread(target=self.worker, name=f'worker-{i}')
            t.start()
            threads.append(t)

        try:
            # Stop when all threads are terminated
            while any(t.is_alive() for t in threads):
                # Is this endlist?
                if playlist.is_endlist:
                    log.info('Found #EXT-X-ENDLIST')
                    jobs.join()
                    break
                # Sleep
                time.sleep(cfg.interval)
                # Fetch new playlist
                r = session.get(cfg.url)
                # Parse m3u8 and put new jobs
                playlist = m3u8.loads(r.text, uri=cfg.url)
                # Log latest media_sequence
                if playlist.media_sequence < media_sequence:
                    log.warning(f'#EXT-X-MEDIA-SEQUENCE decreased! ({media_sequence} -> {playlist.media_sequence})')
                media_sequence = playlist.media_sequence
                # Put new segment to job queue.
                for seg in playlist.segments:
                    if seg.uri in done_jobs:
                        continue
                    log.debug(f'New segment: {seg.uri}')
                    if cfg.no_decrypt:
                        seg.key = None
                    jobs.put(seg)
                    done_jobs.add(seg.uri)
        except KeyboardInterrupt:
            log.info('KeyboardInterrupt received. Gracefully quitting...')
        finally:
            terminated.set()
            for t in threads:
                t.join()

    def worker(self):
        cfg = self.cfg
        log = self.log
        session = self.session
        jobs = self.jobs
        terminated = self.terminated
        log.debug(f'New thread started (id=0x{threading.get_ident():x})')

        last_key_uri = ''
        last_key = utils.hex_string_to_bytes('00' * 16)
        last_iv = utils.hex_string_to_bytes('00' * 16)

        cipher = AES.new(last_key, AES.MODE_CBC, last_iv)

        while not terminated.is_set():
            # Get new segment
            try:
                segment = jobs.get(block=True, timeout=1)
                r = session.get(segment.absolute_uri)
                r.raise_for_status()
                stream = r.content
                # Check encryption
                if segment.key:
                    # Update cipher if key or iv changed
                    key_uri = segment.key.absolute_uri
                    iv = utils.hex_string_to_bytes(segment.key.iv)
                    changed = False
                    if key_uri != last_key_uri:
                        changed = True
                        r = session.get(key_uri)
                        r.raise_for_status()
                        last_key = r.content
                        last_key_uri = key_uri
                        log.debug(f'AES Key changed: {last_key.hex()} ({last_key_uri})')
                    if iv != last_iv:
                        changed = True
                        last_iv = iv
                        log.debug(f'AES IV changed: {last_iv.hex()}')
                    if changed:
                        cipher = AES.new(last_key, AES.MODE_CBC, last_iv)
                    # Decrypt
                    stream = cipher.decrypt(stream)
            except queue.Empty:  # No new segment
                continue
            except requests.HTTPError as e:
                log.error(e)
                break

            # Get filename
            path = urlparse(segment.absolute_uri).path
            output_path = cfg.output_path / Path(path[1:])
            if not output_path.parent.is_dir():
                output_path.parent.mkdir(parents=True, exist_ok=True)
            bytes_written = output_path.write_bytes(stream)
            log.info(f'Downloaded: {output_path.name} ({utils.format_size(bytes_written)})')
            # Notify this segment is complete
            jobs.task_done()

        log.debug(f'Thread terminating... (id=0x{threading.get_ident():x})')
