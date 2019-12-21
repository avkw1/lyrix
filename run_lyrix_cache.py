# -*- coding: utf-8 -*-
"""
Startup script for Lyrix card cache service

@author: Alexander Korolev (avkw@bk.ru)
"""

from lyrix import LyrixConfig, run_cache
import signal
import sys
import settings

def sig_handler(_signo, _stack_frame):
    # Raises SystemExit(0):
    sys.exit(0)

if __name__ == "__main__":
    # Register signal handler
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGHUP, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)
    # Build Lyrix config from settings
    config = LyrixConfig(settings.LYRIX_WSDL_URL, settings.LYRIX_USER,
                         settings.LYRIX_PASSWORD)
    # Use timeout x3 !
    config.timeout = settings.LYRIX_TIMEOUT_S * 3
    config.reconnect_interval_s = settings.LYRIX_RECONNECT_INTERVAL_S
    config.cache_livetime_m = settings.LYRIX_CACHE_LIVETIME_M
    config.card_cache_file = settings.CARD_CACHE_FILE
    if config.card_cache_file:
        run_cache(config)
