"""Rename this file to config.py and edit as needed."""

MX = ['mail.seattlemesh.net']
SPF = ['91.121.161.13', 'q.meshwith.me'], ['2001:41d0:1:e20d::1', 'q.meshwith.me']
SELECTOR = 'q'
DKIM_FOLDER = 'dkim'
CHECKS = ['mx', 'dkim', 'spf']
