"""Rename this file to config.py and edit as needed."""

MX = ['mail.seattlemesh.net']
SPF = ['91.121.161.13', 'q.meshwith.me'], ['2001:41d0:1:e20d::1', 'q.meshwith.me']
SELECTOR = 'q'
DKIM_FOLDER = 'dkim'
SPF_RECORD = 'v=spf1 redirect=seattlemesh.net'
DMARC_RECORD = 'v=DMARC1; p=none; rua=mailto:dmarc@seattlemesh.net; ruf=mailto:dmarcf@seattlemesh.net; fo=1'
