#!/usr/bin/env python
import checks
import json

mx = [('91.121.161.13', 'q.meshwith.me'), ('2001:41d0:1:e20d::1', 'q.meshwith.me')]
result = checks.check_spf('finn.io', mx)
print(json.dumps(result))
