"""Checks various mail-related things about a mail server.

Each check returns a dict with the following keys:

* succeeded: boolean, indicating if the test ran successfully. Does not indicate if the test passed
* passed: boolean, indicating if the test passed
* messages: A list of messages about why the test resulted the way it did
"""
import os
import spf
import DNS
import logging

logging.basicConfig(level=logging.DEBUG)


def check_spf(domain, mx, record):
    """Test the SPF records on a given domain."""
    results = {
        'test': 'spf',
        'passed': None,
        'records': [{'domain': domain, 'type': 'TXT', 'value': record}],
        'messages': []
    }
    try:
        for ip, helo in mx:
            spf_result, message = spf.check2(i=ip, s='admin@%s' % domain, h=helo)
            results['succeeded'] = True
            if spf_result == "none" and message == "":
                message = "No SPF record set! Please set one"
            results['messages'].append("(%s/%s) %s: %s" % (ip, helo, spf_result, message))
            if spf_result == "pass" and results['passed'] in (None, True):
                results['passed'] = True
            else:
                results['passed'] = False
    except spf.AmbiguityWarning as ex:
        results['succeeded'] = True
        results['passed'] = False
        results['message'] = str(ex)
    except (spf.TempError, spf.PermError) as ex:
        results['succeeded'] = False
        results['message'] = str(ex)
    return results


def check_dkim(domain, selector, folder):
    """Test the DKIM records for the given domain."""
    correct_record = open(os.path.join(folder, domain, '%s.txt' % selector)).read().split('"')[1]
    txt_domain = '%s._domainkey.%s' % (selector, domain)
    results = {
        'test': 'dkim',
        'passed': False,
        'records': [{'domain': txt_domain, 'type': 'TXT', 'value': correct_record}],
        'messages': []
    }
    actual_records = DNS.dnslookup(txt_domain, 'TXT')
    for record in actual_records:
        current_record = record[0].decode()
        if current_record == correct_record:
            if not results['passed']:
                results['passed'] = True
                results['messages'].append('Correct DKIM record found at %s' % txt_domain)
        else:
            results['messages'].append("%s found instead" % current_record)
    if len(actual_records) == 0:
        results['messages'].append('No DKIM records found (for selector %s)' % selector)
    return results


def check_mx(domain, servers):
    """Check that the proper MX records are in place for a given domain."""
    results = {
        'test': 'mx',
        'passed': None,
        'records': [],
        'messages': []
    }
    for server in servers:
        results['records'].append({'domain': domain, 'type': 'MX', 'value': server})
    actual_records = DNS.dnslookup(domain, 'MX')
    records = []
    for record in actual_records:
        records.append(record[1])
    for record in servers:
        if record in records:
            if results['passed'] is not False:
                results['passed'] = True
            results['messages'].append('MX record for %s found' % record)
        else:
            results['passed'] = False
            results['messages'].append('Incorrect MX record %s found' % record)
    if len(actual_records) == 0:
        results['messages'].append('No MX records found!')
    return results


def check_dmarc(domain, dmarc_record):
    """Check that the proper DMARC records are in place for a given domain."""
    results = {
        'test': 'dmarc',
        'passed': None,
        'records': [{'domain': '_dmarc.%s' % domain, 'type': 'TXT', 'value': dmarc_record}],
        'messages': ['This test is kinda crappy and may yield false negatives.']
    }
    try:
        actual_records = DNS.dnslookup('_dmarc.%s' % domain, 'TXT')
    except DNS.Base.ServerError:
        actual_records = []
    for record in actual_records:
        current_record = record[0].decode()
        if current_record == dmarc_record and results['passed'] is not False:
            results['passed'] = True
        else:
            results['passed'] = False
    if len(actual_records) == 0:
        results['messages'].append('No DMARC records found!')
        results['passed'] = False
    return results
