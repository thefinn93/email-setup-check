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


def check_spf(domain, mx):
    """Test the SPF records on a given domain."""
    results = {
        'test': 'spf',
        'passed': None,
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
        'record': {txt_domain: correct_record},
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
    return results


def check_mx(domain, servers):
    """Check that the proper MX records are in place for a given domain."""
    results = {
        'test': 'mx',
        'passed': None,
        'messages': []
    }
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
    return results
