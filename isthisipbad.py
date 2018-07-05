#!/usr/bin/env python
"""
Name:     isthisipbad.py
Purpose:  Check a IP against popular IP blacklist
By:       Jerry Gamblin
Date:     11.05.2015
Modified  05.19.2018
Rev Level 0.8
-----------------------------------------------
Downloaded from GitHub page:
https://github.com/jgamblin/isthisipbad/blob/master/isthisipbad.py
Updated by DrMattChristian to fix errors and add features.
"""

from __future__ import print_function
import os
import sys
import argparse
import re
import socket
try:  # Python 3 and newer only
    from urllib.error import HTTPError, URLError
    from urllib.request import build_opener, Request, urlopen
except ImportError:  # Python 2.7 and older
    from urllib2 import build_opener, HTTPError, Request, urlopen, URLError
# Requires dnspython AKA python-dns or python34-dns package
import dns.resolver


def color(text, color_code):
    """Color the text output if the terminal supports it.
    <https://en.wikipedia.org/wiki/ANSI_escape_code#Colors>"""
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text
    else:
        return '\x1b[%dm%s\x1b[0m' % (color_code, text)


def red(text):
    """Red color text"""
    return color(text, 31)


def grey(text):
    """Grey text"""
    return color(text, 5)


def green(text):
    """Green color text"""
    return color(text, 32)


def yellow(text):
    """Yellow color text"""
    return color(text, 33)


def content_test(url, badip):
    """
    Test the content of url's response to see if it contains badip.
        Args:
            url -- the URL to request data from
            badip -- the IP address in question
        Returns:
            Boolean
    """

    try:
        request = Request(url)
        opened_request = build_opener().open(request)
        html_content = opened_request.read().decode('UTF-8')
        retcode = opened_request.code
        escapedip = badip.replace('.', r'\.')

        # Must escape all periods/dots for regular expression
        matches = retcode == 200 and \
            re.findall(escapedip, html_content)

        return len(matches) == 0

    except HTTPError as exp:
        if hasattr(exp, 'code'):
            print('The server returned error code for request at URL ', url)
            print('Error code: ', exp.code)
    except URLError as exp:
        if hasattr(exp, 'reason'):
            print('Failed to reach the URL ', url)
            print('Reason: ', exp.reason)
        return False

# <http://multirbl.valli.org/list/>
BLS = ["all.rbl.webiron.net", "all.s5h.net", "all.spamrats.com",
       "b.barracudacentral.org", "bl.blocklist.de", "bl.drmx.org", "bl.fmb.la",
       "bl.mipspace.com", "bl.mailspike.net", "bl.nszones.com",
       "bl.spamcop.net", "bl.spameatingmonkey.net",
       "bl.suomispam.net", "blacklist.woody.ch", "block.ascams.com",
       "cdl.anti-spam.org.cn", "combined.rbl.msrbl.net", "db.wpbl.info",
       "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net", "dnsbl-3.uceprotect.net",
       "dnsbl.anticaptcha.net",
       "dnsbl.dronebl.org", "dnsbl.forefront.microsoft.com", "dnsbl.justspam.org",
       "dnsbl.sorbs.net", "dnsbl.spfbl.net", "dnsbl.zapbl.net", "dnsrbl.org",
       "dynip.rothen.com",
       "hostkarma.junkemailfilter.com", "ipbl.zeustracker.abuse.ch",
       "ips.backscatterer.org", "ix.dnsbl.manitu.net", "korea.services.net",
       "netbl.spameatingmonkey.net", "orvedb.aupads.org", "psbl.surriel.com",
       "rbl.blockedservers.com", "rbl.choon.net", "rbl.efnetrbl.org",
       "rbl.interserver.net", "relays.nether.net", "spam.dnsbl.anonmails.de",
       "spam.dnsbl.sorbs.net", "spamrbl.imp.ch",
       "truncate.gbudb.net", "ubl.unsubscore.com", "wormrbl.imp.ch",
       "zen.spamhaus.org"]

URLS = [
    #TOR
    ('https://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv',
     'is not a TOR Exit Node',
     'is a TOR Exit Node',
     False),

    #EmergingThreats
    ('https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
     'is not listed on EmergingThreats',
     'is listed on EmergingThreats',
     True),

    #AlienVault
    ('https://reputation.alienvault.com/reputation.data',
     'is not listed on AlienVault',
     'is listed on AlienVault',
     True),

    #BlocklistDE
    ('https://www.blocklist.de/lists/bruteforcelogin.txt',
     'is not listed on BlocklistDE',
     'is listed on BlocklistDE',
     True),

    #NoThinkMalware - Last updated Jan 2016
    #('https://www.nothink.org/blacklist/blacklist_malware_http.txt',
    # 'is not listed on NoThink Malware',
    # 'is listed on NoThink Malware',
    # True),

    #NoThinkSSH
    ('https://www.nothink.org/blacklist/blacklist_ssh_all.txt',
     'is not listed on NoThink SSH',
     'is listed on NoThink SSH',
     True),

    #antispam.imp.ch - Last updated Feb 2017 and no HTTPS
    #('http://antispam.imp.ch/spamlist',
    # 'is not listed on ImproWare AG spamlist',
    # 'is listed on ImproWare AG spamlist',
    # True),

    #dshield - DO NOT USE AS BLOCKLIST? and include email in UA
    ('https://secure.dshield.org/ipsascii.html?limit=10000',
     'is not listed on dshield',
     'is listed on dshield',
     True),

    #malc0de
    ('https://malc0de.com/bl/IP_Blacklist.txt',
     'is not listed on malc0de',
     'is listed on malc0de',
     True),

    #Malwarebytes hpHosts - RSS XML format and HTTP returns error
    ('https://hosts-file.net/rss.asp',
     'is not listed on Malwarebytes hpHosts',
     'is listed on Malwarebytes hpHosts',
     True)]

#    #Spamhaus DROP (in CIDR format, needs parsing)
#    ('https://www.spamhaus.org/drop/drop.txt',
#     'is not listed on Spamhaus DROP',
#     'is listed on Spamhaus DROP',
#     False),
#    #Spamhaus EDROP (in CIDR format, needs parsing)
#    ('https://www.spamhaus.org/drop/edrop.txt',
#     'is not listed on Spamhaus EDROP',
#     'is listed on Spamhaus EDROP',
#     False)]

if __name__ == "__main__":
    PARSER = argparse.ArgumentParser(description='Is This IP Bad?')
    PARSER.add_argument('-i', '--ip', help='IP address to check')
    PARSER.add_argument('--success', help='Also display GOOD',
                        required=False, action='store_true')
    ARGS = PARSER.parse_args()

    print(yellow('Check IP address against popular IP and DNS blacklists'))
    print(yellow('Original script by @jgamblin with updates by @DrMattChristian'))

    if ARGS is not None and ARGS.ip is not None and len(ARGS.ip) > 0:
        BADIP = ARGS.ip
    else:
        # Using HTTPS also bypasses many transparent HTTP proxies
        MY_IP = urlopen('https://icanhazip.com').read().decode('UTF-8').rstrip()

        # Get IP To Check
        try:  # For Python 2
            input = raw_input  # pylint: disable=invalid-name,redefined-builtin
        except NameError:
            pass
        RESP = input('\nWould you like to check your public IP address {0} ? (Y/N): '.format(MY_IP))

        if RESP.lower() in ["yes", "y"]:
            BADIP = MY_IP
        else:
            BADIP = input(yellow("\nWhat IP address would you like to check?: "))
            if BADIP is None or BADIP == "":
                sys.exit("No IP address to check.")

    #IP INFO
    REVERSED_DNS = socket.getfqdn(BADIP)
    GEOREQUEST = urlopen('https://api.hackertarget.com/geoip/?q={0}'.format(BADIP))
    GEOIP = GEOREQUEST.read().decode('UTF-8').rstrip()

    print(green('\nGeolocation IP address information:'))
    print(yellow('\nFQDN: {0}'.format(REVERSED_DNS)))
    print(yellow(GEOIP) + '\n')

    BAD = 0
    GOOD = 0

    for check_url, succ, fail, mal in URLS:
        if content_test(check_url, BADIP):
            if ARGS.success:
                print(green('{0} {1}'.format(BADIP, succ)))
            GOOD += 1
        else:
            print(red('{0} {1}'.format(BADIP, fail)))
            BAD += 1

    for bl in BLS:
        try:
            my_resolver = dns.resolver.Resolver()
            query = '.'.join(reversed(str(BADIP).split('.'))) + '.' + bl
            my_resolver.timeout = 5
            my_resolver.lifetime = 5
            answers = my_resolver.query(query, 'A')
            answers_txt = my_resolver.query(query, 'TXT')
            for answer, answer_txt in zip(answers, answers_txt):
                if bl == 'hostkarma.junkemailfilter.com' and \
                   re.search(r"^127\.0\.0\.[135]$", str(answer)):
                    if ARGS.success:
                        print(green(BADIP + ' is not listed on ' + bl))
                    GOOD += 1
                else:
                    print(red(BADIP + ' is listed on ' + bl)
                          + ' (%s: %s)' % (answer, answer_txt))
                    BAD += 1

        except dns.resolver.NXDOMAIN:
            if ARGS.success:
                print(green(BADIP + ' is not listed on ' + bl))
            GOOD += 1

        except dns.resolver.Timeout:
            print(grey('WARNING: Timeout querying ' + query))

        except dns.resolver.NoNameservers:
            print(grey('WARNING: No nameservers for ' + bl))

        except dns.resolver.NoAnswer:
            print(grey('WARNING: No answer for ' + query))

    if BAD == 0:
        print(green('{0} is NOT listed on any of the {1} blacklists.\n'.
                    format(BADIP, (GOOD+BAD))))
    else:
        print(red('{0} is listed on {1}/{2} blacklists.\n'.
                  format(BADIP, BAD, (GOOD+BAD))))
