# Author:  Giovanni Armano giovanni.armano@aalto.fi
# Copyright 2015 Secure Systems Group, Aalto University, https://se-sy.org/
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from autobahn.twisted.websocket import WebSocketClientProtocol, WebSocketClientFactory
from twisted.python import log
from twisted.internet import reactor, defer

from urllib import parse
import requests
import re
from sys import stdout
from time import sleep
import json
from os import path, mkdir, name
from website import Website, split_mld_ps ,prune_link, guess_mld
from datetime import datetime
import random

#############
# ARGUMENTS #
#############

dlroot = "C:\\Program Log\\"

# header data for google search
HEADERS = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:32.0) Gecko/20100101 Firefox/32.0',}

# regular expression for extracting urls
GOOGLERX = re.compile("""http[s]?://[^\s'"]*""")

# max number of keywords extracted from a website
MAXCOUNT = 5

# stopmlds: mlds that almost always appear in Google's response
STOPMLDS = ['google', 'youtube', 'blogger', 'googleusercontent', 'schema']

def fetch_urls(query):
    """
    Do a Google search with a given query. Extract all URLs from the response for later processing.

    Arguments
    ---------
    query: str
        string containing keywords separated by whitespace

    Returns
    -------
    urls: set
        the set of URLs returned by Google
    """
    # quote whitespace so that the query can be placeed in a URL.
    query = parse.quote(query)
    url = 'http://www.google.com/search?q={}'.format(query)
    r = requests.get(url, headers=HEADERS)
    html = r.text
    urls = set()
    for url in GOOGLERX.findall(html):
        if '<' in url or '\\' in url:  # Google highlights search results
            continue
        mld, ps = split_mld_ps(url)
        domain = mld + '.' + ps
        if domain == 'google.fi' or domain == 'googleusercontent.com':
            continue
        urls.add(url)
    return urls


def extract_domains(url_set, logging=False):
    """
    Extract mail level domains and public suffixes from a set of urls.

    Returns
    -------
    domains : set
        tuples of form (mld, ps)
    """
    domains = set()
    for url in url_set:
        mld, ps = split_mld_ps(url)
        domains.add((mld, ps))
    #print(datetime.now().strftime("%H:%M:%S.%f")+" -- domains returned by google")
    return domains


def prominent_domains(ws, terms, extended_search=False):

    domains = query_domains(terms)
    #print(datetime.now().strftime("%H:%M:%S.%f")+" -- query response received")
    mld_guesses = set()
    # for link in ws.loglinks:
    #     mld_guesses = website.guess_mld(link, ws.boosted_intersection_terms())

    url_tokens = prune_link(ws.starturl)
    url_tokens += ' ' + prune_link(ws.landurl)

    targets = set()
    for mld, ps in domains:
        if not mld:
            continue
        mld = mld.lower()
        ps = ps.lower()
        if mld in ws.keywords:
            targets.add('.'.join([mld, ps]))
        elif mld in ws.boosted_keywords:
            targets.add('.'.join([mld, ps]))
        elif mld in mld_guesses:
            targets.add('.'.join([mld, ps]))
        elif len(mld) > 2:
            if mld in re.sub('\s+', '', ws.title):
                targets.add('.'.join([mld, ps]))
            elif mld in url_tokens:
                targets.add('.'.join([mld, ps]))
            elif extended_search:
                if mld in ws.text_with_title:
                    targets.add('.'.join([mld, ps]))
                elif mld in re.sub('\s+', '', ws.ocrtext):
                    targets.add('.'.join([mld, ps]))

    link_domains = set(split_mld_ps(link) for link in ws.loglinks + ws.source_links)

    # remove mlds that often occur: google, blogger, ... These are STOPMLDS
    link_domains = set((mld, ps) for (mld, ps) in link_domains if mld not in STOPMLDS)
    for dom in domains:
        if dom in link_domains and dom not in targets:
            targets.add('.'.join(dom))
    return targets


def query_domains(terms):
    """
    Query Google with given terms and extract domains.

    Parameters
    ----------
    terms : str, list, or set
    collection of query terms

    Returns
    -------
    domains : set
    set of domains in the form (mld, ps) extracted from the query result.
    """

    if not isinstance(terms, str):
        termstr = ' '.join(sorted(terms))
    else:
        termstr = terms

    urls = fetch_urls(termstr)
    domains = extract_domains(urls)
    return domains


def first_steps(ws, terms):
    targets = set()
    # rd in url?
    mld, ps = split_mld_ps(ws.landurl)
    RD = mld + '.' + ps
    domains = query_domains(terms)
    for dom in domains:
        rd = '.'.join(dom)   # rd = mld.ps
        if rd == RD:
            return RD
        if rd in ' '.join(ws.urls):
            targets.add(rd)
    if targets:
        return targets
    # rd in links?
    link_domains = set(split_mld_ps(link) for link in ws.loglinks + ws.source_links)
    # remove mlds that often occur: google, blogger, ... These are STOPMLDS
    link_domains = set('.'.join(dom) for dom in link_domains if dom[0] not in STOPMLDS)
    for dom in domains:
        rd = '.'.join(dom)   # rd = mld.ps
        if rd in link_domains:
            # logger.print('found {} from links'.format(rd))
            targets.add(rd)
    return targets


def identify_target(ws):

    starturl = ws.starturl
    landurl = ws.landurl

    # registered domain of the website
    mld, ps = split_mld_ps(landurl)
    RD = mld + '.' + ps

    targets = set()

    # STEP 0: guessable domain
    # print(datetime.now().strftime("%H:%M:%S.%f")+" -- STEP 0: guesses for mlds")
    queried = set()
    mld_guesses = set()
    # print(datetime.now().strftime("%H:%M:%S.%f")+" -- starting and landing urls:")
    # starting and landing urls
    for url in ws.urls:
        mld = split_mld_ps(url)[0]
        if mld not in queried:
            queried.add(mld)
            mld_guesses |= guess_mld(url, ws.boosted_intersection_terms())
    # print(datetime.now().strftime("%H:%M:%S.%f")+" -- links:")
    # links
    for url in ws.loglinks + ws.source_links:
        mld, rd = split_mld_ps(url)
        if rd and mld not in queried and mld not in ['w3', 'schema', 'googleapis']:
            queried.add(mld)
            mld_guesses |= guess_mld(mld + '.' + rd, ws.boosted_intersection_terms())

    queried = set()
    for mld in set(mld_guesses):
        if len(mld) > 4:
            # print(datetime.now().strftime("%H:%M:%S.%f")+" -- querying:")
            targets |= prominent_domains(ws, mld, extended_search=False)
            if RD in targets:
                return RD, [RD, '', ''] # not phishing

    # STEP 1: prominent terms
    # print(datetime.now().strftime("%H:%M:%S.%f")+" -- STEP 1: prominent terms:")
    if ws.keywords:
        targets |= prominent_domains(ws, ws.keywords, extended_search=False)
        if RD in targets:
            return RD, [RD, '', ''] # not phishing

    # STEP 2: boosted prominent terms
    # print(datetime.now().strftime("%H:%M:%S.%f")+" -- STEP 2: boosted prominent terms")
    if ws.boosted_keywords:
        targets |= prominent_domains(ws, ws.keywords, extended_search=False)
        if RD in targets:
            # print(datetime.now().strftime("%H:%M:%S.%f")+" -- legal site:")
            return RD, [RD, '', ''] # not phishing

    if not targets:
        return 'unknown', ['unknown', '', '']

    print(datetime.now().strftime("%H:%M:%S.%f")+" -- Targets: {}".format(targets))

    mlds = set()
    mldToFullDomain = {}
    for domain in targets:
        if len(split_mld_ps(domain)[0]) > 2:
            mldToFullDomain[split_mld_ps(domain)[0]] = domain
            mlds.add(split_mld_ps(domain)[0])

    dump = ''
    dump += ' '.join(ws.urls)
    dump += ' ' + ws.title
    dump += ' ' + ws.text_with_title  # gives title an extra nudge
    dump = re.sub('\s+', '', dump)
    d = {}
    for mld in mlds:
        d[mld] = dump.count(mld)
    li = sorted(d.items(), key=lambda x: x[1], reverse=True)
    top3 = li[:3]
    top3 = [x[0] for x in top3]
    main_target = top3[0]

    mldWithFullDomain = {}
    for top in top3:
        mldWithFullDomain[top] = mldToFullDomain[top]

    return main_target, mldWithFullDomain


def target_analyse(data):

    json_data = {'jspageid': data['jspageid']}
    json_data['siteid'] = data['siteid']

    ws = Website(json=data)
    target_identity = identify_target(ws)

    mld = '.'.join(split_mld_ps(data['landurl']))

    if mld == target_identity[0]:
        json_data['falsePositive'] = True
    else:
        json_data['falsePositive'] = False

    json_data['target'] = target_identity[0]
    json_data['otherTargets'] = target_identity[1]
    # print('Identified Target: ' + target_identity[0] + "\t/ other potential targets: " + str(target_identity[1]))

    return json_data


class MyWorkerProtocol(WebSocketClientProtocol):

    def __init__(self):
        self.workerId = random.randint(1, 100)
        self.count = 0

    def onConnect(self, request):
        print("Client connecting: {}".format(request.peer))

    def onOpen(self):
        self.workerId = random.randint(1,100)
        self.count = 0
        print("WebSocket connection open.")
        dict = {}
        dict['addidentifier'] = "I'm a new identifier"
        self.sendMessage(json.dumps(dict).encode('utf-8'), False)

    def onMessage(self, payload, isBinary):
        self.count += 1
        if isBinary:
            dict = json.loads(payload)
        else:
            if payload.decode('utf8') == 'undefined' :
                return
            dict = json.loads(payload.decode('utf8'))

        if 'type' in dict:
            if dict['type'] == "error":
                print("Error message received: {}\n".format(dict))
            return

        # print(datetime.now().strftime("%H:%M:%S.%f")+" TARGET -- website: "+dict['starturl'])

        d = defer.Deferred()
        d.addCallback(target_analyse)
        d.addCallback(self.sendResult)
        d.callback(dict)

    def sendResult(self, res):
        res_json = json.dumps(res).encode('utf-8')
        # print(datetime.now().strftime("%H:%M:%S.%f")+" TARGET -- Result: {}\n".format(res_json))
        self.sendMessage(res_json, False)

    def onClose(self, wasClean, code, reason):
        print("WebSocket connection closed: {}\n".format(reason))
        sleep(3)
        reactor.connectTCP("127.0.0.1", 9000, factory)


def choose_resource_path():
    global dlroot
    if name == "nt":
        if not path.exists(dlroot):
            mkdir(dlroot)
    if name == "posix":
        dlroot = path.abspath(".")

########
# main #
########

if __name__ == '__main__':

    choose_resource_path()

    #log.startLogging(stdout)
    log.startLogging(open(path.join(dlroot, 'log_tar.txt'), 'a'))

    factory = WebSocketClientFactory(u"ws://127.0.0.1:9000", debug=False)
    factory.protocol = MyWorkerProtocol

    reactor.connectTCP("127.0.0.1", 9000, factory)
    reactor.run()