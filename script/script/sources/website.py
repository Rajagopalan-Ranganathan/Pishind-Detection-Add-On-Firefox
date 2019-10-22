"""
This module implements a Python class Website, which is meant to be an
interface between the data obtained when scraping a website (sitedata json file
and screenshot) and programs that use this data.

In general, it is assumed that the data is store in the following hierarchy:

    ROOT/sitedata/<siteid>.json
    ROOT/screenshots/<siteid>/json
"""

# Author:   Kalle Saari kalle.saari@aalto.fi, Giovanni Armano giovanni.armano@aalto.fi
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

from collections import Counter
from datetime import datetime
import json
import os
import pickle
import re
from urllib import parse
from math import log

from goslate import Goslate
from publicsuffix import PublicSuffixList
from unidecode import unidecode

import keywords

###################
# initializations #
###################


g = Goslate()

stopwords = pickle.load(open("data/stopwords_dict", 'rb'))

psl = PublicSuffixList(open("data/public_suffix_list.dat", encoding="utf8"))

document_frequencies = {}
with open("data/count_1w.txt") as f:
    for line in f:
        key, value = line.strip().split()
        document_frequencies[key] = int(value)


#########
# UTILS #
#########

def cleanString(s):
    s = unidecode(s)
    s = re.sub('\n',' ',s)
    s = re.sub('\t',' ',s)
    return str.lower(s)


###########
# private #
###########


def _replace_ad(html):
    """Remove symbols 'a0:' and 'a2:'. 'a0:' stands for 'nobreak'"""
    # opening tag
    html = re.sub('\<\s*a\d\:', '<', html)
    # closing tag
    html = re.sub('\</\s*a\d\:', '</', html)
    return html


def _remove_tags(html):
    """
    Remove tags, ie anything like <...>, from input html string.
    """
    html = _unescape_html(html)
    html = re.sub('\<sup\>|\</sup\>', '', html)
    html = re.sub('\<sub\>|\</sub\>', '', html)
    tagrx = re.compile('\<.+?\>', flags=re.DOTALL)
    html = tagrx.sub(' ', html)
    return html


def _remove_urls(text):
    """
    Remove urls appearing in text.
    """
    urlrx = re.compile("""http[s]?://[^\s'"]*""")
    text = urlrx.sub(' ', text)
    return text


def _unescape_html(html):
    """
    Replace ampersand symbols in html. NOTE: Python 3.4 has this implemented
    in html module.
    """
    html = re.sub('&amp;', '&', html, flags=re.DOTALL)
    html = re.sub('&quot;', '"', html, flags=re.DOTALL)
    html = re.sub('&lt;', '\<', html)
    html = re.sub('&gt;', '\>', html)
    return html

def _remove_inner_punctuation(string):
    """
    If two strings are separated by & or  -, remove
    the symbol and join the strings.

    Example
    -------
    >>> _remove_inner_punctuation("This is AT&T here")
    'This is ATT here'
    >>> _remove_inner_punctuation("A T & T")
    'A T  T'
    """
    string = re.sub('[\&\-]', '', string)
    return string


def _tokens_in_string(tokens, string, is_url=False):
    """
    Find tokens that occur in string. Return a set of tokens.

    Example
    -------
    >>> _tokens_in_string(['hi', 'ring', 'aa'], 'this is a string', is_url=False)
    {'hi', 'ring'}
    >>> _tokens_in_string(['tt', 'ww', 'wh', 'hs', 'fi', 'sin', 'jpg'], 'http://www.hs.fi/helsinki.jpg', is_url=True)
    {'hs', 'sin'}
    NOTE: 'www' is stripped by prune_link. That's why 'ww' is not in the intersection set
    """
    # Assuming tokens are already lowercased
    # If there are too many tokens, this will be a bottle nect.
    # Thus we chop the list of tokens, if necessary.
    if len(tokens) > 4000:
        tokens = tokens[:2000] + tokens[-2000:]
    string = string.lower()
    if is_url:
        string = prune_link(string)
    intersection = set()
    for token in tokens:
        if token in string:
            intersection.add(token)
    return intersection


def _prune_bifixes(set_of_words):
    """
    Remove words from a set that are proper prefixes or suffixes of another word

    Example
    -------
    >>> set_of_words = {'aba', 'a', 'aaba'}
    >>> _prune_bifixes(set_of_words)
    {'aaba'}
    """
    cleaned = set()
    bad_words = set()
    for elem1 in set_of_words:
        for elem2 in set_of_words:
            if elem1 == elem2:
                continue
            if elem2.startswith(elem1) or elem2.endswith(elem1):
                bad_words.add(elem1)
    cleaned = set.difference(set_of_words, bad_words)
    return cleaned


def _remove_stopwords(words, langid='en'):
    """
    Remove English stopwords and frequent www words.
    """
    cleaned = set()
    stopwords = pickle.load(open("data/stopwords_dict", 'br'))
    stopwords_www = set(line.strip() for line in open('data/stopwords_www.txt', encoding="utf8"))
    for token in words:
            if token not in stopwords_www and token not in stopwords[langid]:
                cleaned.add(token)
    return cleaned


##########
# public #
##########


def split_mld_ps(url):
    """
    Extract the main level domain and public suffix from url.

    Parameter
    ---------
    url: str
        url of website

    Returns
    -------
    mld: str
        main level domain
    ps: str
        public suffic

    Example
    -------
    >>> split_mld_ps("http://news.bbc.co.uk/today.html")
    ('bbc', 'co.uk')
    >>> split_mld_ps("https://telepremium.net:443/")
    ('telepremium, 'net')
    """
    try:
        parsed = parse.urlparse(url)
    except:
        return '', ''
    # Next covers urls given both in form google.com and http://google.com
    # It also removes possible port number in netloc
    domain = parsed.netloc.split(':')[0] or parsed.path.split(':')[0]
    domain = psl.get_public_suffix(domain)
    tokens = domain.split('.')
    mld = tokens[0]
    ps = '.'.join(tokens[1:])
    return mld, ps


def prune_link(link):
    """
    Remove protocol and file extension from link

    Example
    -------
    >>> prune_link("http://www.hs.fi/helsinki.jpg")
    "hs/helsinki"
    >>> prune_link("./image.png")
    'image'
    """
    # FIRST: take care of relative links
    if link.startswith('/'):
        return os.path.splitext(link[1:])[0]
    if link.startswith('./'):
        return os.path.splitext(link[2:])[0]
    if link.startswith('../'):
        return os.path.splitext(link[3:])[0]

    # SECOND: treat full urls
    parsed = parse.urlparse(link)
    netloc = parsed.netloc
    # erase www
    if netloc[:4] == 'www.':
        netloc = netloc[4:]
    # erase tld
    mld, ps = split_mld_ps(netloc)
    try:
        netloc = netloc[:-len(ps) - 1]  # extra -1 covers '.'
    except TypeError:
        netloc = ''
    # remove extension from path
    path = os.path.splitext(parsed.path)[0]
    return netloc + path


def guess_mld(urlstring='', intersection=None):
    """
    Generate guesses for the main level domain name given intersection terms.

    Parameters
    ----------
    urlstring : str
        string consisting of url(s)
    intersection : set
        contains the intersection terms

    Returns
    -------
    mld_guesses: set
        set of strings, the mld guesses
    """
    urlstring = prune_link(urlstring).lower()
    boosted = intersection.copy()  # shallow copy
    old = set()

    # First, build as long url token as possible combining existing tokens,
    # possibly glued together with ., -, 0, ..., 9
    while boosted != old:
        old = boosted.copy()
        for token1 in old:
            if token1 in urlstring:
                for token2 in old:
                    if token2 in urlstring:
                        if token1 + token2 in urlstring:
                            boosted.add(token1 + token2)
                        if token1 + '-' + token2 in urlstring:
                            boosted.add(token1 + '-' + token2)
                        if token1 + '.' + token2 in urlstring:
                            boosted.add(token1 + '.' + token2)
                        for d in range(9):
                            if token1 + str(d) + token2 in urlstring:
                                boosted.add(token1 + str(d) + token2)


    # Second, remove intermediate tokens constructed in the previous step
    fullones = set()
    for token1 in boosted:
        if token1 in urlstring:
            for token2 in boosted:
                if token1 + token2 in boosted or token2 + token1 in boosted:
                    break
            else:
                fullones.add(token1)

    # remove possible one-letter domain guesses
    mld_guesses = set([mld for mld in fullones if len(mld) > 1])

    # remove each guess that is a prefix or a suffix of a longer guess
    mld_guesses = _prune_bifixes(mld_guesses)


    # filter out guesses that do not appear in the beginning or in the end of tokenized url
    final_guesses = set()
    tokens = re.split('[\.\/]', urlstring)
    for guess in mld_guesses:
        for token in tokens:
            if token.startswith(guess) or token.endswith(guess):
                final_guesses.add(guess)
            # dont remove if it contains a dot, however
            if '.' in guess:
                final_guesses.add(guess)
    return final_guesses


def pseudo_tfidf(tokens, x, langid='en'):
    if x in stopwords[langid]:
        return 0
    else:
        tf = tokens.count(x)
        idf = 1 / log(10,document_frequencies.get(x, float("inf")))
        return tf * idf


#################
# Website class #
#################


class Website(object):

    def __init__(self, jspath='', sspath='', json=''):
        if json:
            self.js = json
        else:
            self.jspath = jspath
            if sspath:
                self.sspath = sspath
            else:
                dirname = os.path.dirname(jspath)
                siteid = os.path.basename(jspath)
                siteid = os.path.splitext(siteid)[0]
                sspath = os.path.join(dirname, siteid + '.png')
                if os.path.exists(sspath):
                    self.sspath = sspath
                else:
                    dirname = os.path.dirname(os.path.dirname(jspath))
                    self.sspath = os.path.join(dirname, 'screenshots', siteid + '.png')
            with open(jspath, encoding="utf8") as f:
                text = f.read()
            text = cleanString(text)
            self.js = json.loads(text)

    def _combine_sources(self):
        """
        Return a list of source and external sources.
        """
        sources = []
        sources.append(self.js['source'])
        sources += list(self.js.get('external_source', {}).values())
        return sources

    @property
    def external_source(self):
        return len(list(self.js.get('external_source', {}).values()))
    
    
    @property
    def title_tokens_in_url(self):
        """
        Extract tokens in title string that occur in start or landing url.
        """
        if hasattr(self, '_title_tokens_in_url'):
            return self._title_tokens_in_url
        else:
            tokenstring = self.title
            tokenstring = _remove_inner_punctuation(tokenstring)

            # # replace digits with space
            # tokenstring = re.sub('\d+', ' ', tokenstring)
            # # separate by hyphens, e.g., e-mail
            # tokenstring = re.sub('\-+', '', tokenstring)

            # replace non-alphanumeric and  non-underscore symbols with space
            tokenstring = re.sub('\W+', ' ', tokenstring)
            # # replace underscore with space
            # tokenstring = re.sub('_+', ' ', tokenstring)
            # split on spaces
            tokens = re.split('\s+', tokenstring)
            # separate digit groups
            old_tokens = tokens[:]
            tokens = []
            for token in old_tokens:
                tokens += re.findall('\d+|\D+', token)

            intersection = set()
            for string in self.urls:
                intersection |= _tokens_in_string(tokens, string, is_url=True)
            self._title_tokens_in_url = intersection
            return intersection

    @property
    def text_tokens_in_url(self):
        """
        Extract tokens in text string that occur in start or landing url.
        """
        if hasattr(self, '_text_tokens_in_url'):
            return self._text_tokens_in_url
        else:

            tokenstring = self.text_without_title
            tokenstring = _remove_inner_punctuation(tokenstring)

            # replace non-alphanumeric and  non-underscore symbols with space
            tokenstring = re.sub('\W+', ' ', tokenstring)
            # split on spaces
            tokens = re.split('\s+', tokenstring)
            # separate digit groups
            old_tokens = tokens[:]
            tokens = []
            for token in old_tokens:
                tokens += re.findall('\d+|\D+', token)

            intersection = set()
            for string in self.urls:
                intersection |= _tokens_in_string(tokens, string, is_url=True)
            self._text_tokens_in_url = intersection
            return intersection

    @property
    def title_tokens_in_links(self):
        """
        Extract tokens in title string that occur in static or dynamically
        generated links.
        """
        if hasattr(self, '_title_tokens_in_links'):
            return self._title_tokens_in_links
        else:
            tokenstring = self.title
            tokenstring = _remove_inner_punctuation(tokenstring)

            # replace non-alphanumeric and  non-underscore symbols with space
            tokenstring = re.sub('\W+', ' ', tokenstring)
            # split on spaces
            tokens = re.split('\s+', tokenstring)
            # separate digit groups
            old_tokens = tokens[:]
            tokens = []
            for token in old_tokens:
                tokens += re.findall('\d+|\D+', token)

            intersection = set()
            for link in self.source_links + self.loglinks:
                intersection |= _tokens_in_string(tokens, link, is_url=True)
            self._title_tokens_in_links = intersection
            return intersection

    @property
    def text_tokens_in_links(self):
        """
        Extract tokens in text string that occur in static or dynamically
        generated links.
        """
        if hasattr(self, 'text_tokens_in_links_'):
            return self._text_tokens_in_links
        else:
            tokenstring = self.text_without_title
            # tokenstring = _js_to_text(self, js, skip_title=True)
            # tokenstring = _unescape_html(tokenstring)
            tokenstring = _remove_inner_punctuation(tokenstring)

            # replace non-alphanumeric and  non-underscore symbols with space
            tokenstring = re.sub('\W+', ' ', tokenstring)
            # split on spaces
            tokens = re.split('\s+', tokenstring)
            # separate digit groups
            old_tokens = tokens[:]
            tokens = []
            for token in old_tokens:
                tokens += re.findall('\d+|\D+', token)

            intersection = set()
            for link in self.source_links + self.loglinks:
                intersection |= _tokens_in_string(tokens, link, is_url=True)

            self._text_tokens_in_links = intersection
            return intersection

    @property
    def text_tokens_in_title(self):
        """
        Extract tokens in text string that occur in title.
        """
        if hasattr(self, '_text_tokens_in_title'):
            return self._text_tokens_in_title
        else:
            tokenstring1 = self.text_without_title
            tokenstring2 = self.title
            tokenstring1 = _remove_inner_punctuation(tokenstring1)
            tokenstring2 = _remove_inner_punctuation(tokenstring2)

            # replace non-alphanumeric and  non-underscore symbols with space
            tokenstring1 = re.sub('\W+', ' ', tokenstring1)
            tokenstring2 = re.sub('\W+', ' ', tokenstring2)
            # split on spaces
            tokens1 = re.split('\s+', tokenstring1)
            tokens2 = re.split('\s+', tokenstring2)
            # separate digit groups
            old_tokens1 = tokens1[:]
            tokens1 = []
            for token in old_tokens1:
                tokens1 += re.findall('\d+|\D+', token)
            old_tokens2 = tokens2[:]
            tokens2 = []
            for token in old_tokens2:
                tokens2 += re.findall('\d+|\D+', token)

            intersection = set.intersection(set(tokens1), set(tokens2))

            self._text_tokens_in_title = intersection
            return intersection

    @property
    def copyright_tokens_in_text(self):
        """
        Extract tokens that occur both in text and in   a copyright field.
        """
        if hasattr(self, '_copyright_tokens_in_text'):
            return self._copyright_tokens_in_text
        else:
            tokenstring1 = ''
            tokenstring2 = ''
            for line in re.split('\n+', self.text):
                # NOTE: '@' is used by some phisher in place of '©'
                if '@' in line or '©' in line:
                    tokenstring1 += ' ' + line
                else:
                    tokenstring2 += ' ' + line

            tokenstring1 = _remove_inner_punctuation(tokenstring1)
            tokenstring2 = _remove_inner_punctuation(tokenstring2)

            # replace non-alphanumeric and  non-underscore symbols with space
            tokenstring1 = re.sub('\W+', ' ', tokenstring1)
            tokenstring2 = re.sub('\W+', ' ', tokenstring2)
            # split on spaces
            tokens1 = re.split('\s+', tokenstring1)
            tokens2 = re.split('\s+', tokenstring2)
            # separate digit groups
            old_tokens1 = tokens1[:]
            tokens1 = []
            for token in old_tokens1:
                tokens1 += re.findall('\d+|\D+', token)
            old_tokens2 = tokens2[:]
            tokens2 = []
            for token in old_tokens2:
                tokens2 += re.findall('\d+|\D+', token)

            intersection = set.intersection(set(tokens1), set(tokens2))
            self._copyright_tokens_in_text = intersection
            return intersection

    def get_intersection_terms(self, boost=False):
        """
        Find tokens that occur in at least two of the following locations:
        - starting and landing url
        - title
        - text
        - links

        Parameters
        ----------
        boost : boolean (default=False)
            whether to include text_tokens_in_links

        Returns
        -------
        intersection: set
            set of all intersection terms
        """
        intersection = set()
        # title tokens in url
        terms = self.title_tokens_in_url
        intersection |= terms
        # text tokens in url
        terms = self.text_tokens_in_url
        intersection |= terms
        # text tokens in title
        terms = self.text_tokens_in_title
        intersection |= terms
        # title tokens in links
        terms = self.title_tokens_in_links
        intersection |= terms
        # copyright tokens elsewhere in text
        terms = self.copyright_tokens_in_text
        intersection |= terms
        if boost:
            # text tokens in links
            terms = self.text_tokens_in_links
            intersection |= terms
        return intersection

    def intersection_terms(self):
        if hasattr(self, '_intersection_terms'):
            return self._intersection_terms
        else:
            intersection_terms = self.get_intersection_terms(boost=False)
            self._intersection_terms = intersection_terms
            return intersection_terms

    def boosted_intersection_terms(self):
        if hasattr(self, '_boosted_intersection_terms'):
            return self._boosted_intersection_terms
        else:
            intersection_terms = self.get_intersection_terms(boost=True)
            self._boosted_intersection_terms = intersection_terms
            return intersection_terms

    def _add_counts(self, intersection_terms):
        """
        For each intersection term, count the number of times it appears in the site.
        """
        count = {}
        dump = self.starturl + ' ' + self.landurl + ' '
        dump += self.text_with_title
        # dump += ' ' + ' '.join(js['loglinks']).lower()
        for term in intersection_terms:
            count[term] = dump.count(term)
        return count

    def _sort_by_count(self, intersection_terms):
        """
        Return an intersection set by the number of times tokens appear in json file.
        Most frequent tokens appear first.
        """
        li = sorted(self._add_counts(intersection_terms).items(), key=lambda x: x[1], reverse=True)
        return [x[0] for x in li]

    def get_keywords(self, max_count=5, boost=False, langid='en', len_lb=3):
        """
        Extract up to max_count keywords. These words are intersection terms sorted
        by the number of occurrence.

        Parameters
        ----------
        max_count : int (default=5)
            number of keywords extracted. If None, all keywords are returned
        boost : boolean (default=False)
            whether to add text_tokens_in_links
        langid : str (default='en')
            which language to use to remove stopwords
        len_lb : int (default=3)
            filter out terms of length less than len_lb

        Returns
        -------
        keywords: list
            list of keywords
        """
        intersection = self.get_intersection_terms(boost=boost)
        # remove stopwords
        intersection = _remove_stopwords(intersection, langid=langid)
        # remove words that are prefixes or suffixes of another intersection term
        intersection = _prune_bifixes(intersection)
        # remove swords that are shorter than the lower bound len_lb
        intersection = set(token for token in intersection if len(token) >= len_lb)
        keywords = self._sort_by_count(intersection)
        # save keywords for possible later use
        keywords = keywords[:max_count]
        return keywords

    @property
    def keywords(self):
        """
        Get keywords in their default parameter values
        """
        if hasattr(self, '_keywords'):
            return self._keywords
        else:
            keywords = self.get_keywords(boost=False)
            self._keywords = keywords
            return keywords

    @property
    def boosted_keywords(self):
        if hasattr(self, '_boosted_keywords'):
            return self._boosted_keywords
        else:
            keywords = self.get_keywords(boost=True)
            self._boosted_keywords = keywords
            return keywords

    @property
    def source(self):
        if hasattr(self, '_source'):
            return self._source
        else:
            sources = self._combine_sources()
            html = ' '.join(sources)
            source = _unescape_html(html)
            source = _replace_ad(source)
            self._source = source
            return self._source

    @property
    def source_without_tags(self):
        return _remove_tags(self.source)

    @property
    def langid(self):
        if hasattr(self, '_langid'):
            return self._langid
        elif 'langid' in self.js:
            self._langid = self.js['langid']
            return self._langid
        else:
            try:
                langid = g.detect(self.text_with_title)
            except:
                langid = 'en'
            else:
                self.update('langid', langid)
            self._langid = langid
            return langid

    def get_tfidf_terms(self, n=5):
        tokens = list(set(self.text_with_title.split()))
        langid = self.langid
        ranked = []


        for item in set(tokens):
            if len(item) < 3:
                continue
            value = pseudo_tfidf(tokens, item, langid=langid)
            ranked.append((item, value))

        ranked = sorted(ranked, key=lambda x: x[1], reverse=True)
        ranked = [x[0] for x in ranked][:n]
        self._tfidf_terms = ranked
        return ranked

    @property
    def tfidf_terms(self):
        if hasattr(self, '_tfidf_terms'):
            return self._tfidf_terms
        else:
            self._tfidf_terms = self.get_tfidf_terms(n=5)
            return self._tfidf_terms

    @property
    def source_links(self):
        """Try to find all hard-coded links"""

        if hasattr(self, '_source_links'):
            return self._source_links

        # Use html from the site itsels and from its external sources
        sources = self._combine_sources()
        html = ' '.join(sources)

        # Substitute real html symbols
        html = _unescape_html(html)

        links = set()
        hrefrx = re.compile("""href\s*\=\s*['"](.*?)['"]""")
        for link in re.findall(hrefrx, html):
            links.add(str(link))
        srcrx = re.compile("""src\s*\=\s*['"](.*?)['"]""")
        for link in re.findall(srcrx, html):
            links.add(str(link))
        html = re.sub('%20', ' ', html, flags=re.DOTALL)

        # Extract links that are not surrounded by quotes
        urlrx = re.compile("""[^'"](http[s]?://[\.a-zA-Z0-9/]+?)\s""")
        for link in re.findall(urlrx, html):
            links.add(str(link))

        # Extract links that are surrounded by quotes
        # first remove whitespace
        html = re.sub('\s+', '', html)
        urlrx = re.compile('"(http[s]?://[\.a-zA-Z0-9/]+?)"', flags=re.DOTALL)
        for link in re.findall(urlrx, html):
            links.add(link)

        # Remove empty string if exists
        links.discard('')

        # Remove "links" that start with 'javascript:'
        for link in list(links):
            if link.startswith('javascript:'):
                links.discard(link)
        links = sorted(links)
        self._source_links = links
        return links
        
    @property
    def source_links_ext(self):
        """Try to find all hard-coded links"""
        
        if hasattr(self, '_source_links_ext'):
            return self._source_links_ext
        
        # Use html from the site itsels and from its external sources
        sources = self._combine_sources()
        html = ' '.join(sources)
        
        # Substitute real html symbols
        html = _unescape_html(html)
        
        links = set()
        hrefrx = re.compile("""href\s*\=\s*['"](http.*?)['"]""")
        for link in re.findall(hrefrx, html):
            links.add(str(link))
        srcrx = re.compile("""src\s*\=\s*['"](http.*?)['"]""")
        for link in re.findall(srcrx, html):
            links.add(str(link))
        html = re.sub('%20', ' ', html, flags=re.DOTALL)
    
        # Extract links that are not surrounded by quotes
        urlrx = re.compile("""[^'"](http[s]?://[\.a-zA-Z0-9/]+?)\s""")
        for link in re.findall(urlrx, html):
            links.add(str(link))

        # Extract links that are surrounded by quotes
        # first remove whitespace
        html = re.sub('\s+', '', html)
        urlrx = re.compile('"(http[s]?://[\.a-zA-Z0-9/]+?)"', flags=re.DOTALL)
        for link in re.findall(urlrx, html):
            links.add(link)

        # Remove empty string if exists
        links.discard('')
    
        # Remove "links" that start with 'javascript:'
        for link in list(links):
            if link.startswith('javascript:'):
                links.discard(link)
        links = sorted(links)
        self._source_links_ext = links
        return links

    def update(self, key, value):
        """
        Update json file with key-value pair.
        """
        if key in self.js:
            self.js[key] = value
            with open(self.jspath, 'w') as f:
                json.dump(self.js, f, indent=0, sort_keys=True)

    def add_key(self, key, value):
        """
        Add a key-value pair to json file
        """
        if key not in self.js:
            self.js[key] = value
            with open(self.jspath, 'w') as f:
                json.dump(self.js, f, indent=0, sort_keys=True)

    @property
    def keys(self):
        keys = list(self.js.keys())
        return keys

    @property
    def uses_obscuring(self):
        """
        Do some simple checks for potential obscuring of the html source.
        """
        source = self.js['source']
        if '<a0' in source or '<a2' in source:
            return True
        else:
            return False

    def delete(self):
        ans = input('Delete! Are you sure [y]? ')
        if ans == 'y':
            os.remove(self.jspath)
            os.remove(self.sspath)

    @property
    def title(self):
        return cleanString(self.js['title'].lower())
        if hasattr(self.js,'title'):
            return cleanString(self.js['title'].lower())
        else:
            return ""

    @property
    def redirections(self):
        return self.js['redirections']

    @property
    def access_time(self):
        at = self.js.get('access_time', 'NA')
        if at:
            return at
        else:
            return 'NA'

    def datetime(self):
        at = self.js.get('access_time', '')
        try:
            dt = datetime.datetime.strptime(at, "%a %b %d %H:%M:%S %Y")
        except:
            dt = None
        return dt

    @property
    def loglinks(self):
        if hasattr(self, '_loglinks'):
            return self._loglinks
        loglinks = []
        for link in self.js['loglinks']:
            mld, ps = keywords.split_mld_ps(link)
            # the following domains are automatically produced by Firefox and thus useless
            if mld not in set(['mozilla', 'digicert', 'symcd', 'symcb']):
                loglinks.append(link)
        self._loglinks = loglinks
        return loglinks

    @property
    def mld(self):
        mld, ps = keywords.split_mld_ps(self.landurl)
        return mld

    @property
    def siteid(self):
        return self.js['siteid']

    @property
    def text(self):
        if hasattr(self, '_text'):
            return self._text
        else:
            text = self.js['text'].lower()
            self._text = text
            return text

    @property
    def text_without_title(self):
        if hasattr(self, '_text_without_title'):
            return self._text_without_title
        else:
            text = cleanString(self.js['text'].lower())
            self._text_without_title = text
            return text

    @property
    def image_count(self):
        if 'images' in self.js:
            return self.js['images']
        if hasattr(self, '_image_count'):
            return self._image_count
        else:
            return 0


    @property
    def input_count(self):
        if 'inputs' in self.js:
            return self.js['inputs']
        if hasattr(self, '_input_count'):
            return self._input_count
        else:
            return 0

    @property
    def text_with_title(self):
        if hasattr(self, '_text_with_title'):
            return self._text_with_title
        else:
            text = self.text_without_title
            title = self.title
            title = title.lower()
            title = unidecode(title)
            self._text_with_title = title + '\n' + text
            return self._text_with_title

    @property
    def num_tokens(self):
        if hasattr(self, '_num_tokens'):
            return self._num_tokens
        text = self.text_with_title
        text = re.sub('\W+', ' ', text)
        text = re.sub('\s+', ' ', text)
        tokens = text.split()
        self._num_tokens = len(tokens)
        return self._num_tokens

    def most_common_tokens(self, value=10):
        text = self.text_with_title
        tokens = re.split('\W+', text)
        tokens = [token for token in tokens if len(token) >= 2]
        most_common = Counter(tokens).most_common(n=value)
        return most_common

    @property
    def target(self):
        target = self.js.get('target', 'NA')
        return target

    @property
    def starturl(self):
        return self.js['starturl']

    @property
    def landurl(self):
        return self.js['landurl']

    @property
    def urls(self):
        urls = []
        urls.append(self.js['landurl'])
        urls.append(self.js['starturl'])
        return urls

    @property
    def status(self):
        return self.js.get('status', 'NA')

    @property
    def description(self):
        print("site id: {}".format(self.siteid))
        print("path: {}".format(self.jspath))
        print('starting url: {}'.format(self.starturl[:150]))
        print('landing url:  {}'.format(self.landurl[:150]))
        print('title: {}'.format(self.title[:150]))
        print('token count: {}'.format(self.num_tokens))
        print('access time: {}'.format(self.access_time))
        print("target: {}".format(self.target))
        print("phish: {}".format(self.status))

    @property
    def translation(self):
        """
        Translate text using Google translator.
        """
        if 'translation' in self.js:
            translation = self.js['translation']
        else:
            gs = Goslate()
            translation = gs.translate(self.text_with_title, 'en')
            self.add_key(key='translation', value=translation)
        return translation