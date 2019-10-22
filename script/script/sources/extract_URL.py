# Author:   Samuel Marchal samuel.marchal@aalto.fi
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


import re
from urllib import parse
from csv import reader
from publicsuffix import PublicSuffixList
from unidecode import unidecode

IP_pat = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
psl = PublicSuffixList(open("data/public_suffix_list.dat", encoding="utf8"))

class Extractor:

    def __init__(self):
        self.proto = 2
    
    def cleanURL(self,s):    # clean the domain names obtained to respect the DNS rules
        if s[:2] == "b'":
            s = s[2:len(s)-1]
        s = parse.unquote(s)
        return str.lower(unidecode(s))

    def protocol_extract(self,url):
        
        index = url.find("https://")
        if index > -1:
            self.proto = 1
            return url[index+8:]
        index = url.find("http://")
        if index > -1:
            self.proto = 0
            return url[index+7:]
        else:
            self.proto = 0
            return url


    def extract_words(self,url):
        nbdomain = 0
        words_temp = []
        words = {}
        words2 = []
        tokens =  {}
        token_temp =  []
        mld = ""
        url_clean = self.cleanURL(url)
        parts = re.split("[:?/]+", self.protocol_extract(url_clean))
        domain = str.split(parts[0], ".")

        index = 0
    
        if IP_pat.match(parts[0]):
            mld = parts[0]
            domain_ip = 1
        else:
            domain_ip = 0
            if len(domain) == 1:
                mld = domain[0]
            else:
                domain2 = psl.get_public_suffix('.'.join(domain))
                tokens = domain2.split('.')
                mld = tokens[0]
                if mld == "":
                    mld = "Invalid_domain"

        #extract all words
        if index > 0:
            parts.extend(domain[0:index-1])   
        for label in parts[1:]: # split according to all nonalpha-numeric characters"
            words_temp.extend(re.split('[^a-zA-Z]',label))
        words2 = words_temp

        for w in words2:
            if len(w) > 2:
                if w in words:
                    words[w] += 1
                else:
                    words[w] = 1

        if domain_ip:
            return (parts[0],len(domain),mld,words,None)
        else:
            mldwords = re.split('[^a-zA-Z]',str.split(mld,".")[0])
            return (parts[0],len(domain),mld,words,mldwords)
