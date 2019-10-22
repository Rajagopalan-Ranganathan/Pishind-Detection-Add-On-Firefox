# Author:   Samuel Marchal samuel.marchal@aalto.fi,  Giovanni Armano giovanni.armano@aalto.fi
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

import os
import statistics
import math
import time
from urllib import parse
import re
import sys

from unidecode import unidecode
from website import Website
import pandas as pd
import datetime

IP_pat = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

def cleanString(s):
    s = unidecode(s)
    s = re.sub('\n',' ',s)
    s = re.sub('\t',' ',s)
    return str.lower(s)

def cleanURL(s):    # clean the domain names obtained to respect the DNS rules
    if s[:2] == "b'":
        s = s[2:len(s)-1]
    s = parse.unquote(s)
    return str.lower(unidecode(s))

def mergeset(l1,l2):
    if l2 != None:
        for element in l2:
            if len(element) > 2:
                if element in l1:
                    l1[element] += 1
                else:
                    l1[element] = 1 

def merge(l1,l2):
    for element,count in l2.items():
        if element in l1:
           l1[element] += 1
        else:
           l1[element] = 1 



def loadWordList(thefile):

    f = open(thefile,'r', encoding="utf8")
    label_vector = []
    for line in f:
        label = line.strip().split(" ")
        label_vector.append(label[0])
    f.close()

    return label_vector


def jaccard2(dic1, dic2):

    if len(dic1) == 0 or len(dic2) == 0:
        return 0

    count_inter = 0
    count_comp = 0
    for element,count in dic1.items():
        if element in dic2:
           count_inter += dic2[element] + count
        else:
           count_comp += count

    for element,count in dic2.items():
        if element not in dic1:
           count_comp += count

    return float(count_inter) / float(count_inter+count_comp)


def jaccard(dic1, dic2): #hellinger distance
    
    if len(dic1) == 0 or len(dic2) == 0:
        return 1.0
    
    h2 = 0
    count_dic1 = float(sum(dic1.values()))
    count_dic2 = float(sum(dic2.values()))


    for element,count in dic1.items():
        if element in dic2:
            h2 += math.pow(math.sqrt(float(dic2[element])/count_dic2) - math.sqrt(float(count)/count_dic1),2)
        else:
            h2 += float(count)/count_dic1

    for element,count in dic2.items():
        if element not in dic1:
            h2 += float(dic2[element])/count_dic2

    return h2/2


def fill_empty(vect):
    if vect == []:
        return [0,0]
    elif len(vect) == 1:
        return [vect[0],vect[0]]
    else:
        return vect


################### main function

def feature_vector(extractor,ws):


    ############## variables declaration
    phishers_mld = set()
    mld_source_ext = set()
    mld_href_ext = set()
    phish_mldlist = {}
    other_mldlist = {}
    other_word = {}
    phish_word = {}
    href_other_word = {}
    href_phish_word = {}
    source_in = 0
    source_out = 0

    proto_other = []
    levels_other = []
    url_len_other = []
    domain_len_other = []
    mld_len_other = []
    word_mld_other = []
    word_len_other = []

    proto_phish = []
    levels_phish = []
    url_len_phish = []
    domain_len_phish = []
    mld_len_phish = []
    word_mld_phish = []
    word_len_phish = []

    href_in = 0
    href_out = 0

    proto_href_other = []
    levels_href_other = []
    url_len_href_other = []
    domain_len_href_other = []
    mld_len_href_other = []
    word_mld_href_other = []
    word_len_href_other = []

    proto_href_phish = []
    levels_href_phish = []
    url_len_href_phish = []
    domain_len_href_phish = []
    mld_len_href_phish = []
    word_mld_href_phish = []
    word_len_href_phish = []

    offset = 118
    feat_vect = dict((el,0) for el in range(offset + 92))

    ############### features extraction for starting URL feat[118-125]
    print(datetime.datetime.now().strftime("%H:%M:%S.%f")+"-- features extraction for starting URL feat[94-114]:")

    starturl = cleanURL(ws.starturl)
    domain,levels,mld,word,mldlist = extractor.extract_words(starturl)
    start_word = word
    start_mldlist = mldlist
    start_mld = "=="
    phishers_mld.add(mld)

    if mldlist == None:
        feat_vect[offset] = 2
        feat_vect[offset+3] = len(starturl)
        feat_vect[offset+7] = len(word)

    else:
        start_mld = mld
        if len(start_mldlist) > 1:
            start_mldlist.append(mld)
        mergeset(phish_mldlist,start_mldlist)
        feat_vect[offset] = extractor.proto # https connection
        feat_vect[offset+1] = levels # count of level domain
        feat_vect[offset+2] = len(starturl) # url character length
        feat_vect[offset+3] = len(domain) # DN character length
        feat_vect[offset+4] = len(mld) # mld character length
        feat_vect[offset+5] = len(mldlist) # count of labels in mld
        feat_vect[offset+6] = len(word) # count of labels in URL
        feat_vect[offset+7] = len(starturl.split('.')) - levels


    #################### features extraction for landing URL feat[126-133]
    print(datetime.datetime.now().strftime("%H:%M:%S.%f")+"-- features extraction for landing URL feat[115-135]:")
    offset += 8

    landurl = cleanURL(ws.landurl)
    domain,levels,mld,word,mldlist = extractor.extract_words(landurl)
    land_word = word
    land_mldlist = mldlist
    land_mld = "=="


    if mld not in phishers_mld:
        phishers_mld.add(mld)
        feat_vect[0] = 0 #starting = landing mld
    else:
        feat_vect[0] = 1

    if mldlist == None:
        feat_vect[offset] = 2
        feat_vect[offset+3] = len(landurl)
        feat_vect[offset+7] = len(word)

    else:
        land_mld = mld
        if len(land_mldlist) > 1:
            land_mldlist.append(mld)
        mergeset(phish_mldlist,land_mldlist)
        feat_vect[offset] = extractor.proto
        feat_vect[offset+1] = levels
        feat_vect[offset+2] = len(landurl)
        feat_vect[offset+3] = len(domain)
        feat_vect[offset+4] = len(mld)
        feat_vect[offset+5] = len(mldlist)
        feat_vect[offset+6] = len(word)
        feat_vect[offset+7] = len(landurl.split('.')) - levels


    ##################### redirection related features
    print(datetime.datetime.now().strftime("%H:%M:%S.%f")+"-- redirection related features:")

    for url in ws.redirections[1:]:
        domain,levels,mld,word,mldlist = extractor.extract_words(cleanURL(url))
        phishers_mld.add(mld)

        if mldlist != None:
            if len(mldlist) > 1:
                mldlist.append(mld)
            mergeset(phish_mldlist,mldlist)


    ############### feature extraction from loglink (2 treatments: phishers dom / external)
    print(datetime.datetime.now().strftime("%H:%M:%S.%f")+"-- feature extraction from loglink (2 treatments: phishers dom / external):")

    offset += 8

    for url in ws.loglinks:
        domain,levels,mld,word,mldlist = extractor.extract_words(cleanURL(url))

        if mld in phishers_mld:
            source_in += 1
            merge(phish_word,word)
            if mldlist == None:
                proto_phish.append(extractor.proto)
                url_len_phish.append(len(url))
                word_len_phish.append(len(word))
            else:
                proto_phish.append(extractor.proto)
                levels_phish.append(levels)
                url_len_phish.append(len(url))
                domain_len_phish.append(len(domain))
                mld_len_phish.append(len(mld))
                word_mld_phish.append(len(mldlist))
                word_len_phish.append(len(word))


        elif mld != "Invalid_domain" and str.split(mld,".")[0] != "mozilla" and str.split(mld,".")[0] != "digicert":
            source_out += 1
            merge(other_word,word)
            if mld not in mld_source_ext:
                mld_source_ext.add(mld)
                if mldlist != None and len(mldlist) > 1:
                    mldlist.append(mld)
                mergeset(other_mldlist,mldlist)

            if mldlist == None:
                proto_other.append(extractor.proto)
                url_len_other.append(len(url))
                word_len_other.append(len(word))
            else:
                proto_other.append(extractor.proto)
                levels_other.append(levels)
                url_len_other.append(len(url))
                domain_len_other.append(len(domain))
                mld_len_other.append(len(mld))
                word_mld_other.append(len(mldlist))
                word_len_other.append(len(word))


    ######################################## some features

    proto_other = fill_empty(proto_other)
    levels_other = fill_empty(levels_other)
    url_len_other = fill_empty(url_len_other)
    domain_len_other = fill_empty(domain_len_other)
    mld_len_other = fill_empty(mld_len_other)
    word_mld_other = fill_empty(word_mld_other)
    word_len_other = fill_empty(word_len_other)

    proto_phish = fill_empty(proto_phish)
    levels_phish = fill_empty(levels_phish)
    url_len_phish = fill_empty(url_len_phish)
    domain_len_phish = fill_empty(domain_len_phish)
    mld_len_phish = fill_empty(mld_len_phish)
    word_mld_phish = fill_empty(word_mld_phish)
    word_len_phish = fill_empty(word_len_phish)

    ########################### features phishing ressources feat[134-152]
    print(datetime.datetime.now().strftime("%H:%M:%S.%f")+"-- features phishing ressources feat[136-169]:")

    feat_vect[offset] = float(sum(proto_phish))/float(len(proto_phish)) # ratio of secure connection
    feat_vect[offset+1] = statistics.mean(word_len_phish) # count of labels url stats
    feat_vect[offset+2] = statistics.median_low(word_len_phish)
    feat_vect[offset+3] = statistics.stdev(word_len_phish)
    feat_vect[offset+4] = statistics.mean(levels_phish) # level domains stats
    feat_vect[offset+5] = statistics.median_low(levels_phish)
    feat_vect[offset+6] = statistics.stdev(levels_phish)
    feat_vect[offset+7] = statistics.mean(url_len_phish) # url characters length stats
    feat_vect[offset+8] = statistics.median_low(url_len_phish)
    feat_vect[offset+9] = statistics.stdev(url_len_phish)
    feat_vect[offset+10] = statistics.mean(domain_len_phish) # domain characters length stats
    feat_vect[offset+11] = statistics.median_low(domain_len_phish)
    feat_vect[offset+12] = statistics.stdev(domain_len_phish)
    feat_vect[offset+13] = statistics.mean(mld_len_phish) # mld characters length stats
    feat_vect[offset+14] = statistics.median_low(mld_len_phish)
    feat_vect[offset+15] = statistics.stdev(mld_len_phish)
    feat_vect[offset+16] = statistics.mean(word_mld_phish) # count of labels mld stats
    feat_vect[offset+17] = statistics.median_low(word_mld_phish)
    feat_vect[offset+18] = statistics.stdev(word_mld_phish)


    #################################### features external ressources feat[153-171]

    offset += 19
    feat_vect[offset] = float(sum(proto_other))/float(len(proto_other))
    feat_vect[offset+1] = statistics.mean(word_len_other)
    feat_vect[offset+2] = statistics.median_low(word_len_other)
    feat_vect[offset+3] = statistics.stdev(word_len_other)
    feat_vect[offset+4] = statistics.mean(levels_other)
    feat_vect[offset+5] = statistics.median_low(levels_other)
    feat_vect[offset+6] = statistics.stdev(levels_other)
    feat_vect[offset+7] = statistics.mean(url_len_other)
    feat_vect[offset+8] = statistics.median_low(url_len_other)
    feat_vect[offset+9] = statistics.stdev(url_len_other)
    feat_vect[offset+10] = statistics.mean(domain_len_other)
    feat_vect[offset+11] = statistics.median_low(domain_len_other)
    feat_vect[offset+12] = statistics.stdev(domain_len_other)
    feat_vect[offset+13] = statistics.mean(mld_len_other)
    feat_vect[offset+14] = statistics.median_low(mld_len_other)
    feat_vect[offset+15] = statistics.stdev(mld_len_other)
    feat_vect[offset+16] = statistics.mean(word_mld_other)
    feat_vect[offset+17] = statistics.median_low(word_mld_other)
    feat_vect[offset+18] = statistics.stdev(word_mld_other)


    ###################### href features extraction
    print(datetime.datetime.now().strftime("%H:%M:%S.%f")+"-- href features extraction:")

    href_ext = ws.source_links_ext
    href = ws.source_links
    offset += 19


    for url in href_ext:
        domain,levels,mld,word,mldlist = extractor.extract_words(cleanURL(url))

        if mld in phishers_mld:
            merge(href_phish_word,word)
            if mldlist == None:
                proto_href_phish.append(extractor.proto)
                url_len_href_phish.append(len(url))
                word_len_href_phish.append(len(word))
            else:
                proto_href_phish.append(extractor.proto)
                levels_href_phish.append(levels)
                url_len_href_phish.append(len(url))
                domain_len_href_phish.append(len(domain))
                mld_len_href_phish.append(len(mld))
                word_mld_href_phish.append(len(mldlist))
                word_len_href_phish.append(len(word))

        elif mld != "Invalid_domain":
            href_out += 1
            merge(href_other_word,word)
            mld_href_ext.add(mld)
            if mldlist == None:
                proto_href_other.append(extractor.proto)
                url_len_href_other.append(len(url))
                word_len_href_other.append(len(word))
            else:
                proto_href_other.append(extractor.proto)
                levels_href_other.append(levels)
                url_len_href_other.append(len(url))
                domain_len_href_other.append(len(domain))
                mld_len_href_other.append(len(mld))
                word_mld_href_other.append(len(mldlist))
                word_len_href_other.append(len(word))


    # href features
    print(datetime.datetime.now().strftime("%H:%M:%S.%f")+"-- href features:")

    feat_vect[1] = len(ws.redirections) # count of redirections
    feat_vect[2] = len(ws.redirections) - len(phishers_mld) + 1 # count of redirections with no changing DN
    feat_vect[3] = len(phishers_mld) + 1 # count of internal DN
    feat_vect[4] = len(mld_source_ext) # count of external source DN
    feat_vect[5] = len(mld_href_ext) # count of external HREF DN
    feat_vect[7] = len(ws.loglinks) # count of logged ressources
    feat_vect[8] = len(href) # count of href

    if len(ws.loglinks) > 0:
        feat_vect[9] = float(source_out) / float(len(ws.loglinks)) # ratio of ressources from external DN / total ressources
        feat_vect[10] = float(source_in) / float(len(ws.loglinks)) # ratio of ressources from internal DN / total ressources

    if href_out > 0 and len(href) > 0:
        feat_vect[6] = float(len(mld_source_ext.intersection(mld_href_ext))) / float(len(mld_source_ext.union(mld_href_ext))) # jaccard index between external HREF DN and external HREF resource
        feat_vect[11] = float(href_out) / float(len(href)) # ratio of href to external DN
        feat_vect[12] = (float(len(href)) - float(href_out)) / float(len(href)) # ratio of href to internal DN

    proto_href_other = fill_empty(proto_href_other)
    levels_href_other = fill_empty(levels_href_other)
    url_len_href_other = fill_empty(url_len_href_other)
    domain_len_href_other = fill_empty(domain_len_href_other)
    mld_len_href_other = fill_empty(mld_len_href_other)
    word_mld_href_other = fill_empty(word_mld_href_other)
    word_len_href_other = fill_empty(word_len_href_other)

    proto_href_phish = fill_empty(proto_href_phish)
    levels_href_phish = fill_empty(levels_href_phish)
    url_len_href_phish = fill_empty(url_len_href_phish)
    domain_len_href_phish = fill_empty(domain_len_href_phish)
    mld_len_href_phish = fill_empty(mld_len_href_phish)
    word_mld_href_phish = fill_empty(word_mld_href_phish)
    word_len_href_phish = fill_empty(word_len_href_phish)

    # feat[172-190]
    feat_vect[offset] = float(sum(proto_href_phish))/float(len(proto_href_phish))
    feat_vect[offset+1] = statistics.mean(word_len_href_phish)
    feat_vect[offset+2] = statistics.median_low(word_len_href_phish)
    feat_vect[offset+3] = statistics.stdev(word_len_href_phish)
    feat_vect[offset+4] = statistics.mean(levels_href_phish)
    feat_vect[offset+5] = statistics.median_low(levels_href_phish)
    feat_vect[offset+6] = statistics.stdev(levels_href_phish)
    feat_vect[offset+7] = statistics.mean(url_len_href_phish)
    feat_vect[offset+8] = statistics.median_low(url_len_href_phish)
    feat_vect[offset+9] = statistics.stdev(url_len_href_phish)
    feat_vect[offset+10] = statistics.mean(domain_len_href_phish)
    feat_vect[offset+11] = statistics.median_low(domain_len_href_phish)
    feat_vect[offset+12] = statistics.stdev(domain_len_href_phish)
    feat_vect[offset+13] = statistics.mean(mld_len_href_phish)
    feat_vect[offset+14] = statistics.median_low(mld_len_href_phish)
    feat_vect[offset+15] = statistics.stdev(mld_len_href_phish)
    feat_vect[offset+16] = statistics.mean(word_mld_href_phish)
    feat_vect[offset+17] = statistics.median_low(word_mld_href_phish)
    feat_vect[offset+18] = statistics.stdev(word_mld_href_phish)

    # feat[191-209]
    offset += 19
    feat_vect[offset] = float(sum(proto_href_other))/float(len(proto_href_other))
    feat_vect[offset+1] = statistics.mean(word_len_href_other)
    feat_vect[offset+2] = statistics.median_low(word_len_href_other)
    feat_vect[offset+3] = statistics.stdev(word_len_href_other)
    feat_vect[offset+4] = statistics.mean(levels_href_other)
    feat_vect[offset+5] = statistics.median_low(levels_href_other)
    feat_vect[offset+6] = statistics.stdev(levels_href_other)
    feat_vect[offset+7] = statistics.mean(url_len_href_other)
    feat_vect[offset+8] = statistics.median_low(url_len_href_other)
    feat_vect[offset+9] = statistics.stdev(url_len_href_other)
    feat_vect[offset+10] = statistics.mean(domain_len_href_other)
    feat_vect[offset+11] = statistics.median_low(domain_len_href_other)
    feat_vect[offset+12] = statistics.stdev(domain_len_href_other)
    feat_vect[offset+13] = statistics.mean(mld_len_href_other)
    feat_vect[offset+14] = statistics.median_low(mld_len_href_other)
    feat_vect[offset+15] = statistics.stdev(mld_len_href_other)
    feat_vect[offset+16] = statistics.mean(word_mld_href_other)
    feat_vect[offset+17] = statistics.median_low(word_mld_href_other)
    feat_vect[offset+18] = statistics.stdev(word_mld_href_other)


    ##################### text content features
    print(datetime.datetime.now().strftime("%H:%M:%S.%f")+"-- text content features: text_words")

    text_words = []
    title_words = []

    for element in re.split("\s+",ws.text_without_title):
        record = 1
        tokens = re.split("[^a-z]+",cleanString(element))
        for token in tokens:
            if len(token) == 0:
                record = 0
            if len(token) > 2:
                text_words.append(token)
        if record and len(tokens)>1:
            text_words.append(cleanString(element))


    print(datetime.datetime.now().strftime("%H:%M:%S.%f")+"-- text content features: title_words")

    for element in ws.title.split(" "):
        record = 1
        tokens = re.split("[^a-z]+",cleanString(element))
        for token in tokens:
            if len(token) == 0:
                record = 0
            if len(token) > 2:
                title_words.append(token)
        if record and len(tokens)>1:
            title_words.append(cleanString(element))

    print(datetime.datetime.now().strftime("%H:%M:%S.%f")+"-- inputs and images")

    feat_vect[15] = ws.input_count
    feat_vect[16] = ws.image_count


    ######### relatedness features
    print(datetime.datetime.now().strftime("%H:%M:%S.%f")+"-- relatedness features:")

    text_words_dic = {}
    mergeset(text_words_dic,text_words)
    title_words_dic = {}
    mergeset(title_words_dic,title_words)
    land_mlddic = {}
    mergeset(land_mlddic,land_mldlist)
    start_mlddic = {}
    mergeset(start_mlddic,start_mldlist)

    feat_vect[13] = len(text_words)
    feat_vect[14] = len(title_words)


    feat_vect[17] = jaccard(title_words_dic, land_word)
    feat_vect[18] = jaccard(title_words_dic, start_word)
    feat_vect[19] = jaccard(title_words_dic, land_mlddic) # good indicator ?
    feat_vect[20] = jaccard(title_words_dic, start_mlddic) # good indicator ?
    feat_vect[21] = jaccard(title_words_dic, phish_mldlist) # good indicator ?
    feat_vect[22] = jaccard(title_words_dic, other_mldlist) # good indicator ?
    feat_vect[23] = jaccard(title_words_dic, phish_word)
    feat_vect[24] = jaccard(title_words_dic, other_word)
    feat_vect[25] = jaccard(title_words_dic, href_phish_word)
    feat_vect[26] = jaccard(title_words_dic, href_other_word)
    feat_vect[27] = jaccard(title_words_dic, text_words_dic)

    feat_vect[28] = jaccard(text_words_dic, land_word)
    feat_vect[29] = jaccard(text_words_dic, start_word)
    feat_vect[30] = jaccard(text_words_dic, land_mlddic)
    feat_vect[31] = jaccard(text_words_dic, start_mlddic)
    feat_vect[32] = jaccard(text_words_dic, phish_mldlist) # good indicator ? yes
    feat_vect[33] = jaccard(text_words_dic, other_mldlist) # good indicator ?
    feat_vect[34] = jaccard(text_words_dic, phish_word)
    feat_vect[35] = jaccard(text_words_dic, other_word)
    feat_vect[36] = jaccard(text_words_dic, href_phish_word)
    feat_vect[37] = jaccard(text_words_dic, href_other_word)

    feat_vect[38] = jaccard(start_mlddic,land_word)
    feat_vect[39] = jaccard(start_mlddic,start_word)
    feat_vect[40] = jaccard(start_mlddic,land_mlddic)
    feat_vect[41] = jaccard(start_mlddic,phish_mldlist)
    feat_vect[42] = jaccard(start_mlddic,other_mldlist) # good indicator ?
    feat_vect[43] = jaccard(start_mlddic,phish_word)
    feat_vect[44] = jaccard(start_mlddic,other_word)
    feat_vect[45] = jaccard(start_mlddic,href_phish_word)
    feat_vect[46] = jaccard(start_mlddic,href_other_word)

    feat_vect[47] = jaccard(land_mlddic,land_word)
    feat_vect[48] = jaccard(land_mlddic,start_word)
    feat_vect[49] = jaccard(land_mlddic,phish_mldlist)
    feat_vect[50] = jaccard(land_mlddic,other_mldlist) # good indicator ?
    feat_vect[51] = jaccard(land_mlddic,phish_word)
    feat_vect[52] = jaccard(land_mlddic,other_word)
    feat_vect[53] = jaccard(land_mlddic,href_phish_word)
    feat_vect[54] = jaccard(land_mlddic,href_other_word)

    feat_vect[55] = jaccard(phish_mldlist,land_word)
    feat_vect[56] = jaccard(phish_mldlist,start_word)
    feat_vect[57] = jaccard(phish_mldlist, other_mldlist)
    feat_vect[58] = jaccard(phish_mldlist, phish_word)
    feat_vect[59] = jaccard(phish_mldlist, other_word)
    feat_vect[60] = jaccard(phish_mldlist, href_other_word)
    feat_vect[61] = jaccard(phish_mldlist, href_phish_word)

    feat_vect[62] = jaccard(other_mldlist,land_word)
    feat_vect[63] = jaccard(other_mldlist,start_word)
    feat_vect[64] = jaccard(other_mldlist, other_word)
    feat_vect[65] = jaccard(other_mldlist, phish_word)
    feat_vect[66] = jaccard(other_mldlist, href_other_word)
    feat_vect[67] = jaccard(other_mldlist, href_phish_word)

    feat_vect[68] = jaccard(phish_word,land_word)
    feat_vect[69] = jaccard(phish_word,start_word)
    feat_vect[70] = jaccard(phish_word, other_word)
    feat_vect[71] = jaccard(phish_word, href_other_word)
    feat_vect[72] = jaccard(phish_word, href_phish_word)

    feat_vect[73] = jaccard(other_word,land_word)
    feat_vect[74] = jaccard(other_word,start_word)
    feat_vect[75] = jaccard(other_word, href_other_word)
    feat_vect[76] = jaccard(other_word, href_phish_word)

    feat_vect[77] = jaccard(href_phish_word, href_other_word)
    feat_vect[78] = jaccard(href_phish_word, land_word)
    feat_vect[79] = jaccard(href_phish_word, start_word)

    feat_vect[80] = jaccard(href_other_word, land_word)
    feat_vect[81] = jaccard(href_other_word, start_word)

    feat_vect[82] = jaccard(start_word, land_word)


    if start_mld in other_word:
        feat_vect[83] = 1
    if start_mld in phish_word:
        feat_vect[84] = 1
    if start_mld in href_other_word:
        feat_vect[85] = 1
    if start_mld in href_phish_word:
        feat_vect[86] = 1
    if start_mld in title_words_dic:
        feat_vect[87] = 1
    if start_mld in text_words_dic:
        feat_vect[88] = 1

    if land_mld in other_word:
        feat_vect[89] = 1
    if land_mld in phish_word:
        feat_vect[90] = 1
    if land_mld in href_other_word:
        feat_vect[91] = 1
    if land_mld in href_phish_word:
        feat_vect[92] = 1
    if land_mld in title_words_dic:
        feat_vect[93] = 1
    if land_mld in text_words_dic:
        feat_vect[94] = 1

    feat_vect[95] = ws.external_source #external sources of code

    if feat_vect[21] > 0.:
        feat_vect[96] = 1
    if feat_vect[22] > 0.:
        feat_vect[97] = 1

    # title words in starting and landing URL
    print(datetime.datetime.now().strftime("%H:%M:%S.%f")+"-- title words in starting and landing URL:")
    count_occ = 0
    starturlcount = 0
    startmldcount = 0
    landurlcount = 0
    landmldcount = 0
    for label, occ in title_words_dic.items():
        count_occ += occ
        if start_mld.find(label) < 0:
            if starturl.find(label) > -1:
                starturlcount += occ
        else:
            startmldcount += occ

        if land_mld.find(label) < 0:
            if landurl.find(label) > -1:
                landurlcount += occ
        else:
            landmldcount += occ

    if count_occ != 0:
        feat_vect[98] = math.sqrt(float(starturlcount)) / math.sqrt(float(count_occ))
        feat_vect[99] = math.sqrt(float(startmldcount)) / math.sqrt(float(count_occ))
        feat_vect[100] = math.sqrt(float(landurlcount)) / math.sqrt(float(count_occ))
        feat_vect[101] = math.sqrt(float(landmldcount)) / math.sqrt(float(count_occ))


    # text words in starting and landing URL
    count_occ = 0
    starturlcount = 0
    startmldcount = 0
    landurlcount = 0
    landmldcount = 0
    for label, occ in text_words_dic.items():
        count_occ += occ
        if start_mld.find(label) < 0:
            if starturl.find(label) > -1:
                starturlcount += occ
        else:
            startmldcount += occ

        if land_mld.find(label) < 0:
            if landurl.find(label) > -1:
                landurlcount += occ
        else:
            landmldcount += occ

    if count_occ != 0:
        feat_vect[102] = math.sqrt(float(starturlcount)) / math.sqrt(float(count_occ))
        feat_vect[103] = math.sqrt(float(startmldcount)) / math.sqrt(float(count_occ))
        feat_vect[104] = math.sqrt(float(landurlcount)) / math.sqrt(float(count_occ))
        feat_vect[105] = math.sqrt(float(landmldcount)) / math.sqrt(float(count_occ))


    # external RDN words in starting and landing URL
    count_occ = 0
    starturlcount = 0
    startmldcount = 0
    landurlcount = 0
    landmldcount = 0
    for label, occ in other_mldlist.items():
        count_occ += occ
        if start_mld.find(label) < 0:
            if starturl.find(label) > -1:
                starturlcount += occ
        else:
            startmldcount += occ

        if land_mld.find(label) < 0:
            if landurl.find(label) > -1:
                landurlcount += occ
        else:
            landmldcount += occ

    if count_occ != 0:
        feat_vect[106] = math.sqrt(float(starturlcount)) / math.sqrt(float(count_occ))
        feat_vect[107] = math.sqrt(float(startmldcount)) / math.sqrt(float(count_occ))
        feat_vect[108] = math.sqrt(float(landurlcount)) / math.sqrt(float(count_occ))
        feat_vect[109] = math.sqrt(float(landmldcount)) / math.sqrt(float(count_occ))


    # external logged links words in starting and landing URL
    print(datetime.datetime.now().strftime("%H:%M:%S.%f")+"-- external logged links words in starting and landing URL:")
    count_occ = 0
    starturlcount = 0
    startmldcount = 0
    landurlcount = 0
    landmldcount = 0
    for label, occ in other_word.items():
        count_occ += occ
        if start_mld.find(label) < 0:
            if starturl.find(label) > -1:
                starturlcount += occ
        else:
            startmldcount += occ

        if land_mld.find(label) < 0:
            if landurl.find(label) > -1:
                landurlcount += occ
        else:
            landmldcount += occ

    if count_occ != 0:
        feat_vect[110] = math.sqrt(float(starturlcount)) / math.sqrt(float(count_occ))
        feat_vect[111] = math.sqrt(float(startmldcount)) / math.sqrt(float(count_occ))
        feat_vect[112] = math.sqrt(float(landurlcount)) / math.sqrt(float(count_occ))
        feat_vect[113] = math.sqrt(float(landmldcount)) / math.sqrt(float(count_occ))


    # external href links words in starting and landing URL
    print(datetime.datetime.now().strftime("%H:%M:%S.%f")+"-- external href links words in starting and landing URL:")
    count_occ = 0
    starturlcount = 0
    startmldcount = 0
    landurlcount = 0
    landmldcount = 0
    for label, occ in href_other_word.items():
        count_occ += occ
        if start_mld.find(label) < 0:
            if starturl.find(label) > -1:
                starturlcount += occ
        else:
            startmldcount += occ

        if land_mld.find(label) < 0:
            if landurl.find(label) > -1:
                landurlcount += occ
        else:
            landmldcount += occ

    if count_occ != 0:
        feat_vect[114] = math.sqrt(float(starturlcount)) / math.sqrt(float(count_occ))
        feat_vect[115] = math.sqrt(float(startmldcount)) / math.sqrt(float(count_occ))
        feat_vect[116] = math.sqrt(float(landurlcount)) / math.sqrt(float(count_occ))
        feat_vect[117] = math.sqrt(float(landmldcount)) / math.sqrt(float(count_occ))


    return feat_vect


current_milli_time = lambda: int(round(time.time() * 1000))

if __name__=="__main__":

    if len(sys.argv) != 4:
        print("usage: build_feat_vec.py webiste_dir prefix label(0:leg/1:phish)")
    else:

        sys.setrecursionlimit(10000)
        websitedir = os.path.abspath(sys.argv[1])
        extractor = Extractor()
        label = int(sys.argv[3])
        feat_vec_temp = {}
        #fson = open("phish_brand.txt",'r')
        i = 0
        
        pd.set_option('display.max_rows', 1000)
        
        time_stats = open("timestats2.csv",'w', encoding="utf8")
        
        for f in sorted(os.listdir(websitedir)):
            start_time = current_milli_time()

            if f.find(".json") > 0:
             ws = Website(websitedir + "/" + f)
             intermediate = current_milli_time()
             feat_vect_site = feature_vector(extractor,ws)
             end_time = current_milli_time()
             time_stats.write(str(intermediate-start_time) + "," + str(end_time-intermediate) + "\n")
             feat_vect_site["start_url"] = f
             feat_vect_site["label"] = label
             feat_vec_temp[i] = feat_vect_site
             i += 1
             print(ws.starturl)

            elif f.find(".png") < 0:
             ws = Website(websitedir + "/" + f + "/sitedata.json")
             intermediate = current_milli_time()
             feat_vect_site = feature_vector(extractor,ws)
             end_time = current_milli_time()
             time_stats.write(str(intermediate-start_time) + "," + str(end_time-intermediate) + "\n")
             feat_vect_site["start_url"] = ws.starturl
             feat_vect_site["label"] = label
             feat_vec_temp[i] = feat_vect_site
             i += 1
             print(ws.starturl)

        time_stats.close()
        featvecmat = pd.DataFrame(feat_vec_temp)
        featvecmat.transpose().to_pickle(sys.argv[2] + "_fvm.pkl")

        
