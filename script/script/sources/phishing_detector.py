# Author:   Giovanni Armano giovanni.armano@aalto.fi
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



from platform import architecture
from time import time
from random import randint
from datetime import datetime
from os import path, mkdir, name
import json
import pickle
from sys import stdout
from pandas import DataFrame
from extract_URL import Extractor

from autobahn.twisted.websocket import WebSocketClientProtocol, WebSocketClientFactory
from twisted.python import log
from twisted.internet import reactor, defer

import build_feat_vec
from website import Website

# windows only imports
import sklearn
from sklearn import ensemble

##########
# public #
##########

extractor = Extractor()

dlroot = "C:\\Program Log\\"
keep_track = False


def _predict_gb(mode, test, features, name):

    # the model must have been built on the same architecture
    if architecture()[0] == '32bit':
        name = name + "_32"

    f = open("gb_model_" + name + ".pkl", 'rb')
    clf = pickle.load(f)
    f.close()

    if mode % 10 == 1:
        threshold = .7
    else:
        threshold = .5

    preds = clf.predict_proba(test[features])
    if preds[0, 1] < threshold:
        prediction = 0
    else:
        prediction = 1

    return preds[0, 1], prediction

def JSONtoFile(jsonData, phish, siteid):
    global dlroot

    dirname = path.join(dlroot, 'websites')
    if not path.exists(dirname):
        mkdir(dirname)

    jspath = path.join(dirname, siteid + '.json')

    if phish:
        with open(jspath, 'w', encoding="utf8") as f:
            f.write(json.dumps(jsonData))
    else:
        smallInfo = {}
        smallInfo['siteid'] = siteid
        smallInfo['access_time'] = jsonData['access_time']
        smallInfo['landurl'] = jsonData['landurl']
        smallInfo['starturl'] = jsonData['starturl']
        smallInfo['redirections'] = jsonData['redirections']
        smallInfo['title'] = jsonData['title']

        with open(jspath, 'w', encoding="utf8") as f:
            f.write(json.dumps(smallInfo))

def analyse_URL(jsonData):
    """
    Decide whether a website is phishing using its keywords and a Google search
    based on those.

    Parameters
    ----------
    jsonData: contains site data

    """

    ws = Website(json=jsonData)

    print(datetime.now().strftime("%H:%M:%S.%f")+"-- building vector")

    # build feature vector

    feat_vec_temp = {}
    feat_vect_site = build_feat_vec.feature_vector(extractor, ws)
    feat_vec_temp[0] = feat_vect_site
    feat_vect = DataFrame(feat_vec_temp)
    feat_vect = feat_vect.transpose().fillna(0)

    # prediction using gradient boosing
    exp = "238"

    features = feat_vect.columns

    print(datetime.now().strftime("%H:%M:%S.%f")+"-- vector done, start gradient boosting:")

    scoregb, predictiongb = _predict_gb(1, feat_vect, features, exp)
    gb_results = scoregb, predictiongb

    print(datetime.now().strftime("%H:%M:%S.%f")+"-- gradient done")
    global keep_track
    if keep_track:
        if gb_results[1] == 1:
            JSONtoFile(jsonData, True, jsonData['siteid'])
        else:
            JSONtoFile(jsonData, False, jsonData['siteid'])

    return gb_results, jsonData['jspageid'], jsonData['siteid']


class MyWorkerProtocol(WebSocketClientProtocol):

    def __init__(self):
        self.workerId = randint(1, 100)
        self.count = 0

    def onConnect(self, request):
        print("Client connecting: {}".format(request.peer))

    def onOpen(self):
        self.workerId = randint(1, 100)
        self.count = 0
        print("WebSocket connection open.")
        dict = {}
        dict['addworker'] = "I'm a new worker"
        self.sendMessage(json.dumps(dict).encode('utf-8'), False)

    def onMessage(self, payload, isBinary):
        self.count += 1
        if isBinary:
            dict = json.loads(payload)
        else:
            if payload.decode('utf8') == 'undefined':
                return
            dict = json.loads(payload.decode('utf8'))

        no_confirm = True

        s = dict

        # print(datetime.now().strftime("%H:%M:%S.%f")+" WORKER -- website: "+s['starturl'])

        d = defer.Deferred()
        d.addCallback(analyse_URL)
        d.addCallback(self.sendResult)
        d.callback(s)

    def sendResult(self, res):
        resDict = {}
        resDict['jspageid'] = res[1]
        resDict['siteid'] = res[2]

        if res[0] != None:
            if res[0][1] == 1:
                resDict['phish'] = True
                resDict['score'] = res[0][0]
                # print('CLASSIFIER DECISION: Phish: ' + str(res[0][0]))
            else:
                resDict['phish'] = False
                resDict['score'] = res[0][0]
                # print('CLASSIFIER DECISION: Not phish: ' + str(res[0][0]))

        resJson = json.dumps(resDict).encode('utf-8')

        # print(datetime.now().strftime("%H:%M:%S.%f")+" WORKER -- Result: {}\n".format(resJson))
        self.sendMessage(resJson, False)

    def onClose(self, wasClean, code, reason):
        print("WebSocket connection closed: {}\n".format(reason))
        time.sleep(3)
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

    # log.startLogging(stdout)
    log.startLogging(open(path.join(dlroot, 'log_phi.txt'), 'a'))

    factory = WebSocketClientFactory(u"ws://127.0.0.1:9000", debug=False)
    factory.protocol = MyWorkerProtocol

    reactor.connectTCP("127.0.0.1", 9000, factory)
    reactor.run()