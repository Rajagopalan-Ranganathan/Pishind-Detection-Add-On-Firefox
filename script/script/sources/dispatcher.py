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

from autobahn.twisted.websocket import WebSocketServerFactory,  WebSocketServerProtocol

import hashlib
from twisted.python import log
from twisted.internet import reactor
import random
import requests

from datetime import datetime, date
from urllib.parse import urlparse
import json
import sys
import traceback
import os
from os import path, mkdir
import csv

"""
--------------------------- SERVER ---------------------------
It handles request from the add on ad send the data to the workers.
Receive data from workers and send them back to the browser
"""


liveWebSockets = []
workers = []
identifiers = []
MessageError = {"type": "error", "message": "Wrong type format"}
whitelist = {}
whitelist_file = "whitelist"
statistics_file = "conf"
delay_file = "delay"
decision_file = "decisions"

token = "7JGHQTU4Y7IZNA5HBD7I"

root = "C:\\Program Log\\"

user_data = {}
user_data["n_phish"] = 0
user_data["n_leg"] = 0
user_data["n_white"] = 0
# 0 == no sync, 1 == stat on leg, phish, whitelist, 2 == all collected json
user_data["sync"] = 0
user_data["last_upload"] = None


def send_json_information():
    if os.name == "nt":
        os.system("send_website_data.exe")
    if os.name == "posix":
        os.system("./send_website_data.exe")


def check_last_upload():
    global user_data

    if user_data["sync"] == 0:
        return

    today = datetime.today()

    if user_data["last_upload"] is None or (today - user_data["last_upload"]).days > 7:
        print("sending")
        headers = {'Content-Type' : 'application/json'}
        jsonData = {}
        jsonData["phish"] = user_data["n_phish"]
        jsonData["leg"] = user_data["n_leg"]
        jsonData["whitelist"] = user_data["n_white"]
        jsonData["token"] = token
        try:
            r = requests.post('http://phishing.cs.hut.fi:1234/insert', data=json.dumps(jsonData).encode('utf-8'), headers=headers)
            if r.status_code == 200:
                print("Stat uploaded correctly")
                user_data["last_upload"] = datetime.today()
                user_data["n_phish"] = 0
                user_data["n_leg"] = 0
                user_data["n_white"] = 0
                write_statistics()

                if user_data["sync"] == 2:
                   send_json_information()
            else:
                print("Error during stat upload")
        except:
            print("Error during stat upload")


def load_statistics():
    global user_data

    if os.path.isfile(root + statistics_file):
        with open(root + statistics_file) as statfile:
            try:
                temp_data = json.load(statfile)
                user_data["n_phish"] = temp_data["n_phish"]
                user_data["n_leg"] = temp_data["n_leg"]
                user_data["n_white"] = temp_data["n_white"]
                user_data["sync"] = temp_data["sync"]
                date_format = "%Y-%m-%d"
                user_data["last_upload"] = datetime.strptime(temp_data["last_upload"], date_format)
            except:
                if "n_phish" not in temp_data:
                    user_data["n_phish"] = 0
                if "n_leg" not in temp_data:
                    user_data["n_leg"] = 0
                if "n_white" not in temp_data:
                    user_data["n_white"] = 0
                if "sync" not in temp_data:
                    user_data["sync"] = 0
    else:
        user_data["n_phish"] = 0
        user_data["n_leg"] = 0
        user_data["n_white"] = 0
        user_data["sync"] = 0


def write_statistics():
    global user_data
    date_format = "%Y-%m-%d"

    if user_data["sync"] == 0:
        user_data["n_phish"] = 0
        user_data["n_leg"] = 0
        user_data["n_white"] = 0

    if "last_upload" in user_data and user_data["last_upload"] is not None:
        user_data["last_upload"] = user_data["last_upload"].strftime(date_format)

    with open(root + statistics_file, "w", encoding="utf8") as f:
        f.write(json.dumps(user_data))

    if "last_upload" in user_data and user_data["last_upload"] is not None:
        user_data["last_upload"] = datetime.strptime(user_data["last_upload"], date_format)


def write_decision(site_id, user_decision):
    global user_data
    if user_data["sync"] != 0:
        with open(root + decision_file, "a") as myfile:
            myfile.write(site_id+","+user_decision+"\n")


def load_whitelist():
    if os.path.isfile(root + whitelist_file):
        with open(root + whitelist_file) as csvfile:
            websites_list = csv.reader(csvfile, delimiter=',')
            for row in websites_list:
                whitelist[row[0]] = row[1]


def create_ws_from_websocket_data(data):
    ws = data
    ws['siteid'] = hashlib.sha1(domain_from_URL(ws['landurl']).encode()).hexdigest()
    return ws

def domain_from_URL(landurl):
    parsed_uri = urlparse( landurl )
    domain = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
    return domain


# TODO: 0 == not phish, 1 == phish
def add_whitelist(siteid):
    whitelist[siteid] = '0'
    with open(root + whitelist_file, "a") as whiteFile:
        whiteFile.write(siteid+",0\n")


def check_in_whitelist(sitedata):
    if sitedata['siteid'] in whitelist:
        if whitelist[sitedata['siteid']] == '0':
            return True
    return False


def write_delay_log(data):
    data['delay']['result'] = data['phishResult']
    with open(root + delay_file, "a") as myfile:
        myfile.write(json.dumps(data['delay'])+"\n")


def choose_resource_path():
    global root
    if os.name == "nt":
        if not path.exists(root):
            mkdir(root)
    if os.name =="posix":
        root = ""


def check_request(res):
    if 'privacy' in res:
        return True
    if 'delay' in res:
        return True
    if 'decision' in res:
        if not 'siteid' in res:
            return False
        return True
    if 'auth' in res:
        return True
    if 'phish' in res:
        return True
    if 'addworker' in res:
        return True
    if 'addidentifier' in res:
        return True
    if 'target' in res:
        return True

    if 'starturl' not in res:
        return False
    if 'landurl' not in res:
        return False
    if 'source' not in res:
        return False
    if 'text' not in res:
        return False
    if 'redirections' not in res:
        return False
    if 'loglinks' not in res:
        return False
    if 'access_time' not in res:
        return False
    if 'title' not in res:
        return False
    return True


class MyServerProtocol(WebSocketServerProtocol):

    def onConnect(self, request):
        print("Client connecting: {}".format(request.peer))

    def onOpen(self):
        print("WebSocket connection open.")

    def onMessage(self, payload, isBinary):
        global liveWebSockets
        global user_data
        global workers
        global identifiers

        try:

            print(datetime.now().strftime("%H:%M:%S.%f")+" DISPATCHER -- Request received")

            if isBinary:
                # print("Binary message received: {} bytes".format(len(payload)))
                dict = json.loads(payload)
            else:
                # print("Text message received: {}".format(payload.decode('utf8')))
                if payload.decode('utf8') == 'undefined':
                    return
                dict = json.loads(payload.decode('utf8'))

            if not check_request(dict):
                print(datetime.now().strftime("%H:%M:%S.%f")+" DISPATCHER -- Unhandled message type received.")
                print(datetime.now().strftime("%H:%M:%S.%f")+" DISPATCHER -- Message: {}\n".format(dict))
                self.sendMessage(json.dumps(MessageError).encode('utf-8'), isBinary)
                return

            if 'delay' in dict:
                write_delay_log(dict)
                print(datetime.now().strftime("%H:%M:%S.%f")+" DISPATCHER -- Delay message received.")
                return

            if 'privacy' in dict:
                user_data["sync"] = dict["privacy"]
                write_statistics()
                print(datetime.now().strftime("%H:%M:%S.%f")+" DISPATCHER -- Privacy message received.")
                return

            if 'auth' in dict:
                # first message from the addon
                liveWebSockets.append(self)
                print(datetime.now().strftime("%H:%M:%S.%f")+" DISPATCHER -- authentication message received.")
                self.sendMessage(json.dumps({"privacy": user_data["sync"]}).encode('utf-8'), False)
                return

            if 'decision' in dict:
                if dict['decision'] == "continue":
                    if dict['whitelist']:
                        if dict['user']:
                            write_decision(dict['siteid'], "PROCEED_WHITELIST")
                        add_whitelist(dict['siteid'])
                    else:
                        write_decision(dict['siteid'], "PROCEED_NO_WHITELIST")
                if dict['decision'] == "exit":
                    if dict['google'] == True:
                        write_decision(dict['siteid'], "EXIT_GOOGLE")
                    else:
                        write_decision(dict['siteid'], "EXIT_DIRECT_LINK")
                print(datetime.now().strftime("%H:%M:%S.%f")+" DISPATCHER -- User's decision saved.")
                return

            if 'addworker' in dict:
                print(datetime.now().strftime("%H:%M:%S.%f")+" DISPATCHER -- Adding new worker.")
                worker = {}
                worker['busy'] = False
                worker['socket'] = self
                worker['count'] = 0
                workers.append(worker)
                return

            if 'addidentifier' in dict:
                print(datetime.now().strftime("%H:%M:%S.%f")+" DISPATCHER -- Adding new target identifier.")
                identifier = {}
                identifier['busy'] = False
                identifier['socket'] = self
                identifier['count'] = 0
                identifiers.append(identifier)
                return

            if 'phish' in dict:
                if dict['phish'] == True:
                    user_data["n_phish"] += 1
                else:
                    user_data["n_leg"] += 1
                write_statistics()

                for ws in workers:
                    if 'jspageid' in ws:
                        if ws['jspageid'] == dict['jspageid']:
                            ws['count'] -= 1
                            if ws['count'] == 0:
                                ws['busy'] = False

                # result from the worker
                for ws in liveWebSockets:
                    print(datetime.now().strftime("%H:%M:%S.%f")+" DISPATCHER -- result found for SITEID: "+str(dict['jspageid']))
                    ws.sendMessage(payload, isBinary)
                return

            if 'target' in dict:
                for fs in identifiers:
                    if 'jspageid' in fs:
                        if fs['jspageid'] == dict['jspageid']:
                            fs['count'] -= 1
                            if fs['count'] == 0:
                                fs['busy'] = False

                # result from the worker
                for fs in liveWebSockets:
                    print(datetime.now().strftime("%H:%M:%S.%f")+" DISPATCHER -- result found for SITEID: "+str(dict['jspageid']))
                    fs.sendMessage(payload, isBinary)
                return

            jsonData = create_ws_from_websocket_data(dict)

            # print(datetime.now().strftime("%H:%M:%S.%f")+" DISPATCHER -- Request received from the client for "+jsonData['starturl']+", SITEID: "+str(jsonData['jspageid']))

            check_last_upload()

            if check_in_whitelist(jsonData):
                user_data["n_white"] += 1
                write_statistics()

                easyResponse = {}
                easyResponse['jspageid'] = jsonData['jspageid']
                easyResponse['phish'] = False
                easyResponse['score'] = 0


                for ws in liveWebSockets:
                    print(datetime.now().strftime("%H:%M:%S.%f")+" DISPATCHER -- match in whitelist found  for SITEID: "+str(easyResponse['jspageid']))
                    ws.sendMessage(json.dumps(easyResponse).encode('utf-8'), isBinary)
                return

            find = False

            for ws in workers:
                if ws['busy'] == False and not find:
                    ws['socket'].sendMessage(json.dumps(jsonData).encode('utf-8'), isBinary)
                    ws['busy'] = True
                    ws['count'] = 1
                    ws['jspageid'] = dict['jspageid']
                    find = True

            if not find and len(workers) > 0:
                # no workers currently available, just choose one of them random
                selected = random.randint(0, len(workers)-1)
                workers[selected]['socket'].sendMessage(json.dumps(jsonData).encode('utf-8'), isBinary)
                workers[selected]['count'] += 1

            find = False

            for fs in identifiers:
                if fs['busy'] == False and not find:
                    fs['socket'].sendMessage(json.dumps(jsonData).encode('utf-8'), isBinary)
                    fs['busy'] = True
                    fs['count'] = 1
                    fs['jspageid'] = dict['jspageid']
                    find = True

            # no identifier currently available, just choose one of them random
            if not find and len(identifiers) > 0:
                selected = random.randint(0, len(identifiers)-1)
                identifiers[selected]['socket'].sendMessage(json.dumps(jsonData).encode('utf-8'), isBinary)
                identifiers[selected]['count'] += 1

            #print(datetime.now().strftime("%H:%M:%S.%f")+" DISPATCHER -- Request handled")
        except:
            print("Exception raised, contact the support center")
            traceback.print_exc(file=open(path.join(root, 'log_dis.txt'), 'a'))

    def onClose(self, wasClean, code, reason):
        global liveWebSockets
        global workers
        if self in liveWebSockets:
            liveWebSockets.remove(self)
        if self in workers:
            workers.remove(self)
        print("WebSocket connection closed: {}\n".format(reason))


########
# main #
########

if __name__ == '__main__':

    choose_resource_path()

    if len(sys.argv) == 3:
        ide = int(sys.argv[1])
        wor = int(sys.argv[2])

        if ide > 5:
            ide = 5
        if wor > 3:
            wor = 3

        for count in range(0, wor):
            os.system("python3 phishing_detector.py &")

        for count in range(0, ide):
            os.system("python3 target_identifier.py &")

    load_whitelist()
    load_statistics()

    #log.startLogging(sys.stdout)
    log.startLogging(open(path.join(root, 'log_dis.txt'), 'a'))

    factory = WebSocketServerFactory()
    factory.protocol = MyServerProtocol

    reactor.listenTCP(9000, factory)
    reactor.run()
