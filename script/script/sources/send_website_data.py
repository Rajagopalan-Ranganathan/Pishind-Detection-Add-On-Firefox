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

import requests
import json
from os import walk, remove, getcwd

successes = 0
fails = 0
files = []
send = False

token = "7JGHQTU4Y7IZNA5HBD7I"

url = "http://phishing.cs.hut.fi"
# url = "http://localhost"
port = ":1234"

for (dirpath, dirnames, filenames) in walk("./websites"):
    files.extend(filenames)
    break

print("File in queue: " + str(files.__len__()))

for file in files:
    with open(getcwd()+"/websites/"+file) as f:
        send = False
        json_website = json.load(f)
        json_website['token'] = token

        headers = {'Content-Type': 'application/json'}
        r = requests.post(url+port+'/json', data=json.dumps(json_website).encode('utf-8'), headers=headers)
        if r.status_code == 200:
            send = True
            print("Json uploaded correctly")
            successes += 1
        else:
            print("Error during Json upload")
            fails += 1

    if send:
        remove(getcwd()+"/websites/"+file)


print("Upload complete, files correctly send: " + str(successes) + ", files that encounter an error: " + str(fails))
