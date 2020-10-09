# Copyright 2019 CyberArk, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import logging
import platform
import sys

if platform.system() == "Windows":
    import msvcrt

shouldExit = False


def readInput(caption, queue):
    sys.stdout.write("%s :" % caption)
    sys.stdout.flush()
    input_value = ""
    while True:
        if msvcrt.kbhit():
            byte_arr = msvcrt.getche()
            if ord(byte_arr) == 13:  # enter_key
                break
            elif ord(byte_arr) >= 32:  # space_char
                input_value += "".join(map(chr, byte_arr))
        global shoudExit
        if shouldExit:
            logging.info("User used the URL. No need for password input_value")
            return False

    queue.put(input_value)
    return True
