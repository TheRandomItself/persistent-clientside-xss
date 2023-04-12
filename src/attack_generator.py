# Copyright (C) 2019 Ben Stock & Marius Steffens
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from encodings import utf_8
import io
from generator import generate_exploit_for_finding
from pprint import pprint

import os
import shutil
import json

#the directory that contains all flows
src_dir = os.path.join(os.path.dirname(__file__), 'flows') 

#the directory that will contain all generated attacks
ex_dir = os.path.join(os.path.dirname(__file__), 'generated_attacks')

files_to_move = os.listdir(src_dir)

#generates attacks for all flows(if it can)
def main():
    for file_name in files_to_move:
        file_path = os.path.join(src_dir, file_name)
        exploit_file_path = os.path.join(ex_dir, file_name)
        print(file_name)

        with open(file_path, 'r') as f:
            contents = f.read()

        flow_obj = json.loads(contents.decode('utf8'))

        #trys to generate an attack for the flow
        exploit = generate_exploit_for_finding(flow_obj)

        if len(exploit) > 0:
            #if succeeded
            ex_str = json.dumps(exploit)
            print(ex_str.decode('utf8'))
            with open(exploit_file_path, 'w') as f:
                f.write(ex_str)


if __name__ == '__main__':
    main()
