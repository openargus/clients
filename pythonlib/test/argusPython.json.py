import json
import logging
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # or any {'0', '1', '2'}

import argusPython as aw

if __name__ == '__main__':
   aw.argusInit()
   # load Argus baseline for matching

   print(f"Reading Json Argus Data")                             

   with open("argus.out.json", "r") as read_file:
       data = json.load(read_file)
   json_str = json.dumps(data, indent=2)
   
   print(json_str)
