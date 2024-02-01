import logging
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # or any {'0', '1', '2'}

import tensorflow as tf
import numpy as np
import pandas as pd
import argusPython as aw

print(f"Dataset Testing Start")                             

if __name__ == '__main__':
    # load Argus baseline for matching

    aw.argusInit()
#   aw.setArgusBaseline("baseline.2024.01.25.out")
#   print(f"Baseline done")                             

    aw.readArgusData("argus.2024.01.09.out")
    print(f"Argus Datafile done")                             

    # load data
    data = pd.read_csv('argus.2024.01.09.csv')

    # define categorical vs continuous variables
    categoricalNames = ['StartTime','SrcAddr','DstAddr','Proto','Sport','Dport']
    notCat = [f for f in filter(lambda x: x not in categoricalNames, data.columns)]
   
    # rearrange categorical columns to be first
    data = data[categoricalNames+notCat]

    print(f"Dataset Size: {data.shape[0]}")                             
   
    dataList = str(data.columns.values.tolist()).strip('[]')
    dataList = dataList.replace(" ","");
    dataList = dataList.replace("'","");

    aw.setArgusSchema(dataList)

    print("dataList ",dataList)
    print(data)
