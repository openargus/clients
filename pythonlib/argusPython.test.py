import tensorflow as tf
    
import numpy as np
import pandas as pd
import argusPython as aw


print(f"Dataset Testing Start")                             

if __name__ == '__main__':

    # load baseline
    aw.setBaseline("/usr/local/argus/archive/d91ba14b-e0e5-50e6-86de-534d5ede8b2c/.baseline.2024.01.25.out")
    print(f"Baseline done")                             

    # load data
    data = pd.read_csv('/tmp/argus.2024.01.09.flow.csv')


    # define categorical vs continuous variables
    categoricalNames = ['StartTime','SrcAddr','DstAddr','Proto','Sport','Dport']
    notCat = [f for f in filter(lambda x: x not in categoricalNames, data.columns)]
   
    # rearrange categorical columns to be first
    data = data[categoricalNames+notCat]

    print(f"Dataset Size: {data.shape[0]}")                             
   
    dataList = str(data.columns.values.tolist()).strip('[]')
    dataList = dataList.replace(" ","");
    dataList = dataList.replace("'","");

    aw.setSchema(dataList)

    print("dataList ",dataList)
    print(data)
