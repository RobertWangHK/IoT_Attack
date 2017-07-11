import filter_dynamic
import time
import json
import os
import numpy as np
from TPLInkPlugin import *

start_time = time.time()

def process_package(data_list):
    """Process captured package to delta form"""
    data_list = data_list.transpose()
    data_list_delta = np.array(map(lambda x: (int(round(x)) / 10) * 10, data_list[0]))
    data_list_delta = np.subtract(data_list_delta, data_list_delta[0])
    for i in range(1, len(data_list_delta)):
        data_list_delta[i] = data_list_delta[i] - data_list_delta[i-1]
    print data_list_delta
    return data_list_delta
    #data_list_temp = np.array(map(lambda x: (int(round(x)) / 10) * 10, data_list[0]))


def capture_hour():
    """Capture IoT traffic for time_length and store in Data folder"""
    #time_length = input("capture time period: ")
    temp_filter = filter_dynamic.Dynamic_Filter(time=time_length)
    packages = temp_filter.live_Capture()
    format_time = time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime())
    path = os.path.join(data_path, format_time)

    with open(path, "w") as output:
        json.dump(packages, output)
    output.close()

if __name__ == "__main__":
    capture_hour()




