import json
import os

from time import time
import numpy as np
import matplotlib.pyplot as plt

from sklearn import metrics
from sklearn.cluster import KMeans
from sklearn.datasets import load_digits
from sklearn.decomposition import PCA
from sklearn.preprocessing import scale

data_path = "../Data/ML_Feed"
file_name = "feed_plugin"

valid_ip = ["192.168.1.4", "192.168.1.6"]
command_list= ["schedule_get_rule", "anti_theft", "netif", "system_get_info"
               "system_set_state_1", "system_set_state_0", "count_down", "time", "cnCloud"]

class parse:

    def __init__(self):
        self.features = np.zeros(shape=(1, 6))                #data size
        self.labels = []

    def load_raw(self):
        """read and parse raw data from feed_plugin"""

        with open(os.path.join(data_path, file_name)) as input:
            packages = json.load(input)
        input.close()

        IP_Delta = np.array(packages[2]["192.168.1.4"]).transpose()
        IP_Package = np.array(packages[3]["192.168.1.4"]).transpose()

        split_index = np.where(IP_Delta[1] > 5)                         # splitting frame index
        split_frame_no = np.take(IP_Delta[0], split_index)              # frame no of splitting frames

        # 8 clusters for 192.168.1.4
        length = len(split_index[0])
        for i in range(length):
            # initiate start and end index
            if i == 0:
                start_index = 0
            else:
                start_index = split_index[0][i - 1]
            end_index = split_index[0][i]

            crapped_array = IP_Package[1][start_index:end_index]
            crapped_array = np.reshape(crapped_array, (1, len(crapped_array)))
            crapped_time = IP_Delta[1][start_index:end_index]
            crapped_time = np.reshape(crapped_time, (1, len(crapped_time)))

            try:
                crapped_time = np.reshape(crapped_time, (len(crapped_time[0])))
                crapped_array = np.reshape(crapped_array, (len(crapped_array[0])))

                average_size = np.average(crapped_array)
                average_time = np.average(crapped_time)
                variance_size = np.var(crapped_array)
                variance_time = np.var(crapped_time)
                delta_size = crapped_array.max() - crapped_array.min()
                delta_time = np.sum(crapped_time)

                temp_array = np.array([average_size, average_time, variance_size, variance_time,
                                       delta_size, delta_time])
                temp_array = np.reshape(temp_array, (1,6))
                self.features = np.append(self.features, temp_array, axis=0)
                self.labels.append(i % 9)

            except:
                continue

        self.features = np.delete(self.features, 0,0)
        self.save_result()

    def kmeans_cluster(self):
        """kmeans clustering practice"""

        self.load_result()
        reduced_data = self.features
        kmeans = KMeans(init='k-means++', n_clusters=8, n_init=8)
        kmeans.fit(self.features)
        h = .02
        print(79 * '_')
        print('% 9s' % 'init'
                       '    time  inertia    homo   compl  v-meas     ARI AMI  silhouette')
        self.bench_k_means(KMeans(init='k-means++', n_clusters=9, n_init=9),
                      name="k-means++", data=self.features)
        self.bench_k_means(KMeans(init='random', n_clusters=9, n_init=9),
                      name="random", data=self.features)

    def bench_k_means(self, estimator, name, data):
        t0 = time()
        estimator.fit(data)
        print('% 9s   %.2fs    %i   %.3f   %.3f   %.3f   %.3f   %.3f    %.3f'
              % (name, (time() - t0), estimator.inertia_,
                 metrics.homogeneity_score(self.labels, estimator.labels_),
                 metrics.completeness_score(self.labels, estimator.labels_),
                 metrics.v_measure_score(self.labels, estimator.labels_),
                 metrics.adjusted_rand_score(self.labels, estimator.labels_),
                 metrics.adjusted_mutual_info_score(self.labels, estimator.labels_),
                 metrics.silhouette_score(data, estimator.labels_,
                                          metric='euclidean',
                                          sample_size=len(self.features))))

    def load_result(self):
        """Load parsed data to self attributes"""
        self.features = np.loadtxt(os.path.join(data_path, "features"))
        self.labels = np.loadtxt(os.path.join(data_path, "labels"))

    def save_result(self):
        """Save parsed data to numpy local files"""
        np.savetxt(os.path.join(data_path, "features"), self.features)
        np.savetxt(os.path.join(data_path, "labels"), self.labels)


if __name__ == '__main__':
    parse = parse()
    parse.load_raw()
    parse.kmeans_cluster()