import pandas as pd
import os

features = ['Destination Port',
            'Flow Duration',
            'Total Fwd Packets',
            'Total Backward Packets',
            'Total Length of Fwd Packets',
            'Total Length of Bwd Packets',
            'Fwd Packet Length Max',
            'Fwd Packet Length Min',
            'Fwd Packet Length Mean',
            'Fwd Packet Length Std',
            'Bwd Packet Length Max',
            'Bwd Packet Length Min',
            'Bwd Packet Length Mean',
            'Bwd Packet Length Std',
            'Flow Bytes/s',
            'Flow Packets/s',
            'Flow IAT Mean',
            'Flow IAT Std',
            'Flow IAT Max',
            'Flow IAT Min',
            'Fwd IAT Total',
            'Fwd IAT Mean',
            'Fwd IAT Std',
            'Fwd IAT Max',
            'Fwd IAT Min',
            'Bwd IAT Total',
            'Bwd IAT Mean',
            'Bwd IAT Std',
            'Bwd IAT Max',
            'Bwd IAT Min',
            'Fwd PSH Flags',
            'Bwd PSH Flags',
            'Fwd URG Flags',
            'Bwd URG Flags',
            'Fwd Header Length',
            'Bwd Header Length',
            'Fwd Packets/s',
            'Bwd Packets/s',
            'Min Packet Length',
            'Max Packet Length',
            'Packet Length Mean',
            'Packet Length Std',
            'Packet Length Variance',
            'FIN Flag Count',
            'SYN Flag Count',
            'RST Flag Count',
            'PSH Flag Count',
            'ACK Flag Count',
            'URG Flag Count',
            'CWE Flag Count',
            'ECE Flag Count',
            'Down/Up Ratio',
            'Average Packet Size',
            'Avg Fwd Segment Size',
            'Avg Bwd Segment Size',
            'Fwd Avg Bytes/Bulk',
            'Fwd Avg Packets/Bulk',
            'Fwd Avg Bulk Rate',
            'Bwd Avg Bytes/Bulk',
            'Bwd Avg Packets/Bulk',
            'Bwd Avg Bulk Rate',
            'Subflow Fwd Packets',
            'Subflow Fwd Bytes',
            'Subflow Bwd Packets',
            'Subflow Bwd Bytes',
            'Init_Win_bytes_forward',
            'Init_Win_bytes_backward',
            'act_data_pkt_fwd',
            'min_seg_size_forward',
            'Active Mean',
            'Active Std',
            'Active Max',
            'Active Min',
            'Idle Mean',
            'Idle Std',
            'Idle Max',
            'Idle Min',
            'Label']

lycos_cic_association = {"dst_port": 0,
                         "flow_duration": 1,
                         "down_up_ratio": 51,
                         "pkt_len_max": 39,
                         "pkt_len_min": 38,
                         "pkt_len_mean": 40,
                         "pkt_len_var": 42,
                         "pkt_len_std": 41,
                         "bytes_per_s": 14,
                         "pkt_per_s": 15,
                         "fwd_pkt_per_s": 36,
                         "bwd_pkt_per_s": 37,
                         "fwd_pkt_cnt": 2,
                         "fwd_pkt_len_tot": 4,
                         "fwd_pkt_len_max": 6,
                         "fwd_pkt_len_min": 7,
                         "fwd_pkt_len_mean": 8,
                         "fwd_pkt_len_std": 9,
                         "fwd_pkt_hdr_len_tot": 34,
                         "bwd_pkt_cnt": 3,
                         "bwd_pkt_len_tot": 5,
                         "bwd_pkt_len_max": 10,
                         "bwd_pkt_len_min": 11,
                         "bwd_pkt_len_mean": 12,
                         "bwd_pkt_len_std": 13,
                         "bwd_pkt_hdr_len_tot": 35,
                         "iat_max": 18,
                         "iat_min": 19,
                         "iat_mean": 16,
                         "iat_std": 17,
                         "fwd_iat_tot": 20,
                         "fwd_iat_max": 23,
                         "fwd_iat_min": 24,
                         "fwd_iat_mean": 21,
                         "fwd_iat_std": 22,
                         "bwd_iat_tot": 25,
                         "bwd_iat_max": 28,
                         "bwd_iat_min": 29,
                         "bwd_iat_mean": 26,
                         "bwd_iat_std": 27,
                         "active_max": 71,
                         "active_min": 72,
                         "active_mean": 69,
                         "active_std": 70,
                         "idle_max": 75,
                         "idle_min": 76,
                         "idle_mean": 73,
                         "idle_std": 74,
                         "flag_SYN": 44,
                         "flag_fin": 43,
                         "flag_rst": 45,
                         "flag_ack": 47,
                         "flag_psh": 46,
                         "fwd_flag_psh": 30,
                         "bwd_flag_psh": 31,
                         "flag_urg": 48,
                         "fwd_flag_urg": 32,
                         "bwd_flag_urg": 33,
                         "flag_cwr": 49,
                         "flag_ece": 50,
                         "fwd_bulk_bytes_mean": 55,
                         "fwd_bulk_pkt_mean": 56,
                         "fwd_bulk_rate_mean": 57,
                         "bwd_bulk_bytes_mean": 58,
                         "bwd_bulk_pkt_mean": 59,
                         "bwd_bulk_rate_mean": 60,
                         "fwd_subflow_bytes_mean": 62,
                         "fwd_subflow_pkt_mean": 61,
                         "bwd_subflow_bytes_mean": 64,
                         "bwd_subflow_pkt_mean": 63,
                         "fwd_tcp_init_win_bytes": 65,
                         "bwd_tcp_init_win_bytes": 66,
                         "label": 77}

lycos_cic_association_name = {lycos_feature: features[lycos_cic_association[lycos_feature]] for lycos_feature in
                              lycos_cic_association}

rename_class_cic2017 = {
    'BENIGN': "Benign",
    'DoS Hulk': "DoS Hulk",
    'DoS slowloris': 'DoS Slowloris',
    'DoS Slowhttptest': 'DoS Slowhttptest',
    'DoS GoldenEye': 'DoS GoldenEye',
    'DDoS': "DDoS",
    'PortScan': "PortScan",
    'FTP-Patator': 'FTP-Patator',
    'SSH-Patator': 'SSH-Patator',
    'Bot': "Bot",
    'Web Attack � Brute Force': 'Web Attack - Brute Force',
    'Web Attack � Sql Injection': 'Web Attack - Sql Injection',
    'Web Attack � XSS': 'Web Attack - XSS',
    'Infiltration': 'Infiltration',
    'Heartbleed': 'Heartbleed'
}

rename_class_lycos2017 = {
    'benign': "Benign",
    'portscan': "PortScan",
    'dos_hulk': "DoS Hulk",
    'ddos': "DDoS",
    'dos_goldeneye': 'DoS GoldenEye',
    'dos_slowloris': 'DoS Slowloris',
    'dos_slowhttptest': 'DoS Slowhttptest',
    'ftp_patator': 'FTP-Patator',
    'ssh_patator': 'SSH-Patator',
    'webattack_bruteforce': 'Web Attack - Brute Force',
    'bot': "Bot",
    'webattack_xss': 'Web Attack - XSS',
    'webattack_sql_injection': 'Web Attack - Sql Injection',
    'heartbleed': 'Heartbleed'
}

rename_class_cic2018 = {
    'Benign': 'Benign',
    'DDOS attack-HOIC': 'DDoS HOIC',
    'DDoS attacks-LOIC-HTTP': 'DDoS LOIC-HTTP',
    'DDOS attack-LOIC-UDP': 'DDoS LOIC-UDP',
    'DoS attacks-SlowHTTPTest': 'DoS Slowhttptest',
    'DoS attacks-GoldenEye': 'DoS GoldenEye',
    'DoS attacks-Slowloris': 'DoS Slowloris',
    'DoS attacks-Hulk': 'DoS Hulk',
    'Bot': 'Bot',
    'FTP-BruteForce': 'FTP-Patator',
    'SSH-Bruteforce': 'SSH-Patator',
    'Infilteration': 'Infiltration',
    'Brute Force -Web': 'Web Attack - Brute Force',
    'Brute Force -XSS': 'Web Attack - XSS',
    'SQL Injection': 'Web Attack - Sql Injection'
}

# insert the path of the folder "MachineLearningCVE" of the CIC-IDS2017 dataset
cic2017_csv_folder = "/data/cantone/datasets/cic-ids2017/MachineLearningCVE/"
# insert the path of the folder "Processed Traffic Data for ML Algorithms" of the CSE-CIC-IDS2018 dataset
cic2018_csv_folder = "/mnt/qnap2/cse-cic-ids2018/Processed Traffic Data for ML Algorithms/"
# insert the path of lycos2017 csv
lycos_folder = "/home/cantone/Datasets/lycos-ids2017/"


save_path = "/data/cantone/datasets/test_ids/"


if __name__ == "__main__":

    # PREPROCESS CIC2017

    # # concatenate csv
    # dataset = pd.DataFrame()
    # for file in os.listdir(cic2017_csv_folder):
    #     print(f'loading {os.path.join(cic2017_csv_folder, file)}')
    #     dataset = pd.concat([dataset, pd.read_csv(os.path.join(cic2017_csv_folder, file))], axis=0)
    #
    # # remove duplicate feature "Fwd Header Length"
    # dataset = dataset.drop(" Fwd Header Length.1", axis=1)
    # # rename columns according to list "features" (this is mainly for removing the space that exist at the beginning of some features name)
    # dataset = dataset.rename({list(dataset.columns)[i]: features[i] for i in range(len(features))}, axis=1)
    # # clean dataset (remove rows with NaN or inf)
    # dataset = dataset.dropna()
    # dataset = dataset[(dataset != float("inf")).all(axis=1)]
    #
    # # rename attack names
    # dataset["Label"] = dataset["Label"].replace(rename_class_cic2017)
    #
    # # save dataFrame as csv
    # dataset.to_csv(os.path.join(save_path, "CIC-IDS2017.csv"), sep=',', index=False)
    #
    # # ------------------------------------------------------------------------------------------------------------------
    #
    # # PREPROCESS CIC2018
    #
    # # concatenate csv
    # dataset_list = []
    # dataset = pd.DataFrame()
    # for csv_file_name in os.listdir(cic2018_csv_folder):
    #     print(f'Loading {csv_file_name}')
    #     dataset_list.append(pd.read_csv(os.path.join(cic2018_csv_folder, csv_file_name)))
    #     print(dataset_list[-1]["Label"].value_counts())
    #     print(len(dataset_list[-1]))
    #     if csv_file_name in ["Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
    #                          "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
    #                          "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"]:
    #         dataset_list[-1] = dataset_list[-1][dataset_list[-1]["Label"] != "Label"]
    #     if csv_file_name == 'Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv':
    #         dataset_list[-1] = dataset_list[-1].drop(['Flow ID', 'Src IP', 'Src Port', 'Dst IP'], axis=1)
    # dataset = pd.concat(dataset_list, axis=0)
    # # remove features not present in 2017
    # dataset = dataset.drop(["Protocol", "Timestamp"], axis=1)
    #
    # # rename features name
    # dataset = dataset.rename({list(dataset.columns)[i]: features[i] for i in range(len(features))}, axis=1)
    # # clean dataset
    # dataset = dataset.dropna()
    # dataset = dataset[(dataset != "Infinity").all(axis=1)]
    # dataset = dataset[(dataset != float("inf")).all(axis=1)]
    #
    # # rename attack names
    # dataset["Label"] = dataset["Label"].replace(rename_class_cic2018)
    #
    # # save dataset as csv
    # dataset.to_csv(os.path.join(save_path, "CSE-CIC-IDS2018.csv"), sep=',', index=False)

    # ------------------------------------------------------------------------------------------------------------------

    # PREPROCESS LycoS2017

    # concatenate csv
    dataset_list = []
    for file in os.listdir(lycos_folder):
        print(f'loading {file}')
        dataset_list.append(pd.read_csv(os.path.join(lycos_folder, file)))
    dataset = pd.concat(dataset_list, axis=0)

    # drop features that cannot be used for training
    dataset = dataset.drop(['flow_id', 'src_addr', 'src_port', 'dst_addr', 'timestamp'], axis=1)

    # clean dataset
    dataset = dataset.dropna()
    dataset = dataset[(dataset != float("inf")).all(axis=1)]

    # rename attack names
    dataset["label"] = dataset["label"].replace(rename_class_lycos2017)

    # save dataFrame as csv
    dataset.to_csv(os.path.join(save_path, "LycoS-IDS2017.csv"), sep=',', index=False)
