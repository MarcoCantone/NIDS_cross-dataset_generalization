# NIDS Cross-Dataset Generalization

This repository contains the code supporting the article:  
**_"Machine Learning in Network Intrusion Detection: A Cross-Dataset Generalization Study"_**

## 📂 Datasets

The study uses the following four publicly available datasets:

1. [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)  
2. [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html)  
3. [LycoS-IDS2017](https://lycos-ids.univ-lemans.fr/)  
4. [LycoS-Unicas-IDS2018](https://github.com/MarcoCantone/LycoS-Unicas-IDS2018)  

---

## 🔧 Preprocessing

The following datasets need to be preprocessed using `preprocess_dataset.py`:
- CIC-IDS2017
- CSE-CIC-IDS2018
- LycoS-IDS2017

To do so, edit the beginning of the script and set the correct paths for input folders and output CSVs:

```python
# Insert the path of the folder "MachineLearningCVE" from the CIC-IDS2017 dataset
cic2017_csv_folder = "/data/cantone/datasets/cic-ids2017/MachineLearningCVE/"

# Insert the path of the folder "Processed Traffic Data for ML Algorithms" from the CSE-CIC-IDS2018 dataset
cic2018_csv_folder = "/mnt/qnap2/cse-cic-ids2018/Processed Traffic Data for ML Algorithms/"

# Insert the path to LycoS-IDS2017 CSV files
lycos_folder = "/home/cantone/Datasets/lycos-ids2017/"

# Output directory for preprocessed CSVs
save_path = "/data/cantone/datasets/test_ids/"
```


## 🚀 Running Experiments
The script CyberExperiment.py is used to run within-dataset and cross-dataset machine learning experiments.
It supports command-line arguments to configure various aspects of the experiment.

Results are saved as a Python dictionary using torch.save() in the specified workspace directory and can be reloaded with torch.load().
This is the structure of the result dictionary.

res
├── train
│   ├── mcc
│   └── acc
├── test
│   ├── mcc
│   ├── acc
│   ├── confusion_matrix
│   ├── f1
│   ├── roc
│   └── auc
└── by_class
    ├── <attack1>
    │   ├── mcc
    │   ├── acc
    │   ├── f1
    │   ├── tn
    │   ├── fp
    │   ├── tp
    │   └── fn
    ├── <attack2>
    |   ├── ...
    ├── ...


## 📌 Example Usages

### 🔹 Example 1:
Within-Dataset Binary Classification (CIC-IDS2017) with a 80:20 split and a random forest classifier.
```bash
python CyberExperiment.py --csv-file ".../CIC-IDS2017.csv" --train-test-split 0.8 --classifier rf --workspace ".../exp1/"
```

### 🔹 Example 2:
Cross-dataset binary experiment using the CIC-IDS2017 as training set and the CSE-CIC-IDS2018 as test set.

```bash
python .../CyberExperiment.py --csv-file ".../CIC-IDS2017.csv" --ext-test-set ".../CSE-CIC-IDS2018.csv" --classifier rf --workspace ".../exp2/"
```

### 🔹 Example 3:
Cross-dataset multiclass experiment using the LycoS-IDS2017 as training set and the LycoS-Unicas-IDS2018 as test set with a decision tree classifier.

```bash
python .../CyberExperiment.py --csv-file ".../LycoS-IDS2017.csv" --ext-test-set ".../LycoS-Unicas-IDS2018.csv" --classifier dt --training-mode multiclass --workspace ".../exp3/"
```

### 🔹 Example 4:
Within-dataset Benign vs DoS GoldenEye experiment on the LycoS-IDS2017 using a grid search for the classifier hyperparameters optimization. In addition the max unbalance ratio between classes is set to 10.

```bash
python .../CyberExperiment.py --csv-file ".../LycoS-IDS2017.csv" --train-test-split 0.8 --training-mode binary --categorical-features "ip_prot" --classes "Benign" "DoS GoldenEye" --negative-label "Benign" --max-unbalance-ratio 10 --classifier dt --clf-params ".../dt_grid_search_space.json" --classifier dt --workspace ".../exp4/"
```

The json file defining the search space for the grid search is a jaml file containing a dict of string: list. Where the key represent the name of the hyperparameters and the list all the possible values that we want to try.
The following is an example for the decision tree classifier

```json
{
    "criterion": ["gini", "entropy"],
    "splitter": ["best", "random"],
    "max_depth": [null, 20],
    "min_samples_split": [2, 4, 8, 16],
    "min_samples_leaf": [1, 2, 4],
    "min_weight_fraction_leaf": [],
    "max_features": [null, "sqrt", "log2"],
    "random_state": [],
    "max_leaf_nodes": [null, 10000, 1000000],
    "min_impurity_decrease": [],
    "class_weight": [],
    "ccp_alpha": []
}
```
