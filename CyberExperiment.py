import argparse
import os.path
import time
import json
import inspect
import pandas as pd
import numpy as np

import torch

from sklearn.model_selection import train_test_split, StratifiedShuffleSplit
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn import metrics
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.model_selection import GridSearchCV
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

from feature_sets import feature_sets


class MinMaxQuantile:
    def __init__(self, q=0.95):
        self.threshold = None
        self.q = q
        self.fitted = False

    def fit(self, x):
        self.threshold = np.quantile(x, self.q, method="higher", axis=0)
        self.fitted = True
        # self.min = np.min(x, axis=0)

    def transform(self, x):
        if not self.fitted:
            print(f'You have to fit data before transform')
        tmp = x.copy()
        # Set the value grater than max to max for each column
        tmp = tmp.apply(lambda col: col.apply(lambda value: min(value, self.threshold[tmp.columns.get_loc(col.name)])), axis=0)
        minmax_scaler = MinMaxScaler()
        return minmax_scaler.fit_transform(tmp)

    def fit_transform(self, x):
        self.fit(x)
        return self.transform(x)


str_to_clf = {
    "rf": RandomForestClassifier,
    "xgboost": XGBClassifier,
    "svm": SVC,
    "lda": LinearDiscriminantAnalysis,
    "dt": DecisionTreeClassifier
}

parser = argparse.ArgumentParser(
    prog='CyberExperiment',
    description='A little framework for running machine learning training and evaluation on CyberSecurity datasets')

parser.add_argument('-i', '--csv-file', type=str, required=True, help='Path to csv file used for training, the last column must indicate the label')
parser.add_argument('--train-test-split', type=float, help="Percentage of training set used in an holdout split of the dataset. If --ext-test-set is provided this argument is ignored")
parser.add_argument('-t', '--ext-test-set', type=str, help="Path to a csv file used for test. It has to have the same classe sand feature of --csv-file")
parser.add_argument('-f', '--feature-set', type=str, choices=list(feature_sets.keys()) + ["all"],
                    default="all", help="Selected subset of features")
parser.add_argument('--mrmr-first-k', type=int, help="use the first k feature of the best features colulated with mrmr (work only for subset calculated with mrmr)")
parser.add_argument('--categorical-features', type=str, nargs='+', help="Encode the categorical features specified with OneHotEncoder")
parser.add_argument('-n', '--normalization', type=str, choices=["minmax", "minmaxquantile", "standardization"], help="Normalization method")
parser.add_argument('--training-mode', type=str, choices=["binary", "multiclass"], default="binary", help="Training mode")
parser.add_argument('--classes', type=str, nargs='+', help="Use only the sample of the specified classes")
parser.add_argument('--negative-label', type=str, default="Benign", help="Specify the negative class")
parser.add_argument('--max-unbalance-ratio', type=float, help="Define the max unbalance ratio admitted. Surplus samples are removed ")
parser.add_argument('--max-samples', type=int, help="Define the maximum number of sample used. Maintain the ratio between classes")
parser.add_argument('--classifier', type=str, choices=list(str_to_clf.keys()), help="Select the classifier to be used")
parser.add_argument('--clf-params', type=str, help="Path to a yaml file defining the hyperparameters of the classifier. If a list of values for at least one parameter is given, perform a grid search on a subset of the training set.")
parser.add_argument('--thread', type=int, default=16, help="Number of threads to use")
parser.add_argument('--thread-base-clf', type=int, default=16, help="Number of threads to use for a single classifier")
parser.add_argument("--workspace", type=str, help="Specify the path where all the experiment data are saved")

if __name__ == '__main__':

    # parsing command line arguments
    args = parser.parse_args()

    # load dataset
    print(f'loading data at {args.csv_file}... ', end="")
    start = time.time()
    X = pd.read_csv(args.csv_file)
    print(f'(done in {time.time() - start:.2f} s)')

    # separate label from features
    Y = X.iloc[:, -1]
    X = X.iloc[:, :-1]

    X_train, X_test, Y_train, Y_test = None, None, None, None
    if args.ext_test_set:
        if args.train_test_split:
            print(f'ignoring --train-test-split since external test set is provided')
        X_train, Y_train = X, Y

        print(f'loading external test set at {args.ext_test_set}... ', end="")
        start = time.time()
        X_test = pd.read_csv(args.ext_test_set)
        print(f'(done in {time.time() - start:.2f} s)')

        Y_test = X_test.iloc[:, -1]
        X_test = X_test.iloc[:, :-1]

        if not (X_test.columns == X_train.columns).all():
            print(f'features in train and test set are different')
            exit()

    elif args.train_test_split:
        if 0 <= args.train_test_split <= 1:
            print(f'selecting {(1-args.train_test_split)*100:.2f}% of data as test set')
            X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=1 - args.train_test_split)
        else:
            print(f'--train-test-split has to be between 0 and 1 ({args.train_test_split} provided)')
    else:
        print("neither --train-test-split nor --ext-test-set provided.")
        exit()

    print("")

    # categorical features encoding
    if args.categorical_features:
        one = OneHotEncoder(handle_unknown="infrequent_if_exist",
                            min_frequency=0.001,
                            dtype=int,
                            sparse_output=False,
                            max_categories=10)

        if set(args.categorical_features) <= set(X_train.columns):
            categorical_features = args.categorical_features
        else:
            print(f'Have been specified categorical features not present in data. Will not be encoded.')
            categorical_features = [f for f in args.categorical_features if f in X_train.columns]

        print(f'Encoding {categorical_features} with OneHotEncoder.')

        one.fit(X_train[categorical_features])

        cat_features = pd.DataFrame(one.transform(X_train[categorical_features]),
                                    columns=one.get_feature_names_out(),
                                    index=X_train.index)
        X_train = pd.concat([cat_features, X_train.drop(categorical_features, axis=1)], axis=1)
        cat_features = pd.DataFrame(one.transform(X_test[categorical_features]),
                                    columns=one.get_feature_names_out(),
                                    index=X_test.index)
        X_test = pd.concat([cat_features, X_test.drop(categorical_features, axis=1)], axis=1)

    # use all features or select a subset
    if args.feature_set != "all":
        print(f'Using the following set of features:')
        if "mrmr" in args.feature_set:
            if args.mrmr_first_k:
                print(feature_sets[args.feature_set][:args.mrmr_first_k])
                X_train = X_train[feature_sets[args.feature_set][:args.mrmr_first_k]]
                X_test = X_test[feature_sets[args.feature_set][:args.mrmr_first_k]]
            else:
                print("you have to specify --mrmr-first-k to use the group of best 'mrmr-first-k' features if mRMR feature sets are selected. Using all features.")
                print(feature_sets[args.feature_set])
                X_train = X_train[feature_sets[args.feature_set]]
                X_test = X_test[feature_sets[args.feature_set]]
        else:
            print(feature_sets[args.feature_set])
            X_train, X_test = X_train[feature_sets[args.feature_set]], X_test[feature_sets[args.feature_set]]

    # select classes of interest
    if args.classes:
        print(f'Considering only samples of the following classes: {args.classes}')
        index = Y_train.isin(args.classes)
        X_train = X_train[index]
        Y_train = Y_train[index]

        index = Y_test.isin(args.classes)
        X_test = X_test[index]
        Y_test = Y_test[index]

    # apply normalization
    if args.normalization == "minmax":
        print("Applying MinMax normalization")
        minmax = MinMaxScaler()
        X_train = pd.DataFrame(minmax.fit_transform(X_train), columns=X_train.columns, index=X_train.index)
        minmax1 = MinMaxScaler()
        X_test = pd.DataFrame(minmax1.fit_transform(X_test), columns=X_test.columns, index=X_test.index)
    elif args.normalization == "minmaxquantile":
        # TODO: move definition of q (command line or global variable)
        q = 0.99
        print(f"Applying MinMaxQuantile normalization with q={q}")
        start = time.time()
        scaler = MinMaxQuantile(q=q)
        X_train = pd.DataFrame(scaler.fit_transform(X_train), columns=X_train.columns, index=X_train.index)
        X_test = pd.DataFrame(scaler.transform(X_test), columns=X_test.columns, index=X_test.index)
        print(f'Done in {time.time()-start:.2f} sec.')
    elif args.normalization == "standardization":
        print(f'not implemented...')
        exit()

    # convert label
    if args.training_mode == "binary":
        if args.negative_label in ["0", "1"]:
            args.negative_label = int(args.negative_label)
        print(f'Training in binary mode, grouping all classes different from negative label {args.negative_label} in one')
        if args.negative_label not in Y_train.unique():
            print(f'The chosen negative label is not present in column label')
            exit()
        # FIXME use list instead of set in pandas.replace for version compatibility
        Y_train.replace(list(set(Y_train.unique()).difference({args.negative_label})), 1, inplace=True)
        Y_train.replace([args.negative_label], 0, inplace=True)

        Y_multi = Y_test.copy()
        Y_test.replace(list(set(Y_test.unique()).difference({args.negative_label})), 1, inplace=True)
        Y_test.replace([args.negative_label], 0, inplace=True)

    elif args.training_mode == "multiclass":
        print(f'Training in multiclass mode')




    # rebalancing
    if args.max_unbalance_ratio:
        print(f'Rebalacing training set according to {args.max_unbalance_ratio} max ratio')
        composition = Y_train.value_counts()
        num_minority_class = composition.min()
        for label_value in composition.index:
            surplus_samples = composition[label_value] - int(num_minority_class * args.max_unbalance_ratio)
            if surplus_samples > 0:
                indexes = Y_train[Y_train == label_value].sample(surplus_samples).index
                Y_train = Y_train.drop(indexes, axis=0)
                X_train = X_train.drop(indexes, axis=0)

    # undersampling
    if args.max_samples and args.max_samples < len(Y_train):
        print(f'Reducing training set to {args.max_samples} samples.')
        Y_train = Y_train.groupby(Y_train).sample(frac=args.max_samples/len(Y_train))
        X_train = X_train.loc[Y_train.index]

    print("")

    print(f'Classifier: {str_to_clf[args.classifier]}')
    if args.clf_params:
        print(f'Loading parameters classifier at {args.clf_params}')
        with open(args.clf_params, "r") as f:
            params = json.loads(f.read())
    else:
        print(f'Using sklearn default parameters')
        params = {}

    if ({False} == {type(params[x]) == list for x in params}) or params == {}:
        if 'n_jobs' in inspect.signature(str_to_clf[args.classifier].__init__).parameters or args.classifier == "xgboost":
            params["n_jobs"] = args.thread
        clf = str_to_clf[args.classifier](**params)
    elif {True} == {type(params[x]) == list for x in params}:
        # removing empty sequence of parameters
        params = {key: params[key] for key in params if params[key] != []}
        # TODO: move thread_base_clf and max samples for gridsearch in global parameters (or command line parameters)
        gridSearch_size = min(1000000/len(X_train), 1)
        gridSearch_split = StratifiedShuffleSplit(n_splits=1, train_size=0.8 * gridSearch_size, test_size=0.2 * gridSearch_size)
        threads_base_clf = args.thread_base_clf
        print(f'Applying GridSearch on:\n{params}')
        if 'n_jobs' in inspect.signature(str_to_clf[args.classifier].__init__).parameters or args.classifier == "xgboost":
            base_clf = str_to_clf[args.classifier](n_jobs=min(args.thread, threads_base_clf))
            clf = GridSearchCV(base_clf,
                               params,
                               scoring=metrics.make_scorer(metrics.matthews_corrcoef),
                               cv=gridSearch_split,
                               refit=True,
                               n_jobs=int(args.thread/min(args.thread, threads_base_clf)))
        else:
            base_clf = str_to_clf[args.classifier]()
            clf = GridSearchCV(base_clf,
                               params,
                               scoring=metrics.make_scorer(metrics.matthews_corrcoef),
                               cv=gridSearch_split,
                               refit=True,
                               n_jobs=args.thread)
    else:
        print(f'Wrong params format!')
        exit()

    # train model
    print(f'start training... ', end="")
    start = time.time()
    if args.training_mode == "multiclass" and (type(clf) == XGBClassifier or type(clf.estimator) == XGBClassifier):
        le = LabelEncoder()
        clf.fit(X_train, le.fit_transform(Y_train))
    else:
        clf.fit(X_train, Y_train)
    elapsed = time.time() - start
    print(f'(done in {elapsed:.2f} s)')

    res = {"train": {}, "test": {}}

    print(f'Evaluating training set... ', end="")
    start = time.time()
    prediction_train = clf.predict(X_train)
    if args.training_mode == "multiclass" and (type(clf) == XGBClassifier or type(clf.estimator) == XGBClassifier):
        prediction_train = le.inverse_transform(prediction_train)
    elapsed = time.time() - start
    print(f'(done in {elapsed:.2f} s)')

    print(f'Calculating the metrics...')
    res["train"]["mcc"] = metrics.matthews_corrcoef(Y_train, prediction_train)
    res["train"]["acc"] = metrics.accuracy_score(Y_train, prediction_train)

    print(f'acc_train = {res["train"]["acc"]}')
    print(f'mcc_train = {res["train"]["mcc"]}')

    print(f'Evaluating test set... ', end="")
    start = time.time()
    prediction = clf.predict(X_test)
    if args.classifier == "xgboost" and args.training_mode == "multiclass":
        prediction = le.inverse_transform(prediction)
    scores = clf.predict_proba(X_test)
    elapsed = time.time() - start
    print(f'(done in {elapsed:.2f} s)')
    # TODO: compute prediction from scores (evaluate convinience) argmap -> map to classes -> list to ndarray
    # prediction = [clf.classes_[x] for x in scores.argmax(axis=1)]

    print(f'Calculating the metrics...')
    res["test"]["mcc"] = metrics.matthews_corrcoef(Y_test, prediction)
    res["test"]["acc"] = metrics.accuracy_score(Y_test, prediction)
    res["test"]["confusion_matrix_labels"] = list(Y_test.unique())
    res["test"]["confusion_matrix_data"] = metrics.confusion_matrix(Y_test, prediction,
                                                                    labels=res["test"]["confusion_matrix_labels"])

    print(f'acc = {res["test"]["acc"]}')
    print(f'mcc = {res["test"]["mcc"]}')

    if len(Y_test.unique()) == 2:
        if args.training_mode == "binary":
            pos_label = 1
        else:
            if args.negative_label not in Y_test.unique():
                print(f'Negative label {args.negative_label} not present in Y_test')
                exit()
            pos_label = list(Y_test.unique())[(list(Y_test.unique()).index(args.negative_label) + 1) % 2]
        res["test"]["f1"] = metrics.f1_score(Y_test, prediction, pos_label=pos_label)
        if type(clf) == XGBClassifier and args.training_mode == "multiclass":
            res["test"]["roc"] = metrics.roc_curve(Y_test, scores[:, list(le.inverse_transform(clf.classes_)).index(pos_label)], pos_label=pos_label)
        else:
            res["test"]["roc"] = metrics.roc_curve(Y_test, scores[:, list(clf.classes_).index(pos_label)], pos_label=pos_label)
        res["test"]["auc"] = metrics.auc(res["test"]["roc"][0], res["test"]["roc"][1])

        print(f'f1 = {res["test"]["f1"]}')
        print(f'auc = {res["test"]["auc"]}')

    if args.training_mode == "binary":
        res["by_class"] = {}

        # negative_label = Y_multi.value_counts().index[Y_multi.value_counts().argmax()] (OLD OLD)
        # negative_label = list(set(Y_multi).intersection({"BENIGN", "Benign", "benign"}))[0] (OLD)
        negative_label = args.negative_label
        pos_classes = set(Y_multi.unique()).difference({negative_label})
        for attack in pos_classes:
            res["by_class"][attack] = {}

            tmp_y = Y_multi[Y_multi.isin([attack, negative_label])].replace([negative_label, attack], [0, 1])
            # tmp_y.replace([negative_label, attack], [0, 1])
            tmp_pred = prediction[Y_multi.isin([attack, negative_label])]
            # tmp_pred = clf.predict(X_test[Y_multi.isin([attack, "benign"])])

            res["by_class"][attack]["mcc"] = metrics.matthews_corrcoef(tmp_y, tmp_pred)
            res["by_class"][attack]["acc"] = metrics.accuracy_score(tmp_y, tmp_pred)
            res["by_class"][attack]["f1"] = metrics.f1_score(tmp_y, tmp_pred)
            tn, fp, fn, tp = metrics.confusion_matrix(tmp_y, tmp_pred).ravel()
            res["by_class"][attack]["tn"] = tn
            res["by_class"][attack]["fp"] = fp
            res["by_class"][attack]["fn"] = fn
            res["by_class"][attack]["tp"] = tp

            for metric in res["by_class"][attack]:
                print(f'{metric}_{attack} = {res["by_class"][attack][metric]}')

    if args.workspace:
        if os.path.isdir(args.workspace):
            torch.save(res, os.path.join(args.workspace, "results.torch"))
            torch.save(args, os.path.join(args.workspace, "args.torch"))
            torch.save(clf, os.path.join(args.workspace, "clf.sk_model"))
            if hasattr(clf, "cv_results_"):
                pd.DataFrame(clf.cv_results_).to_csv(os.path.join(args.workspace, "gridSearch.csv"))
        else:
            print(f'{args.workspace} is not a directory')
