import keras
import pickle
from keras.models import Sequential
from keras.layers import Dense, Dropout, Activation
import os
import numpy as np
import glob
import random
import math
from keras.callbacks import ModelCheckpoint
import time
import keras.backend as K
import tensorflow as tf
from tensorflow import set_random_seed
import subprocess
from collections import Counter
import socket
import sys

argvv = ['./test']
seed_list = glob.glob('./neuzz_in/*')
seed_list.sort()
SPLIT_RATIO = len(seed_list)
rand_index = np.arange(SPLIT_RATIO)
np.random.shuffle(seed_list)

MAX_FILE_SIZE = 512
call=subprocess.check_output
raw_bitmap = {}
tmp_cnt = []
out = ''
for f in seed_list:
    tmp_list = []
    try:
        # append "-o tmp_file" to strip's arguments to avoid tampering tested binary.
        print(f)
        with open(f) as myinput:
            out = call(['./afl-showmap', '-q', '-e', '-o', '/dev/stdout', '-m', '512'] + argvv, stdin=myinput)
    except subprocess.CalledProcessError:
        print("find a crash")
    for line in out.splitlines():
        edge = line.split(':')[0]
        tmp_cnt.append(edge)
        tmp_list.append(edge)
    raw_bitmap[f] = tmp_list

counter = Counter(tmp_cnt).most_common()
label = [int(f[0]) for f in counter]
bitmap = np.zeros((len(seed_list), len(label)))
for idx,i in enumerate(seed_list):
    tmp = raw_bitmap[i]
    for j in tmp:
        if int(j) in label:
            bitmap[idx][label.index((int(j)))] = 1

fit_bitmap = np.unique(bitmap,axis=1)

fit_label = []
for i in range(fit_bitmap.shape[1]):
    edges = []
    for j in range(bitmap.shape[1]):
        if (bitmap[:, j] == fit_bitmap[:, i]).all():
            edges.append(j)
    fit_label.append(edges)


