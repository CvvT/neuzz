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
MAX_BITMAP_SIZE = fit_bitmap.shape[1]
for idx,i in enumerate(seed_list):
    file_name = "./bitmaps/"+i.split('/')[-1]
    np.save(file_name,fit_bitmap[idx])

fit_label = []
for i in range(fit_bitmap.shape[1]):
    edges = []
    for j in range(bitmap.shape[1]):
        if (bitmap[:, j] == fit_bitmap[:, i]).all():
            edges.append(j)
    fit_label.append(edges)

def getIndex(edge):
    index = label.index(edge)
    for i, edges in enumerate(fit_label):
        if index in edges:
            return i
    return None

def accur_1(y_true,y_pred):
    y_true = tf.round(y_true)
    pred = tf.round(y_pred)
    summ = tf.constant(MAX_BITMAP_SIZE,dtype=tf.float32)
    wrong_num = tf.subtract(summ,tf.reduce_sum(tf.cast(tf.equal(y_true, pred),tf.float32),axis=-1))
    right_1_num = tf.reduce_sum(tf.cast(tf.logical_and(tf.cast(y_true,tf.bool), tf.cast(pred,tf.bool)),tf.float32),axis=-1)
    ret = K.mean(tf.divide(right_1_num,tf.add(right_1_num,wrong_num)))
    return ret

def build_model():
    batch_size = 32
    num_classes = MAX_BITMAP_SIZE
    epochs = 50
    model = Sequential()
    model.add(Dense(4096, input_dim=MAX_FILE_SIZE))
    model.add(Activation('relu'))
    model.add(Dense(num_classes))
    model.add(Activation('sigmoid'))
    opt = keras.optimizers.adam(lr=0.0001)
    model.compile(loss='binary_crossentropy', optimizer=opt, metrics=[accur_1])
    model.summary()
    return model

model = build_model()

def generate_training_data(lb,ub):
    seed = np.zeros((ub-lb,MAX_FILE_SIZE))
    bitmap = np.zeros((ub-lb,MAX_BITMAP_SIZE))
    for i in range(lb,ub):
        tmp = open(seed_list[i],'r').read()
        ln = len(tmp)
        if ln < MAX_FILE_SIZE:
            tmp = tmp + (MAX_FILE_SIZE - ln) * '\0'
        seed[i-lb] = [ord(j) for j in list(tmp)]
    for i in range(lb,ub):
        file_name = "./bitmaps/"+ seed_list[i].split('/')[-1] + ".npy"
        bitmap[i-lb] = np.load(file_name)
    return seed,bitmap

def train_generate(batch_size):
    global seed_list
    while 1:
        np.random.shuffle(seed_list)
        for i in range(0,SPLIT_RATIO,batch_size):
            if (i+batch_size) > SPLIT_RATIO:
                x,y=generate_training_data(i,SPLIT_RATIO)
                x = x.astype('float32')/255
            else:
                x,y=generate_training_data(i,i+batch_size)
                x = x.astype('float32')/255
            yield (x,y)

class LossHistory(keras.callbacks.Callback):
    def on_train_begin(self, logs={}):
        self.losses = []
        self.lr = []
    def on_epoch_end(self, batch, logs={}):
        self.losses.append(logs.get('loss'))
        self.lr.append(step_decay(len(self.losses)))
        print(step_decay(len(self.losses)))

def step_decay(epoch):
    initial_lrate = 0.001
    drop = 0.7
    epochs_drop = 10.0
    lrate = initial_lrate * math.pow(drop,math.floor((1+epoch)/epochs_drop))
    return lrate

def train(model):
    loss_history = LossHistory()
    lrate = keras.callbacks.LearningRateScheduler(step_decay)
    callbacks_list = [loss_history, lrate]
    model.fit_generator(train_generate(16),
              steps_per_epoch = (SPLIT_RATIO/16 + 1),
              epochs=100,
              verbose=1, callbacks=callbacks_list)
    # Save model and weights
    model.save_weights("hard_label.h5")

train(model)

def vectorize_file(fl, isfile):
    seed = np.zeros((1,MAX_FILE_SIZE))
    if isfile:
        tmp = open(fl,'r').read()
    else:
        tmp = fl
    ln = len(tmp)
    if ln < MAX_FILE_SIZE:
        tmp = tmp + (MAX_FILE_SIZE - ln) * '\0'
    seed[0] = [ord(j) for j in list(tmp)]
    seed = seed.astype('float32')/255
    return seed

def gradient(model, edge, seed, isfile):
    layer_list = [(layer.name, layer) for layer in model.layers]
    index = getIndex(edge)
    loss = layer_list[-2][1].output[:,index]
    grads = K.gradients(loss,model.input)[0]
    iterate = K.function([model.input], [loss, grads])
    x=vectorize_file(seed, isfile)
    loss_value, grads_value = iterate([x])
    idx = np.flip(np.argsort(np.absolute(grads_value),axis=1)[:, -MAX_FILE_SIZE:].reshape((MAX_FILE_SIZE,)),0)
    val = np.sign(grads_value[0][idx])
    return idx, val


