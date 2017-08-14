#!/usr/bin/env python
# Created for HTor project
# basic ideas are stated in submitted 2018 infoCom paper:
#       Link Us If You Can: Enabling Unlinkable Communication on the Internet
# For anonymity of this project, more details will be stated later.
import numpy
import os
import glob
import matplotlib as mpl

mpl.use('Agg')
import matplotlib.pyplot as plt
from pandas import read_csv
import math
import tensorflow as tf
from keras.models import Sequential
from keras.models import model_from_json
from keras.layers import Dense
from keras.layers import LSTM
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import mean_squared_error
from keras.backend.tensorflow_backend import set_session
import entropy

config = tf.ConfigProto()
config.gpu_options.per_process_gpu_memory_fraction = 0.1
set_session(tf.Session(config=config))


# convert an array of values into a dataset matrix
def create_dataset(dataset, look_back=1):
    dataX, dataY = [], []
    for i in range(len(dataset) - look_back - 1):
        a = dataset[i:(i + look_back), 0]
        dataX.append(a)
        dataY.append(dataset[i + look_back, 0])
    return numpy.array(dataX), numpy.array(dataY)


# data_directory = ['ext2/', 'ext1/', 'raw/']
back_up_folder = "less/"
pic_folder = "less/pic/"
# for dd in data_directory:
# print ('Using directory %s' % dd)
# for kk in range(1):
learn_data = '5google_browse_less'
look_backs = [30]
linux_or_dasheng = 'model_lb'
train_percentage = 0.9
# fix random seed for reproducibility
for look_back in look_backs:
    numpy.random.seed(42)
    # load the dataset
    with open(learn_data) as f:
        content = f.readlines()
    # you may also want to remove whitespace characters like `\n` at the end of each line
    data = [float(x.strip()) for x in content]
    data = numpy.asarray(data, dtype=numpy.float32)
    dataset = numpy.reshape(data, (data.shape[0], 1))

    # dataframe = read_csv('international-airline-passengers.csv', usecols=[1], engine='python', skipfooter=3)
    # dataset = dataframe.values
    # dataset = dataset.astype('float32')
    # normalize the dataset
    scaler = MinMaxScaler(feature_range=(0, 1))
    dataset = scaler.fit_transform(dataset)
    # split into train and test sets
    train_size = int(len(dataset) * train_percentage)
    test_size = len(dataset) - train_size
    train, test = dataset[0:train_size, :], dataset[train_size:len(dataset), :]
    # reshape into X=t and Y=t+1
    trainX, trainY = create_dataset(train, look_back)
    testX, testY = create_dataset(test, look_back)
    # reshape input to be [samples, time steps, features]
    trainX = numpy.reshape(trainX, (trainX.shape[0], trainX.shape[1], 1))
    testX = numpy.reshape(testX, (testX.shape[0], testX.shape[1], 1))
    # create and fit the LSTM network
    batch_size = 1
    m_name = linux_or_dasheng + str(look_back)
    try:  # load the newest model trained
        exist_model = max(glob.iglob(back_up_folder + m_name + '.json'), key=os.path.getctime)[:-5]
    except:
        exist_model = ''
    if exist_model:
        print ("load %s !" % exist_model)
        json_file = open(exist_model + '.json', 'r')
        loaded_model_json = json_file.read()
        json_file.close()
        model = model_from_json(loaded_model_json)
        # load weights into new model
        model.load_weights(exist_model + ".h5")
        model.compile(loss='mean_squared_error', optimizer='rmsprop', metrics=['accuracy'])
    else:
        print ("No exist model %s !" % (back_up_folder + m_name))
        model = Sequential()
        model.add(LSTM(256, return_sequences=True, input_shape=(trainX.shape[1], trainX.shape[2])))
        model.add(LSTM(128))
        # model.add(LSTM(128, input_shape=(trainX.shape[1], trainX.shape[2])))
        model.add(Dense(1))
        model.compile(loss='mean_squared_error', optimizer='adam')

    model.fit(trainX, trainY, epochs=100, batch_size=1, verbose=2)
    model_json = model.to_json()
    with open(back_up_folder + linux_or_dasheng + str(look_back) + ".json", "w") as json_file:
        json_file.write(model_json)
    # serialize weights to HDF5
    model.save_weights(back_up_folder + linux_or_dasheng + str(look_back) + ".h5")
    # print ("epoch %s: self lb %s at %s" % (_, look_back, back_up_folder))

    # make predictions
    trainPredict = model.predict(trainX, batch_size=batch_size)
    testPredict = model.predict(testX, batch_size=batch_size)
    # invert predictions
    trainPredict = scaler.inverse_transform(trainPredict)
    trainY = scaler.inverse_transform([trainY])
    testPredict = scaler.inverse_transform(testPredict)
    testY = scaler.inverse_transform([testY])

    # compute entropy
    origin_en = entropy.shannon_entropy(scaler.inverse_transform(dataset[len(trainPredict) + (look_back * 2):, :]))
    predict_en = entropy.shannon_entropy(testPredict)
    print ('origin Entropy %s' % origin_en)
    print ('predict Entropy %s' % predict_en)

    # calculate root mean squared error
    trainScore = math.sqrt(mean_squared_error(trainY[0], trainPredict[:, 0]))
    print('Train Score: %.2f RMSE' % (trainScore))
    testScore = math.sqrt(mean_squared_error(testY[0], testPredict[:, 0]))
    print('Test Score: %.2f RMSE' % (testScore))
    # shift train predictions for plotting
    trainPredictPlot = numpy.empty_like(dataset)
    trainPredictPlot[:, :] = numpy.nan
    trainPredictPlot[look_back:len(trainPredict) + look_back, :] = trainPredict
    # shift test predictions for plotting
    testPredictPlot = numpy.empty_like(dataset)
    testPredictPlot[:, :] = numpy.nan
    testPredictPlot[len(trainPredict) + (look_back * 2) + 1:len(dataset) - 1, :] = testPredict
    # plot baseline and predictions

    plt.plot(scaler.inverse_transform(dataset[len(trainPredict) + (look_back * 2):, :]), 'g')
    # plt.plot(trainPredictPlot, 'b.')
    plt.plot(testPredict, 'r.')
    # plt.show()
    # if trainScore < 300 or (kk == 6 and testScore < 300.0):
    plt.savefig(
        pic_folder + 'train' + str(int(trainScore)) + 'test' + str(int(testScore)) + linux_or_dasheng + str(look_back) \
        + 'O' + str(origin_en)[2:6] + 'P' + str(predict_en)[2:6] + '.png')
    plt.clf()
