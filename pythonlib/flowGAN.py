
# Large amount of credit goes to:
# https://github.com/keras-team/keras-contrib/blob/master/examples/improved_wgan.py
# which I've used as a reference for this implementation

from __future__ import print_function, division

import argusWgan as aw

#import tensorflow as tf

from numpy import array, argmax, savetxt
from keras.activations import softmax
from keras.layers import Input, Dense, Flatten, Dropout, Concatenate, Layer, Lambda, Multiply, Add, Average
from keras.models import Sequential, Model
from keras.optimizers import Adam, RMSprop
from keras.utils import to_categorical
from functools import partial

import sys

import keras.backend as K
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


from tensorflow.python.framework.ops import disable_eager_execution

disable_eager_execution()


#class RandomWeightedAverage(tf.keras.layers.Layer):
class RandomWeightedAverage(Layer):
    def __init__(self, batch_size):
        #super(RandomWeightedAverage,self).__init__()
        super().__init__()
        
        self.batch_size = batch_size

    def call(self, inputs, **kwargs):
        #alpha = tf.random.uniform((self.batch_size, 1))
        alpha = K.random_uniform((self.batch_size, 1))
        return (alpha * inputs[0]) + ((1 - alpha) * inputs[1])

    def compute_output_shape(self, input_shape):
        return input_shape[0]

#from keras.layers.merge import _Merge
#class RWA(_Merge):
class RWA(Layer):
    """Provides a (random) weighted average between real and generated image samples"""
    def _merge_function(self, inputs):
        alpha = K.random_uniform((32, 1, 1, 1))
        return (alpha * inputs[0]) + ((1 - alpha) * inputs[1])
   



class WGANGP():
    def __init__(self,epochs,batch_size,sample_interval,n_critic,tau):
        self.epochs = epochs
        self.batch_size = batch_size
        self.sample_interval = sample_interval
        self.n_critic = n_critic        
        self.tau = tau
        
        water = pd.read_csv('myFlow.csv')
        water.drop(['Unnamed: 0'],axis=1) 
        self.data = self.data2OneHot(water)
        #print(self.data)
        
        self.getDims(latent=100)

        #optimizer = RMSprop(lr=0.00005)
        optimizer = Adam(0.0001, beta_1=0.5, beta_2=0.9)

        # Build the generator and critic
        self.generator = self.build_generator()
        self.generator.summary()
        
        self.critic = self.build_critic()
        self.critic.summary()

        #-------------------------------
        # Construct Computational Graph
        #       for the Critic
        #-------------------------------

        # Freeze generator's layers while training critic
        self.generator.trainable = False

        # real sample
        realFlow = Input(shape=(self.inputDim,))

        # Noise input
        z_disc = Input(shape=(self.latent_dim,))
        # Generate flow based of noise (fake sample)
        fakeFlow= self.generator(z_disc)

        # Discriminator determines validity of the real and fake images
        fake = self.critic(fakeFlow)
        valid = self.critic(realFlow)

        # Construct weighted average between real and fake images
        #auxNoise1 = Input(shape=(self.inputDim,))
        #auxNoise2 = Input(shape=(self.inputDim,))
        #rf = Multiply()([auxNoise1,realFlow])
        #ff = Multiply()([auxNoise2,fakeFlow])
        #interpolated_flow = Add()([rf,ff])
        
        interpolated_flow = Lambda(self.randomInterpolation,output_shape=(self.inputDim,),name="inter")([realFlow, fakeFlow])

        #interpolated_flow = RandomWeightedAverage(self.batch_size)([realFlow, fakeFlow])
        #interpolated_flow = RWA()([realFlow, fakeFlow])
        
        #interpolated_flow = Average(name="inter")([realFlow, fakeFlow])
        #getInterFlow = K.function([realFlow,fakeFlow],[interpolated_flow])
        
        # Determine validity of weighted sample
        validity_interpolated = self.critic(interpolated_flow)
        
        # Use Python partial to provide loss function with additional
        # 'averaged_samples' argument
        #partial_gp_loss = partial(self.gradient_penalty_loss,
        #                  averaged_samples=self.interpolated_flow)
        #partial_gp_loss.__name__ = 'gradient_penalty' # Keras requires function names

        self.critic_model = Model(inputs=[realFlow, z_disc#,auxNoise1,auxNoise2
                                          ],
                            outputs=[valid, fake, validity_interpolated
                                     ])
        self.critic_model.summary()
        self.critic_model.compile(loss=[self.customLoss,
                                              self.wasserstein_loss,
                                              self.gradient_penalty_loss#partial_gp_loss
                                              ],
                                        optimizer=optimizer,
                                        loss_weights=[1, 1, 10
                                                      ],experimental_run_tf_function=False
                                        )
        self.interID = [layer.name for layer in self.critic_model.layers].index("inter")
        #-------------------------------
        # Construct Computational Graph
        #         for Generator
        #-------------------------------

        # For the generator we freeze the critic's layers
        self.critic.trainable = False
        self.generator.trainable = True

        # Sampled noise for input to generator
        z_gen = Input(shape=(self.latent_dim,))
        # Generate flow based of noise
        flow = self.generator(z_gen)
        # Discriminator determines validity
        valid = self.critic(flow)
        # Defines generator model
        self.generator_model = Model(z_gen, valid)
        self.generator_model.summary()
        self.generator_model.compile(loss=self.wasserstein_loss, optimizer=optimizer)

    def randomInterpolation(self,inputs):
        """Provides a (random) weighted average between real and generated image samples"""
        
        #alpha = tf.random.uniform((self.batch_size, self.inputDim))
        alpha = K.random_uniform((self.batch_size, self.inputDim))
        
        #rf = Multiply()([alpha,inputs[0]])
        #ff = Multiply()([1-alpha,inputs[1]])
        #return(Add()([rf,ff]))
        
        return((alpha * inputs[0]) + ((1 - alpha) * inputs[1]))

    def cat2oneHot(self,data):
        """
        Returns one-hot representation of categories and a <dict> mapping to invert transformation
        
        Based off https://machinelearningmastery.com/how-to-one-hot-encode-sequence-data-in-python/
        """
        
        alphabet = set(data)
        cat2int = dict((cat,i) for i,cat in enumerate(alphabet))
        int2cat = dict((i,cat) for i,cat in enumerate(alphabet))
        
        # encode as one hot
        oneHot = to_categorical(array([cat2int[cat] for cat in data]))

        return oneHot,int2cat
    
    def oneHot2int(self,oh):
        """Returns mapped integer represented by one-hot"""
        
        return argmax(oh)
        
    def oneHot2Cat(self,oh,int2cat):
        """Returns category represented by one-hot"""
        
        return int2cat[self.oneHot2int(oh)]

    def standardize(self,data,lab):
        
        x = data[lab].values.reshape(-1,1)
        
        #m,s = np.mean(x), np.std(x)
        #self.sumStats[lab] = [m,s]
        #return((x-m)/s)
        
        a,b = np.min(x),np.max(x)
        self.sumStats[lab] = [a,b]
        
        return((0.05 + x-a)/(1+(b-a)))
        
    def data2OneHot(self,data):
        """Load data"""
        
        srcAddr, self.int2srcAddr = self.cat2oneHot(data['SrcAddr'])
        dstAddr, self.int2dstAddr = self.cat2oneHot(data['DstAddr'])
        dPort, self.int2dPort = self.cat2oneHot(data['Dport'])
        proto, self.int2proto = self.cat2oneHot(data['Proto'])
        
        self.sumStats = dict()
        sPort = self.standardize(data,'Sport')
        rate = self.standardize(data,'Rate')
        load = self.standardize(data,'Load')
        
        return np.concatenate([srcAddr,dstAddr,sPort,dPort,proto,rate,load],axis=1).astype(np.float32)
    
    def segmentOutput(self,oh):
        """Segments output to indiviudal categories."""
        
        i=0
        srcAddr = oh[:,i:(i+self.dimSrcAddr)]
        i+=self.dimSrcAddr
        dstAddr = oh[:,i:(i+self.dimDstAddr)]
        i+=self.dimDstAddr
        sPort = oh[:,i:(i+self.dimSPort)]
        i+=self.dimSPort
        dPort = oh[:,i:(i+self.dimDPort)]
        i+=self.dimDPort
        proto = oh[:,i:(i+self.dimProto)]
        i+=self.dimProto
        rate = oh[:,i:(i+self.dimRate)]
        i+=self.dimRate
        load= oh[:,i:(i+self.dimLoad)]
        i+=self.dimLoad
        
        return srcAddr, dstAddr, sPort, dPort, proto, rate, load
    
    def deStandardize(self,z,lab):
        
        #m,s = self.sumStats[lab]
        #return(m+s*z)
        
        a,b = self.sumStats[lab]
        return(a-0.05 + (1+(b-a))*z)
        
    def oneHot2DataFrame(self,oh):
        """Map one-hots to data representation"""
        
        sa, da, sp, dp, p, r, l = self.segmentOutput(oh)
        
        sa = [self.oneHot2Cat(sa[i],self.int2srcAddr) for i in np.arange(sa.shape[0])]
        da = [self.oneHot2Cat(da[i],self.int2dstAddr) for i in np.arange(da.shape[0])]
        dp = [self.oneHot2Cat(dp[i],self.int2dPort) for i in np.arange(dp.shape[0])]
        p = [self.oneHot2Cat(p[i],self.int2proto) for i in np.arange(p.shape[0])]
        
        df = pd.DataFrame({
            'srcAddr':sa,
            'dstAddr':da
        })
        
        df['sPort'] = self.deStandardize(sp,'Sport').astype(int)
        df['dPort'] = dp
        df['Proto'] = p
        df['Rate'] = self.deStandardize(r,'Rate')
        df['Load'] = self.deStandardize(l,'Load')
        
        return df
    
    def getDims(self,latent):
        """Defines dims of inputs"""
        
        self.dimSrcAddr = len(self.int2srcAddr.keys())
        self.dimDstAddr = len(self.int2dstAddr.keys())
        self.dimSPort = 1
        self.dimDPort = len(self.int2dPort.keys())
        self.dimProto = len(self.int2proto.keys())
        self.dimRate = 1
        self.dimLoad = 1
        self.inputDim = self.dimSrcAddr+self.dimDstAddr+self.dimSPort+self.dimDPort+self.dimProto+self.dimRate+self.dimLoad
        
        self.latent_dim = latent
        
    def gradient_penalty_loss(self, y_true, y_pred):
    #def gradient_penalty_loss(self, y_true, y_pred, averaged_samples):
        """
        Computes gradient penalty based on prediction and weighted real / fake samples
        """
        
        gradients = K.gradients(y_pred, self.critic_model.get_layer("inter").output)[0]
        #gradients = K.gradients(y_pred, self.critic_model.layer[self.interID].output)[0]
        #gradients = K.gradients(y_pred, averaged_samples)[0]
        #gradients = K.gradients(y_pred)[0]
        # compute the euclidean norm by squaring ...
        gradients_sqr = K.square(gradients)
        #   ... summing over the rows ...
        gradients_sqr_sum = K.sum(gradients_sqr,
                                  axis=np.arange(1, len(gradients_sqr.shape)))
        #   ... and sqrt
        gradient_l2_norm = K.sqrt(gradients_sqr_sum)
        # compute lambda * (1 - ||grad||)^2 still for each single sample
        gradient_penalty = K.square(1 - gradient_l2_norm)
        # return the mean as loss over all the batch samples
        return K.mean(gradient_penalty)

    def wasserstein_loss(self, y_true, y_pred):
        return -K.mean(y_true * y_pred)
    
    def custom(self,y_true,y_pred):
        pass
    
    def customLoss(self,y_true,y_pred):
        
        wasser = aw.argus_critic(y_true,y_pred)
        #wasser = self.wasserstein_loss(y_true,y_pred)
        #match = self.custom(y_true,y_pred)
        
        #return(wasser+match)
        return(wasser)

    def build_generator(self):
        
        noise = Input(shape=(self.latent_dim,))
        
        #z = Dense(32,activation="relu")(noise)
        #z0 = Dense(128,activation="relu")(noise)
        #z = Dense(128,activation="relu")(z0)
        
        logit_srcAddr = Dense(self.dimSrcAddr,activation = "linear")(noise)
        #srcAddr = Dense(self.dimSrcAddr,activation = "softmax")(noise)
        
        logit_dstAddr = Dense(self.dimDstAddr,activation = "linear")(noise)
        #dstAddr = Dense(self.dimDstAddr,activation = "softmax")(noise)
        
        sPort = Dense(self.dimSPort,activation = "sigmoid")(noise)
        
        logit_dPort = Dense(self.dimDPort,activation = "linear")(noise)
        #dPort = Dense(self.dimDPort,activation = "softmax")(noise)
        
        logit_proto = Dense(self.dimProto,activation = "linear")(noise)
        
        rate = Dense(self.dimRate,activation = "sigmoid")(noise)
        
        load = Dense(self.dimLoad,activation = "sigmoid")(noise)
        
        
        # round sPorts
        #def round(y):
        #    return(K.round(y))
        #sPort = Lambda(round,output_shape=(self.dimSPort,))(sPort)
            
        
        # gumbel max trick
        def sampling(logits_y):
            U = K.random_uniform(K.shape(logits_y))
            G = -K.log(-K.log(U + 1e-20) + 1e-20)
            y = logits_y + G # logits + gumbel noise
            return softmax(y / self.tau)
        
        srcAddr = Lambda(sampling,output_shape=(self.dimSrcAddr,))(logit_srcAddr)
        dstAddr = Lambda(sampling,output_shape=(self.dimDstAddr,))(logit_dstAddr)
        dPort = Lambda(sampling,output_shape=(self.dimDPort,))(logit_dPort)
        proto = Lambda(sampling,output_shape=(self.dimProto,))(logit_proto)

        y = Concatenate()([srcAddr,dstAddr,sPort,dPort,proto,rate,load])
        
        return Model(noise, y)
        
    def build_critic(self):
        flow = Input(shape=(self.inputDim,))
        #z0 = Dense(8,activation="relu")(flow)
        #z = Dense(4,activation="relu")(z0)
        #z = Dense(128,activation="relu")(flow)
        validity = Dense(1,activation="tanh")(flow)

        return Model(flow, validity)

    def train(self):
        # Adversarial ground truths
        valid = -np.ones((self.batch_size, 1))
        fake =  np.ones((self.batch_size, 1))
        dummy = np.zeros((self.batch_size, 1)) # Dummy gt for gradient penalty
        
        dLoss = np.ones((self.epochs,))
        gLoss = np.ones((self.epochs,))
        
        for epoch in range(self.epochs):

            for _ in range(self.n_critic):

                # ---------------------
                #  Train Discriminator
                # ---------------------

                # Select a random batch of images
                idx = np.random.randint(0, self.data.shape[0], self.batch_size)
                flows = self.data[idx]
                # Sample generator input
                noise = np.random.normal(0, 1, (self.batch_size, self.latent_dim))
                
                #aux = np.random.uniform(0, 1, (self.batch_size,1))
                #aux1 = aux+np.zeros((self.batch_size,self.inputDim))
                #aux2 = (1-aux1)
                #for i in [flows,noise,#aux1,aux2,
                #          valid,fake,dummy]:
                #    print(type(i))
                #    print(i.shape)
                
                # Train the critic
                d_loss = self.critic_model.train_on_batch([flows, noise#,aux1,aux2
                                                           ],
                                                                [valid, fake, dummy
                                                                 ])

            # ---------------------
            #  Train Generator
            # ---------------------
            g_loss = self.generator_model.train_on_batch(noise, valid)
            
            
            # record loss
            dLoss[epoch] = d_loss[0]
            gLoss[epoch] = g_loss

            # If at save interval => save generated image samples
            if epoch % self.sample_interval == 0:
                self.generate_samples(epoch)
                print ("%d [D loss: %f] [G loss: %f]" % (epoch, d_loss[0], g_loss))
        
        self.loss = {'dLoss':dLoss,'gLoss':gLoss}
        #pd.DataFrame({'dLoss':dLoss,'gLoss':gLoss}).to_csv()
        
        plt.plot(dLoss)
        plt.plot(gLoss)
        plt.title('model loss')
        plt.ylabel('loss')
        plt.xlabel('epoch')
        plt.legend(['Discriminator', 'Generator'], loc='upper left')
        plt.show()
        plt.savefig("loss_%d_%d.png" % (self.epochs,self.batch_size))

    def generate_samples(self, epoch):
        #noise = np.random.normal(0, 1, (self.data.shape[0], self.latent_dim))
        noise = np.random.normal(0, 1, (100, self.latent_dim))
        gen = self.generator.predict(noise)
        
        self.oneHot2DataFrame(gen).to_csv("flows/flow_%d.csv" % epoch)

if __name__ == '__main__':
    criticUpdates = [1,2,4,8]
    taus = [1/3, 2/3, 1, 4/3]
    batchSizes = [16,32,64,128]
    chunk = 100
    
    bs = 32
    nc = 1
    t = 2/3
    
    wgan = WGANGP(epochs=1+chunk*3, batch_size=bs, sample_interval=chunk, n_critic=nc,tau=t)
    #wgan.train(epochs=30000, batch_size=32, sample_interval=100)
    wgan.train()
    




















