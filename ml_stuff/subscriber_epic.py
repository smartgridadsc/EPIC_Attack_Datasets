import csv
import copy
import time
import broker
import sys
import numpy as np
import joblib
import tensorflow_addons as tfa
from tensorflow.keras import layers
from keras.models import Model, load_model

from multiprocessing import Process, Queue, set_start_method

def check_state(s,s1,s2,s3,s4):
    while True:
        sync_activated = s1.get()
        q2c_in_sync = s2.get()
        gen1_p_negative = s3.get()
        gen2_p_negative = s4.get()
        states = s.get()

        #print("sync_activated", sync_activated)
        #print("q2c_in_sync", q2c_in_sync)
        #print("gen1_p_negative", gen1_p_negative)
        #print("gen2_p_negative", gen2_p_negative)
        #print("states", states)

        if len(sync_activated) == 0 and len(q2c_in_sync) == 0 and len(gen1_p_negative) == 0 and len(gen2_p_negative) == 0:
            pass
        elif len(states) == 0:
            print("no states yet")
            counter_1 = 0
            counter_2 = 0
            counter_3 = 0
            counter_4 = 0
            #prepare new state vector
            new_state = [0,0,0,0,0]
            if len(sync_activated) != 0:
                counter_1 = sync_activated[-1][0]
                new_state[1] = sync_activated[-1][1]
            if len(q2c_in_sync) != 0:
                counter_2 = q2c_in_sync[-1][0]
                new_state[2] = q2c_in_sync[-1][1]
            if len(gen1_p_negative) != 0:
                counter_3 = gen1_p_negative[-1][0]
                new_state[3] = gen1_p_negative[-1][1]
            if len(sync_activated) != 0:
                counter_4 = gen2_p_negative[-1][0]
                new_state[4] = sync_activated[-1][1]
            max_counter = max(counter_1, counter_2, counter_3, counter_4)
            if max_counter != 0:
                new_state[0] = max_counter
                states.append(new_state)
        else:
            print("we got state")
            #check if we have anything new to resolve
            old_state = copy.deepcopy(states[-1])
            new_state = []
            if len(sync_activated) != 0:
                if sync_activated[-1][0] > old_state[0]:
                    if sync_activated[-1][1] == 0:
                       new_state = copy.deepcopy(old_state)
                       new_state[0] = sync_activated[-1][0]
                       new_state[1] = sync_activated[-1][1]
                    if sync_activated[-1][1] == 1:
                       new_state = copy.deepcopy(old_state)
                       new_state[0] = sync_activated[-1][0]
                       new_state[1] = sync_activated[-1][1]
            if len(q2c_in_sync) != 0:
                if q2c_in_sync[-1][0] > old_state[0]:
                    if q2c_in_sync[-1][1] == 0:
                           if len(new_state) == 0:
                               new_state = copy.deepcopy(old_state)
                               new_state[0] = q2c_in_sync[-1][0]
                               new_state[2] = q2c_in_sync[-1][1]
                           else:
                               if new_state[0] < q2c_in_sync[-1][0]:
                                   new_state[0] = q2c_in_sync[-1][0]
                               new_state[2] = q2c_in_sync[-1][1]
                    if q2c_in_sync[-1][1] == 1:
                            if len(new_state) == 0:
                                new_state = copy.deepcopy(old_state)
                                new_state[0] = q2c_in_sync[-1][0]
                                new_state[2] = q2c_in_sync[-1][1]
                            else:
                                if new_state[0] < q2c_in_sync[-1][0]:
                                    new_state[0] = q2c_in_sync[-1][0]
                                new_state[2] = q2c_in_sync[-1][1]
            if len(gen1_p_negative) != 0:
                if gen1_p_negative[-1][0] > old_state[0]:
                    if states[-1][3] != gen1_p_negative[-1][1]:
                          if len(new_state) == 0:
                               new_state = copy.deepcopy(old_state)
                               new_state[0] = gen1_p_negative[-1][0]
                               new_state[3] = gen1_p_negative[-1][1]
                          else:
                               if new_state[0] < gen1_p_negative[-1][0]:
                                   new_state[0] = gen1_p_negative[-1][0]
                               new_state[3] = gen1_p_negative[-1][1]
            if len(gen2_p_negative) != 0:
                if gen2_p_negative[-1][0] > old_state[0]:
                    if states[-1][3] != gen2_p_negative[-1][1]:
                          if len(new_state) == 0:
                               new_state = copy.deepcopy(old_state)
                               new_state[0] = gen2_p_negative[-1][0]
                               new_state[3] = gen2_p_negative[-1][1]
                          else:
                               if new_state[0] < gen2_p_negative[-1][0]:
                                   new_state[0] = gen2_p_negative[-1][0]
                               new_state[3] = gen2_p_negative[-1][1]

            if len(new_state) != 0:
                states.append(new_state)

            print("states_after", states)

        s.put(states)
        s1.put(sync_activated)
        s2.put(q2c_in_sync)
        s3.put(gen1_p_negative)
        s4.put(gen2_p_negative)

        time.sleep(1.0)

def do_prediction(q,s,scaler,gm,clf,downstream_model,decoder):
    #pass
    #while True:
    #    mied2_meas = q.get()
    #    if len(mied2_meas) > 0:
    #        print("MIED2_MEAS:", mied2_meas[-1])
    #    q.put(mied2_meas)
    #    time.sleep(1.0)

    #check state counter against measurement counter
    #get lowest state counter < all new measurement counters
    #then for each state with counter >= lowest state counter, get indexes and append states accordingly
    #if all new measurement counters > latest state counter, then append latest to all new measurements

    header = ['Ypred']
    
    with open('prediction.csv', 'a') as file:
        writer = csv.writer(file)
        writer.writerow(header)

    while True:
        somelist = q.get()
        states = s.get()
        if len(somelist) > 10:
            measarr = somelist[-10:]
            q.put(somelist[:-10])
            measarr = np.array(measarr)
            lowest_meas_counter = measarr[0,0]
            index = 0
            all_meas_less_states = 0
            if len(states) != 0:
                lowest_state_counter = states[-1][0]
                if lowest_state_counter < lowest_meas_counter:
                    index = -1
                    #best case
                else:
                    while lowest_state_counter > lowest_meas_counter:
                        try:
                            index -= 1
                            lowest_state_state_counter = states[index][0]
                        except:
                            index += 1
                            all_meas_less_states = 1
                            break

                if all_meas_less_states == 1:
                    #take latest state
                    state_to_copy = states[-1][1:]

                else:
                    #keep it simple for now
                    state_to_copy = states[index][1:]
            else:
                state_to_copy = [0,0,0,0]
            #broadcast states over measurement array
            states_repeat = np.repeat([state_to_copy], 10, axis=0)
            #concatenate measurements with states
            measarr = np.array(measarr)
            measarr= measarr[:,1:]
            testarr = np.concatenate((measarr, states_repeat), axis=1)
            s.put(states)
            
            with np.printoptions(suppress=True):
                print("TESTARR: {}".format(testarr))

            testarr =  testarr.flatten()
            testarr = scaler.transform(testarr.reshape(-1,1))
            newtest = testarr.reshape(1,10,8)

            RFpred = downstream_model.predict(newtest)
            Xpredtes = decoder.predict(RFpred)
            error_test = newtest-Xpredtes
            error_test = error_test.reshape(error_test.shape[0],80)
            testfea = gm.predict(error_test)
            testfea = testfea.reshape(testfea.shape[0],1)
            RFpred = RFpred.reshape(RFpred.shape[0], RFpred.shape[1]*RFpred.shape[2])
            RFpred1 = np.concatenate([RFpred, testfea],axis=1)
            Ypred = clf.predict(RFpred1)
            print("Ypred: {}".format(Ypred))
            with open('prediction.csv', 'a') as file:
                writer = csv.writer(file)
                writer.writerow(Ypred)
            time.sleep(1)
        else:
            print("not enough", len(somelist))
            q.put(somelist)
            s.put(states)
            time.sleep(1)


def get_data(q,s1,s2,s3,s4):
    endpoint = broker.Endpoint()
    subscription = endpoint.make_subscriber("epic")
    status_subscription = endpoint.make_status_subscriber(True)
    endpoint.peer("127.0.0.1", 9999)

    status = status_subscription.get()
    print("status: ".format(status), flush=True)

    c = 0

    while True:
        tag, data = subscription.get()
        somedata = broker.bro.Event(data).args()[0]
        #MIED2 MEAS
        if somedata[4] == 'MIED2PROT_LLN0$Measurement':
            c += 1
            somelist = q.get()
            somelist.append([c, float(somedata[1+4]), float(somedata[2+4]), float(somedata[4+4]), float(somedata[16+4])])
            q.put(somelist)
        #Sync_Activated
        if somedata[4] == 'SCADA_Q2C_Sync_Activated':
            c += 1
            somelist = s1.get()
            if somedata[4+19] == 'true':
                somelist.append([c, 1])
            s1.put(somelist)
        #Q2C_In_Sync
        if somedata[4] == 'Q2C_In_Sync':
            c += 1
            somelist = s2.get()
            if somedata[4+20] == 'true':
                somelist.append([c, 1])
            s2.put(somelist)
        #GEN1_P_Negative
        if somedata[4] == 'GEN1_P_Negative':
            c += 1
            somelist = s3.get()
            if somedata[4+21] == 'true':
                somelist.append([c, 1])
            elif somedata[4+21] == 'false':
                somelist.append([c, 0])
            s3.put(somelist)
        #GEN2_P_Negative
        if somedata[4] == 'GEN2_P_Negative':
            c += 1
            somelist = s4.get()
            if somedata[4+22] == 'true':
                somelist.append([c, 1])
            elif somedata[4+22] == 'false':
                somelist.append([c, 0])
            s4.put(somelist)       
        #VSD1_Stop_Cmd
        if somedata[4] == 'VSD1_Stop_Cmd':
            somelist = s1.get()
            print(c, somedata[4], somedata[4+23], somelist)
            s1.put(somelist)
            if somedata[4+23] == 'true':
                somelist1 = s1.get()
                somelist2 = s2.get()
                try:
                    if abs(somelist1[-1][0] - c) > 5: 
                        c += 1
                        somelist1.append([c,0]) 
                        somelist2.append([c,0])
                except:
                    pass
                s1.put(somelist1)
                s2.put(somelist2)


if __name__ == '__main__':
    set_start_method('spawn')

    q = Queue()
    s = Queue()
    s1 = Queue()
    s2 = Queue()
    s3 = Queue()
    s4 = Queue()

    q.put([])
    s.put([])
    s1.put([])
    s2.put([])
    s3.put([])
    s4.put([])

    scalerpath = '/home/adsc/model_demo_8features/scaler/scaler_8features.joblib'
    modelpath = '/home/adsc/model_demo_8features/'
    gmpath = '/home/adsc/model_demo_8features/gm/gm_8features.joblib'
    clfpath = '/home/adsc/model_demo_8features/clf/clf_8features.joblib'

    scaler = joblib.load(scalerpath)
    gm = joblib.load(gmpath)
    clf = joblib.load(clfpath)

    #representation extraction
    model = load_model(modelpath)
    model.summary()
    
    #We mainly need the first to the forth layers for the representation extractor.
    reshape = model.layers[1]
    dense = model.layers[2]
    
    # Extract the encoder.
    encoder = model.layers[3]
    
    # Pack as a model.
    patches = layers.Input(shape=(10, 8))
    x = reshape(patches)
    patch_embeddings = dense(x)
    encoder_outputs = encoder(patch_embeddings)
    
    # The outputs are the extracted representations
    downstream_model = Model(inputs = patches, outputs = encoder_outputs)

    # train the GMM and the downstream classifier
    pat=layers.Input(shape=(2,140))
    m = model.layers[4]
    n = model.layers[5]
    x1 = m(pat)
    x2 = n(x1)
    decoder = Model(inputs=pat, outputs=x2)

    p1 = Process(target=get_data, args=(q,s1,s2,s3,s4))
    p2 = Process(target=check_state, args=(s,s1,s2,s3,s4,))
    p3 = Process(target=do_prediction, args=(q,s,scaler,gm,clf,downstream_model,decoder,))

    p1.start()
    p2.start()
    p3.start()


                    
                
            
            
