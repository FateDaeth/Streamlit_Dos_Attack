#!/usr/bin/env python
# coding: utf-8

# In[74]:


#TARP Rev 2

# Title : Dos attack visualization using K-means Clustering Algorithm 


# In[75]:


#importing useful modules

import pandas as pd
import numpy as np
from os import system


# In[76]:


#Read the Data

data = pd.read_csv('access_log.txt', error_bad_lines=False, sep=" ", names=['IP','Space','Blank','Date', 'TimeZone', 'Method', 'StatusCode', 'Bytes', 'Path', 'Browser'])


data2 = pd.read_csv('access_log.txt', error_bad_lines=False, sep=" ", names=['IP','Space','Blank','Date', 'TimeZone', 'Method', 'StatusCode', 'Bytes', 'Path', 'Browser'])

data = data.append(data2, ignore_index=True)


# In[77]:


#Feature Selection .. IP and Status Code

data = data.drop(['Space', 'Blank'], axis=1)
data = data.drop(['Date','TimeZone','Method','Bytes','Path','Browser'], axis=1)


# In[78]:


#To drop the null values from the dataset

data.dropna


# In[ ]:





# In[79]:


#Feature Selection

data= data.groupby(['IP','StatusCode']).StatusCode.agg('count').to_frame('Count').reset_index()
data.insert(0, 'IPCount', range(len(data)))
new_data = data.drop(['IP'], axis=1)


# In[80]:


import matplotlib.pyplot as mtp  
wc_list =[]
for i in range(1, 11):  
    kmeans = KMeans(n_clusters=i, init='k-means++', random_state= 42)  
    kmeans.fit(data['StatusCode'].values.reshape(-1,1))  
    wc_list.append(kmeans.inertia_)  
mtp.plot(range(1, 11), wc_list)  
mtp.title('The Elobw Method Graph')  
mtp.xlabel('Number of clusters(k)')  
mtp.ylabel('wc_list')  
mtp.show()  


# In[81]:


from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans


# In[94]:


#Data Scaling

sc = StandardScaler()
data_scaled = sc.fit_transform(new_data)


# In[95]:


#Creating Model

model = KMeans(n_clusters=4)

#Fit and Predict

pred  = model.fit_predict(data_scaled)


# In[96]:


#Adding Cluster Labels to dataset

data_pred = pd.DataFrame(data_scaled, columns=['IP_Scaled', 'StatusCode_Scaled','Count_Scaled'])
data_pred['Cluster'] = pred
data_final = pd.concat([data, data_pred], axis=1, sort=False)


# In[97]:



#library for plotting the graph

import plotly.graph_objs as go
import plotly.offline as pyo
import plotly.express as px


# In[86]:


#Plotting Scatter Graph Using Plotly


Graph   = px.scatter(data_final, 'Count', 'IP', 'Cluster', hover_data=['StatusCode'], color_continuous_scale='Jet')
layout  = go.Layout(title='No of Requests Per IP', hovermode='closest')
figure  = go.Figure(data=Graph, layout=layout)
graph = pyo.plot(figure, filename='Graph_IPCount.html', auto_open=False)


# In[98]:


#Finding IP resulting to DoS attacks

IPCluster_to_be_blocked = []
for index, row in data_final.iterrows():
    if data_final['Count'].loc[index] > 200:
          IPCluster_to_be_blocked.append(data_final['Cluster'].loc[index])
IPCluster_to_be_blocked = max(set(IPCluster_to_be_blocked), key = IPCluster_to_be_blocked.count)


# In[99]:


#Find the cluster to be blocked

print(IPCluster_to_be_blocked)


# In[100]:


#Block the IPs and create the Data
for index_in_data, row_in_data in data_final.iterrows():
    if data_final['Cluster'].loc[index_in_data] == IPCluster_to_be_blocked:
                #system("sudo iptables -A INPUT -s {0} -p tcp --destination-port 80 -j DROP".format(data_final['IP'].loc[index_in_data]))
                print(data_final['IP'].loc[index_in_data])

data_final.to_csv('BlockIP_Data.csv', index=False)


# In[ ]:




