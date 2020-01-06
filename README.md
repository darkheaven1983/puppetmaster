# -*- coding: utf-8 -*-
"""
Created on Thu Aug  2 17:43:57 2018

@author: Zhiqi Feng
"""

# -*- coding: utf-8 -*-
"""
Created on Tue Jul 31 10:02:15 2018

@author: Zhiqi Feng
"""

import os
#os.chdir(r"C:\Users\Zhiqi Feng\Desktop\Splunk")
import re
import json
import os
import datetime
import time
import sys
import pandas as pd
import numpy as np
from elasticsearch import helpers
from elasticsearch import Elasticsearch
from sklearn.cluster import KMeans
from scipy.stats import mode

def get_swg_option(startTime, endTime):
#    setEndTime=setTime+datetime.timedelta(minutes=10)
    es_search_options = {
      "query": {
        "bool": {
          "filter": {
            "bool": {
              "must": [
                {
                  "range": {
                    "@timestamp": {
                      "gt": str(startTime).replace(" ","T")+".000Z",
                      "lt": str(endTime).replace(" ","T")+".000Z",
                    }
                  }
                }
              ]          
            }
          }
        }
      },
     "aggs":{
      "ipterm":{
        "terms":{"field":"userId.keyword","size":10000},
        "aggs": {
                  "sum_install": {
                      "date_histogram": {
                          "field": "@timestamp",
                              "interval": "hour"
                              },
                    "aggs": {
                        "types": {
                            "terms": {
                                "field": "type.keyword"
                                    },
                            "aggs": {
                                      "dest":{"cardinality": {"field": "destinationIp"}
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
    return es_search_options

def get_network_option(startTime, endTime):
#    setEndTime=setTime+datetime.timedelta(minutes=10)
    es_search_options = {
      "query": {
        "bool": {
          "filter": {
            "bool": {
              "must": [
                {
                  "range": {
                    "@timestamp": {
                      "gt": str(startTime).replace(" ","T")+".000Z",
                      "lt": str(endTime).replace(" ","T")+".000Z",
                    }
                  }
                }
              ]          
            }
          }
        }
      },
     "aggs":{
      "ipterm":{
        "terms":{"field":"userId.keyword","size":10000},
        "aggs": {
                  "sum_install": {
                      "date_histogram": {
                          "field": "@timestamp",
                              "interval": "hour"
                              },
                    "aggs": {
                        "types": {
                            "terms": {
                                "field": "type.keyword"
                                    },
                            "aggs": {
                                      "byte":{"sum":{"field": "orig_ip_bytes"}},
                                      "dest":{"cardinality": {"field": "resp_h"}
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
    return es_search_options
    
#def _dns_blockQuery():
#    subdomains=["skyguardmis"]
#    subdomain_query=[]
#    for i in subdomains:
#        subdomain_query.append({"wildcard":{"query":"*"+i+"*"}})
#    return subdomain_query    
#    
#    
#def get_dns_option(startTime, endTime):
#    es_search_options = {
#      "query": {
#        "bool": {
#          "filter": {
#            "bool": {
#              "must": [
#                {
#                  "range": {
#                    "@timestamp": {
#                      "gt": str(startTime).replace(" ","T")+".000Z",
#                      "lt": str(endTime).replace(" ","T")+".000Z",
#                    }
#                  }
#                }
#              ]          
#            }
#          }
#        }
#      },
#        "aggs": {
#          "ipterm": {
#              "terms": {"field":"sourceIp","size":10000},
#              "aggs": {
#                  "sum_install": {
#                      "date_histogram": {
#                          "field": "@timestamp",
#                              "interval": "day"
#                              },
#                    "aggs": {
#                        "types": {
#                            "terms": {
#                                "field": "type.keyword"
#                                    },
#                            "aggs": {
#			           "dns_query_pkt_length":{
#			    				"filter":  {"bool": {"must": [ {"range": {"query_pkt_length": {"gt":64}}}],
#			                                         "must_not":_dns_blockQuery()}}},
#                 "dns_query_entropy":{
#			    				"filter":  {"bool": {"must": [ {"range": {"query_entropy": {"gt":4.15}}}],
#			                                         "must_not":_dns_blockQuery()}}},
#                "dns_total_resource_records_length":{
#			    				"filter":  {"bool": {"must": [ {"range": {"total_resource_records_length": {"gt": 89}}}],
#			                                         "must_not":_dns_blockQuery()}}},
#                "dns_qtype_name":{
#			    				"filter":  {"bool": {"must": [ {"terms": {"qtype_name.keyword": ["CNAME", "TXT", "0", "NULL"]}}],
#			                                         "must_not":_dns_blockQuery()}}}
#                                            }
#                                        }
#                                    }   
#                                }
#                            }
#                        }
#                        }
#                        }
#    return es_search_options


def transform(data):
    for i in data.columns.tolist():
        if i not in ['timestamp']:
            for j in range(len(data)):
                data[i][j]=list(data[i])[j].get("doc_count")
    return(data)
    
def delRepeat(liebiao):
 for x in liebiao:
  while liebiao.count(x)>1:
   del liebiao[liebiao.index(x)]
 return pd.DataFrame(liebiao)




def working_time(data):
    
    """
    输入数据的结构，index，doc，hour
    第一：通过统计SWG表中用户最近一个月每个小时网络行为的记录条数，剔除周六整天，周天整天，以及周一到周五的12-14点的数据(统计过network单位时间内的flow,效果不好)；
    第二：对剩下的数据进行聚类，聚类数量为2（当用户出现下班不关机，还是有网络行为，但是无法确定出不同用户工作时间和非工作时间网络行为的固定比例，因此采用聚类）；
    第三：提取12点之前的大类数据（用户有正常上班行为的数据），0-12点之间，每个hour在大类中出现次数的分位数，
        计算出现次数大于中位数的最小的hour，作为上班时间，且上班时间大于等于6点；
    第四：提取12点后的大类数据（用户有正常上班行为的数据），13-23点之间，每个hour在大类中出现次数的分位数，
        计算出现次数大于中位数的最大的hour，作为下班时间，且下班时间大于15点；
    第五：所有用户工作时间中有缺失值通过按照公司所有用户上班或者下班时间的众数进行填充，出现缺失值的情况如下：
        部分用户工作时间，只有一两个小时网络行为很多，通过聚类，大部分hour的行为数据完全聚为一个小类，
        如果行为最多的时间段位12-15点之间或者早上6点之前，这样就无法求出上下班时间；
        如果行为最多时间在我们规定的时间范围内，那么只能求出一个上班时间或者下班时间；
        
    缺点：如果个别用户一天24小时都有网络行为，且网络行为数据量都比较均衡，只有一两个小时出现少量的网络行为，
         通过上面逻辑算出来的上下班时间一般都为（6点，23点）
         
    """
    working_time=pd.DataFrame()
    userId=list(set(data.index))
    start_list=[]
    end_list=[]
    for i in userId:
        compute_data=data[(data.index==i)]
        yc = list(compute_data['doc_count'])
        yc = [[i] for i in yc] # 把每个样本变成一个单独的‘向量’就可以了。
        if len(yc)>=2:
            estimator = KMeans(n_clusters=2)#构造聚类器
            estimator.fit(yc)#聚类
            estimator.cluster_centers_
            label=list(estimator.labels_)
            compute_data['label']=label
            if estimator.cluster_centers_[0]>estimator.cluster_centers_[1]:
                statistics=pd.DataFrame(compute_data[compute_data["label"]==0]['hour'].value_counts())
            else:
                statistics=pd.DataFrame(compute_data[compute_data["label"]==1]['hour'].value_counts())
            statistics_hour=statistics[statistics['hour']>=statistics['hour'].describe()[5]]
            if len(statistics_hour)>0:
                if len(statistics_hour[(statistics_hour.index<='12')&(statistics_hour.index>='06')])>0:
                    start=min(statistics_hour[(statistics_hour.index<='12')&(statistics_hour.index>='06')].index)
                else:
                    start=''
                
                if len(statistics_hour[statistics_hour.index>'15'])>0:
                    end=max(statistics_hour[statistics_hour.index>'15'].index)
                else:
                    end=''
            else:
                start=''
                end=''  
        else:
            start=''
            end=''  
        print(i,start,end)
        start_list.append(start)
        end_list.append(end)
    working_time['userId']=userId
    working_time['start']=start_list  
    working_time['end']=end_list
    working_time['end'][working_time['end']=='']=mode(working_time[working_time['end']!='']['end'])[0]
    working_time['start'][working_time['start']=='']=mode(working_time[working_time['start']!='']['start'])[0]
    return(working_time)




##################################################swg##################################################      
if __name__ == "__main__":    
    time_stamp="2018-08-30 23:59:00"
    default_time_span=336
    start =datetime.datetime.strptime(time_stamp,'%Y-%m-%d %H:%M:%S')-datetime.timedelta(hours=int(default_time_span)+8)    
    end = datetime.datetime.strptime(time_stamp,'%Y-%m-%d %H:%M:%S')-datetime.timedelta(hours=8)  
    es_search_options = get_swg_option(start , end)
    es = Elasticsearch([{"host": "172.22.149.230", "port": 9200}],http_auth=("", ""),timeout=300)
    swg_rslt=es.search(index="swg-*", body=es_search_options, size=1)         
    swg_rslt=swg_rslt["aggregations"]["ipterm"]["buckets"]   
#    netwrok_rslt=pd.DataFrame(netwrok_rslt)

    swg_sub_data=pd.DataFrame()
  
#    test_data=netwrok_rslt[0:10]
    for i in range(len(swg_rslt)):
        for j in range(len(swg_rslt[i]["sum_install"]["buckets"])):
            #print(i,j)
            aa = pd.DataFrame(swg_rslt[i]["sum_install"]["buckets"][j]['types']["buckets"])
            aa["sourceIp"]=swg_rslt[i]["key"]
            aa["timestamp"]=datetime.datetime.strptime(swg_rslt[i]["sum_install"]["buckets"][j]["key_as_string"],'%Y-%m-%dT%H:%M:%S.%fZ')+datetime.timedelta(hours=8)  
            swg_sub_data=swg_sub_data.append(aa)


#    sub_data.index=sub_data['sourceIp']

        
    swg_final_data=swg_sub_data.copy()
    swg_final_data.index=swg_final_data['sourceIp']
    swg_final_data=swg_final_data.drop(["dest",'key',"sourceIp"], axis=1)

    hour_list=[]
    weekday_list=[]
    for i in range(len(swg_final_data)):
        hour=swg_final_data["timestamp"][i].strftime("%H")
        hour_list.append(hour)
        weekday=swg_final_data["timestamp"][i].strftime("%A")
        weekday_list.append(weekday)
    swg_final_data['hour']=hour_list
    swg_final_data['weekday']=weekday_list
    
    test_data=swg_final_data[(swg_final_data['weekday']!='Sunday')&(swg_final_data['weekday']!='Saturday')&(swg_final_data['hour']!="12")&(swg_final_data['hour']!="13")]
    test_data=swg_final_data.drop(['timestamp','weekday'],axis=1)
    
    
    
    working_time_table=working_time(test_data)
