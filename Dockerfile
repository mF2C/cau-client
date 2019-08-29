#############################################################################
# Copyright 2018 UKRI Science and Technology Facilities Council
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License 
#############################################################################
#use alpine base image, Oracle one has problem with licence
#alpine adapts to docker built platform
FROM openjdk:8-jdk-alpine
#
LABEL author="Shirley Crompton" \
      vendor="UK RI STFC" \
      eu.mf2c-project.version="2.1" \
      eu.mf2c-project.version.is-production="false" 
      
#RPI may not have netcat installed      
#RUN apt-get update
#RUN apt-get install netcat
      
#
# cloud CAU ip and port
ENV CCAU_URL="213.205.14.13:55443"
# local CAU ip and port, we use service/container name as the ip
#docker cloud
#ENV CAU_URL="cau-stfc1:55443"
#standalone, use cloud CAU for the moment
ENV CAU_URL="213.205.14.13:55443" 
RUN mkdir /var/app
#for sharing certificate and key with traefik
RUN mkdir /pkidata
VOLUME /pkidata
#
ADD mf2c-cauclient-jar-with-dependencies.jar /var/app/cau-client.jar
WORKDIR /var/app
# 
EXPOSE 46065
#run the application
CMD exec java -jar cau-client.jar ${CAU_URL} ${CCAU_URL}

