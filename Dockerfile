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
#use apline base image, Oracle one has problem with licence
FROM openjdk:8-jdk-alpine
#
LABEL author="Shirley Crompton" \
      vendor="UK RI STFC" \
      eu.mf2c-project.version="0.0.1-beta" \
      eu.mf2c-project.version.is-production="false" 
#
# regional CAU ip and port
ENV CAU_URL="127.0.0.1:46400"
# leader CAU ip and port
ENV LCAU_URL="127.0.0.1:46410"
RUN mkdir /var/app
#for sharing certificate and key with traefik
RUN mkdir /pkidata
VOLUME /pkidata
#
ADD cau-client.jar /var/app/cau-client.jar
WORKDIR /var/app
# 
EXPOSE 46065
#run the application
#CMD [ "java", "-jar", "cau-client.jar", $CAU_URL, $LCAU_URL ]
CMD exec java -jar cau-client.jar ${CAU_URL} ${LCAU_URL}

