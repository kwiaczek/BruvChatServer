FROM ubuntu:18.04

RUN apt -yqq update
RUN apt -yqq install python3 mongodb libsodium-dev python3-pip

COPY requirements.txt /tmp 
RUN pip3 install -r /tmp/requirements.txt

WORKDIR /bruvchatserver

EXPOSE 9300
