# This Docker image helps to run the tests in a fresh environment
# docker build -t pysec-test .
# docker run -it --rm pysec-test:latest /bin/bash

FROM python:3.6-slim

RUN apt-get update && apt-get install -y curl git
WORKDIR /root/home
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python3 get-pip.py
RUN git clone https://github.com/SAP/cloud-pysec
WORKDIR /root/home/cloud-pysec
RUN pip3 install -r requirements-tests.txt
