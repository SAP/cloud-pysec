# This Docker image helps to run the tests in a fresh environment
# docker build -t pysec-test .
# docker run -it --rm pysec-test:latest /bin/bash

FROM python:3.6-slim

RUN apt-get update && apt-get install -y git
WORKDIR /root/home
RUN pip install --upgrade pip
RUN git clone https://github.com/SAP/cloud-pysec
WORKDIR /root/home/cloud-pysec
RUN pip install -r requirements-tests.txt
