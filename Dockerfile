FROM ubuntu:16.04

RUN apt-get update && apt-get install -y build-essential && apt-get clean

RUN apt-get install -y python3 python3-pip 

WORKDIR /app 

COPY requirements.txt /app

RUN python3 -m pip install -r requirements.txt