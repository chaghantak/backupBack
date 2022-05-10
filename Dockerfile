FROM ubuntu:latest

ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
RUN mkdir -p /app
WORKDIR /app

RUN apt-get update && yes | apt-get upgrade
RUN apt-get install -y emacs wget bzip2 openjdk-8-jdk
RUN wget --quiet https://repo.anaconda.com/archive/Anaconda3-5.3.1-Linux-x86_64.sh
RUN bash Anaconda3-5.3.1-Linux-x86_64.sh -b -p /opt/anaconda3

ENV PATH /opt/anaconda3/bin:$PATH

RUN conda update conda
RUN conda update anaconda
RUN conda update --all

RUN conda create -n apt-lib python=3.8
ENV PATH /opt/anaconda3/envs/apt-lib/bin:$PATH
SHELL ["conda", "run", "-n", "apt-lib", "/bin/bash", "-c"]

RUN conda config --add channels conda-forge
RUN conda install flask flask-cors flask-restx flask-socketio flask-sqlalchemy psycopg2 neo4j-python-driver numpy
RUN pip install flask-pymongo kafka-python

RUN apt-get clean autoclean && apt-get autoremove --yes && rm -rf /var/lib/{apt,dpkg,cache,log}/