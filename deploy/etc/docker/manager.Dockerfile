#
# SPDX-License-Identifier: MIT
#
# Copyright (c) 2022 The Authors.
# Authors: Wei Yue  <@w-yue>
#
# Summary: Arion-manager service Dockerfile
#
# base image
FROM fwnetworking/python_base:latest

ENV PYTHONUNBUFFERED 1

# set working directory
WORKDIR /opt/arion/manager

# Add app
COPY build/manager /opt/arion/manager/
COPY build/bin /opt/arion/bin/

# install netcat and manager
RUN ln -snf /opt/arion/bin /trn_bin && \
    pip3 install /opt/arion/manager/

# Run app in shell format
CMD /etc/init.d/rsyslog restart && /opt/arion/manager/entrypoint.sh