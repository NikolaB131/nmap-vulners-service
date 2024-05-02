#!/bin/bash

wget https://github.com/vulhub/vulhub/archive/master.zip -O vulhub-master.zip
unzip vulhub-master.zip

# port 2222
cd /vulhub-master/libssh/CVE-2018-10933
docker compose up -d

# port 8080
cd /vulhub-master/nginx/CVE-2017-7529
docker compose up -d
