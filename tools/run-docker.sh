#!/usr/bin/env sh
# First-time usage: docker build . && docker tag <id> libethard && ./run-docker.sh

dockerimage=libethard

docker run -it --rm -v $(pwd):/home/user/libethard:z -e LOCAL_USER_ID=`id -u` $dockerimage "$@"
