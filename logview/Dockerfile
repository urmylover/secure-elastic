FROM node:alpine

WORKDIR  /view/ 

RUN apk --no-cache add openssl

RUN wget "https://github.com/zhaowenjian/secure-elastic-front/archive/master.tar.gz" -O- | tar zx -C /view \
    && mv /view/secure-elastic-front-master/* /view

EXPOSE 5000

CMD "node app.js"

