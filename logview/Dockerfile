FROM node:alpine

WORKDIR  /view/ 

RUN apk --no-cache add openssl

RUN wget "https://github.com/zhaowenjian/secure-elastic-front/archive/master.tar.gz" -O- | tar zx -C /view \
    && mv /view/secure-elastic-front-master/* /view

RUN npm install --production

EXPOSE 5000

CMD ["/usr/local/bin/node","/view/app.js"]

