ARG SRC_PATH=ubuntu
ARG OS_VERSION=18.04

FROM ${SRC_PATH}:${OS_VERSION}
ENV SRC_IMG=${SRC_PATH}:${OS_VERSION}

#INSTALL EXPLORER LIBS
RUN apt-get update && \
    apt-get install wget nano vim -y --fix-missing

#COPY SRC
RUN mkdir -p /DAPS/
COPY /DAPS-Explorer/ /DAPS/
RUN rm /DAPS/config/*

#INSTALL NVM, NPM, NODE
RUN wget -qO- https://raw.githubusercontent.com/creationix/nvm/v0.33.11/install.sh | bash && \
    export NVM_DIR="$HOME/.nvm" && \
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" && \
    [ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion" && \
    nvm install 10 && \
    cd /DAPS/ && \
    npm install
    
EXPOSE 3001

CMD /bin/bash -c "trap: TERM INT; sleep infinity & wait"
