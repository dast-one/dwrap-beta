FROM kalilinux/kali-rolling

RUN apt-get update && apt-get upgrade -y && apt-get autoremove -y && apt-get install -y \
    curl wget dnsutils vim mc htop iperf3 iftop \
    git \
    npm \
    sqlmap \
    xsser \
    wordlists \
    dirsearch \
    amass \
    nodejs \
    whatweb \
    beef-xss \
&& apt-get clean && rm -rf /var/lib/apt/lists/*

RUN npm install --global yarn && \
    git clone --depth 1 https://github.com/AliasIO/wappalyzer.git && \
    cd wappalyzer && yarn install && yarn run link && \
    cd .. # && rm -rf wappalyzer
