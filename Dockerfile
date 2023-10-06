FROM ubuntu:jammy-20230916

# Install depdendencies
RUN apt update && apt install -y git make cmake gcc bash perl build-essential checkinstall zlib1g-dev wget

# Get openssl source
RUN wget https://www.openssl.org/source/openssl-3.0.2.tar.gz && tar -xf openssl-3.0.2.tar.gz
WORKDIR /openssl-3.0.2

# remove previous openssl lib (installed as dep for git)
RUN apt purge openssl -y

# Configure openssl - https://wiki.openssl.org/index.php/Compilation_and_Installation
RUN ./Configure enable-weak-ssl-ciphers --prefix=/usr/ --openssldir=/usr/ shared

# Build
RUN make

# install to defined prefix
RUN make install

WORKDIR /

# hack to prevent errors with multiple ssl versions
RUN rm -rf /openssl-3.0.2 \
    && rm /usr/lib/x86_64-linux-gnu/libssl.so.3 \
    && ln -s /usr/lib64/libssl.so.3 /usr/lib/x86_64-linux-gnu/libssl.so.3

# This command will check if the corresct cipher is installed
RUN openssl ciphers -V ALL | grep DES-CBC3-SHA

# install nginx and generate self-signed cert
RUN apt install -y nginx
RUN mkdir -p /etc/nginx/ssl
RUN LD_LIBRARY_PATH=/usr/lib64 openssl req -x509 -newkey rsa:4096 -keyout /etc/nginx/ssl/cert.key -out /etc/nginx/ssl/cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"

# copy poodle vulnerable configuration file
COPY ./nginx-config /etc/nginx/sites-available/poodle.conf
RUN ln -s /etc/nginx/sites-available/poodle.conf /etc/nginx/sites-enabled/poodle.conf

# mark vulnerable port as exposable
EXPOSE 1337

STOPSIGNAL SIGQUIT

CMD ["nginx", "-g", "daemon off;"]
