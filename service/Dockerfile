from ubuntu:18.04

ENV TERM linux
## for apt to be noninteractive
ENV DEBIAN_FRONTEND noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN true

## preesed tzdata, update package index, upgrade packages and install needed software

RUN echo "travis_fold:start:Dapt\033[33;1mservice Dockerfile apt\033[0m" && \
    echo "tzdata tzdata/Areas select America" > /tmp/preseed.txt; \
    echo "tzdata tzdata/Zones/America select Phoenix" >> /tmp/preseed.txt; \
    debconf-set-selections /tmp/preseed.txt && \
    apt-get update && \
    apt-get install -y tzdata && \
    apt-get -qq update -y && apt-get upgrade -y && \
    apt-get install -y software-properties-common &&  add-apt-repository -y ppa:ondrej/php && \
    apt-get install -y -qq byobu python-minimal php7.0-cgi php7.0-dev apache2 mysql-server php-mysql php7.0-mysqli wget && \
    echo "\ntravis_fold:end:Dapt\r"

COPY src/www/db.sql /root/db.sql
RUN chmod 0400 /root/db.sql && chown root:root /root/db.sql

COPY src/www/install_db.sh /root/install_db.sh
RUN chmod 0700 /root/install_db.sh && chown root:root /root/install_db.sh
RUN /root/install_db.sh

# dugging tools

RUN rm /var/www/html/index.html
COPY src/www/index.html /var/www/html/
RUN chmod 0444 /var/www/html/index.html

COPY src/www/000-default.conf /etc/apache2/sites-available/000-default.conf
COPY src/www/ports.conf /etc/apache2/ports.conf
RUN /usr/sbin/a2enmod cgi

RUN rm /etc/apache2/conf-enabled/serve-cgi-bin.conf
COPY src/www/php.ini /etc/php/7.0/cgi/php.ini

COPY src/www/mysqld.cnf /etc/mysql/mysql.conf.d/mysqld.cnf

#COPY shellme.so /usr/lib/php/20151012/shellme.so
#RUN chmod 0644 /usr/lib/php/20151012/shellme.so && chown root:root /usr/lib/php/20151012/shellme.so


#RUN mysql shellql -e "select count(*) from flag" || mysql < /root/db.sql

COPY libphpcpp.so.2.1.4 /usr/lib/libphpcpp.so.2.1.4
RUN chmod 0755 /usr/lib/libphpcpp.so.2.1.4 && chown root:root /usr/lib/libphpcpp.so.2.1.4
RUN ln -s /usr/lib/libphpcpp.so.2.1.4 /usr/lib/libphpcpp.so.2.1
RUN ln -s /usr/lib/libphpcpp.so.2.1.4 /usr/lib/libphpcpp.so

RUN useradd -s /bin/bash -m proxyuser

# Proxy
COPY src/cproxy/run_proxy.sh /run_proxy.sh
RUN chmod 0500 /run_proxy.sh && chown proxyuser:proxyuser /run_proxy.sh

COPY tcpproxy /usr/bin/tcpproxy
RUN chmod 0500 /usr/bin/tcpproxy && chown proxyuser:proxyuser /usr/bin/tcpproxy

RUN touch /var/log/tcpproxy.log && chmod 644 /var/log/tcpproxy.log && chown proxyuser:proxyuser /var/log/tcpproxy.log

RUN touch /flag && chmod 644 /flag && echo "OOO{WaTCH ouT FoR THaT ReTuRN TRiP}" > /flag
RUN chmod 400 /flag && chown proxyuser:proxyuser /flag

RUN wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh && sed -i 's/u27a4/u003e/g' ~/.gdbinit-gef.py

COPY shellme.so /usr/lib/php/20151012/shellme.so
RUN chmod 0644 /usr/lib/php/20151012/shellme.so && chown root:root /usr/lib/php/20151012/shellme.so

# PHP Script that calls shellme.so
RUN mkdir /var/www/html/cgi-bin && chown root:root /var/www/html/cgi-bin
COPY src/www/index.php /var/www/html/cgi-bin/index.php
RUN chmod 0555 /var/www/html/cgi-bin/index.php



RUN apt-get install -y emacs wget netcat gdb

EXPOSE 9090

CMD /etc/init.d/apache2 start && /etc/init.d/mysql start && su - proxyuser -c /run_proxy.sh
#CMD /etc/init.d/apache2 start && /etc/init.d/mysql start && /bin/bash

