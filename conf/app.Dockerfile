# OpenResty on Debian
FROM openresty/openresty:buster

RUN apt-get update
RUN apt-get install -y vim less procps net-tools

#
# Install dependencies.
#
RUN apt-get install -y openresty-openssl-dev qrencode
RUN apt-get install -y luarocks

RUN luarocks install uuid
RUN luarocks install luafilesystem
RUN luarocks install otp \
    CRYPTO_DIR=/usr/local/openresty/openssl \
    OPENSSL_DIR=/usr/local/openresty/openssl

#
# Install Nginx/Openresty configuration.
#
COPY conf/nginx.conf /etc/nginx/nginx.conf
RUN ln -sf /etc/nginx/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

#
# Setup unprivileged user.
#
RUN useradd -m svc
RUN chown -R svc:svc /var/run/openresty/ /usr/local/openresty/nginx/
RUN chown -R root:root /usr/local/openresty/nginx/sbin/

#
# Source and data directories.
#
RUN mkdir -p /app /data
COPY src/public_html /app/public_html
COPY src/*.lua /app/
RUN chown -R svc:svc /app /data

#
# Run the service.
#
USER svc
EXPOSE 8000
ENTRYPOINT ["/usr/bin/openresty"]
CMD ["-g", "daemon off;"]
