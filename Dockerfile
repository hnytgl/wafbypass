FROM debian:sid
LABEL version="1.1"
LABEL description="WAFBypass Dockerized"
LABEL author="hnytgl"
COPY bootstrap.sh /tmp/bootstrap.sh
RUN chmod +x /tmp/bootstrap.sh
RUN bash -c /tmp/bootstrap.sh