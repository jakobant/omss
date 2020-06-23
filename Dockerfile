FROM python:3.7-slim
RUN apt-get update && apt-get install -yq git libmariadb-dev-compat libmariadb-dev gcc
ADD ./src/* /app/
ADD ./requirements.txt /app/
ADD start.sh /usr/local/bin/
RUN mkdir -p /tmp
RUN pip3 install -r /app/requirements.txt

ENV HOME /app
ENTRYPOINT ["/usr/local/bin/start.sh"]
