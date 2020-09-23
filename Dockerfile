FROM alpine:3.11

RUN apk add python3 py3-pip

COPY requirements.txt .
RUN pip3 install -r requirements.txt

COPY dot.py .

EXPOSE 853/tcp

CMD ["sh", "-c", "./dot.py --listen-address 0.0.0.0 --listen-port 853 --upstream-resolver 8.8.8.8 --certfile ${CERT_FILE} --keyfile ${KEY_FILE} --level DEBUG"]
