FROM python:3.9-alpine
LABEL authors="markus_ef"

WORKDIR /usr/src/app
RUN mkdir /var/keys && mkdir /var/bot-tmp && mkdir /var/sign-secret
COPY requirements.txt ./
RUN apk add --no-cache gcc make python3-dev musl-dev libffi-dev openssl-dev && \
 pip install --no-cache-dir -r requirements.txt && \
    apk del gcc make python3-dev musl-dev libffi-dev openssl-dev

RUN apk add --no-cache gpg git

COPY . .

CMD [ "python", "-u", "./main.py" ]
