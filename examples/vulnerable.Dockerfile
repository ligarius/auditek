# Dockerfile de ejemplo VULNERABLE A PROPÓSITO para `auditek scan container`.
FROM ubuntu:latest

ENV DB_PASSWORD=SuperSecret123
ARG AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE

RUN curl https://get.example.com/install.sh | bash
RUN chmod -R 777 /app && sudo mkdir /data

ADD https://example.com/app.tar.gz /app/
COPY . /app

EXPOSE 22 8080
# (sin instrucción USER -> corre como root)
