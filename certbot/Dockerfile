FROM python:3.8-slim-buster

COPY requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

RUN apt-get update -y && \
    apt-get install -y curl && \
    curl -LO https://dl.eff.org/certbot-auto && \
    mv certbot-auto /usr/local/bin && \
    chown root /usr/local/bin/certbot-auto && \
    chmod 755 /usr/local/bin/certbot-auto && \
    certbot-auto --install-only -n && \
    rm -rf /var/lib/apt/lists/*

RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.17.0/bin/linux/amd64/kubectl && \
    mv kubectl /usr/local/bin && \
    chmod +x /usr/local/bin/kubectl

COPY new-certificate* /usr/local/bin/

USER 1000
ENV LE_AUTO_SUDO=
WORKDIR /usr/local/bin
ENTRYPOINT ["python", "new-certificate.py"]

