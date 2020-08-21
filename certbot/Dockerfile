# compiled by docker-optimizer
# https://github.com/bmustiata/docker-optimizer
from python:3.8-slim-buster
env BUILD_DATE="2020.08.21-00:33:20"
copy requirements.txt /requirements.txt
run ( pip install -r /requirements.txt ) && ( apt-get update -y ) && ( apt-get install -y curl &&     curl -LO https://dl.eff.org/certbot-auto &&     mv certbot-auto /usr/local/bin &&     chown root /usr/local/bin/certbot-auto &&     chmod 755 /usr/local/bin/certbot-auto &&     certbot-auto --install-only -n ) && ( curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.17.0/bin/linux/amd64/kubectl &&     mv kubectl /usr/local/bin &&     chmod +x /usr/local/bin/kubectl ) && ( rm -rf /var/lib/apt/lists/* )
copy new-certificate* /usr/local/bin/
copy letsencrypt-operator* /usr/local/bin/
copy adhesive_config.yml /usr/local/bin/.adhesive/config.yml
user 1000
env LE_AUTO_SUDO=
workdir /usr/local/bin
entrypoint ["python", "letsencrypt-operator.py"]
