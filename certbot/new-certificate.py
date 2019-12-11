from typing import Optional, List

import adhesive
from adhesive.kubeapi import KubeApi
import http.server
import socketserver
import time
import requests
import os
import logging
import sys
import base64

LOG = logging.getLogger(__name__)

PORT = 8000


class Data:
    namespace: str
    domain_names: List[str]
    _error: Exception


httpd: Optional[socketserver.TCPServer] = None


@adhesive.task('Run HTTP Server')
def start_http_server(context: adhesive.Token) -> None:
    """
    Fire up a HTTP server.
    """
    global httpd

    os.makedirs('/tmp/www/.well-known/', exist_ok=True)
    os.chdir('/tmp/www')

    Handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", PORT), Handler) as httpd:  # type: ignore
        assert httpd

        LOG.info(f"serving at port {PORT}")
        httpd.serve_forever(poll_interval=1)


@adhesive.task('Wait for HTTP Server to be up')
def wait_for_http_server_to_be_up(context: adhesive.Token) -> None:
    wait_for_url(f'http://localhost:{PORT}/')


@adhesive.task('Wait for Connectivity')
def wait_for_connectivity(context: adhesive.Token[Data]) -> None:
    wait_for_url(f"http://{context.data.domain_names[0]}/.well-known/")


@adhesive.task('Create Certificate for {domain_name}')
def create_certificate_for_domain_name_(context: adhesive.Token[Data]) -> None:
    # certbot-auto renew --webroot --agree-tos --email
    # bogdan.mustiata@gmail.com -n -d vpn.ciplogic.com --webroot-path /tmp/www
    domains_as_string = f"-d {' -d '.join(context.data.domain_names)}"

    context.workspace.run(f"""
        certbot-auto certonly \\
                --webroot \\
                --agree-tos \\
                --email bogdan.mustiata@gmail.com \\
                -n \\
                {domains_as_string} \\
                --config-dir /tmp/le/config \\
                --work-dir /tmp/le/work \\
                --logs-dir /tmp/le/logs \\
                --webroot-path /tmp/www
    """)


@adhesive.task('Shutdown HTTP Server')
def stop_http_server(context: adhesive.Token) -> None:
    global httpd
    assert httpd

    httpd.shutdown()


@adhesive.task('Create Secret {namespace}-le')
def create_secret(context: adhesive.Token[Data]) -> None:
    kube = KubeApi(context.workspace)
    namespace = context.data.namespace
    domain_name = context.data.domain_names[0]

    tls_certificate = read_file_base64(f'/tmp/le/config/live/{domain_name}/cert.pem')
    tls_key = read_file_base64(f'/tmp/le/config/live/{domain_name}/privkey.pem')

    kube.apply(f"""
        apiVersion: v1
        kind: Secret
        type: kubernetes.io/tls
        metadata:
            name: {namespace}-le
            namespace: {namespace}
        data:
            tls.crt: {tls_certificate}
            tls.key: {tls_key}
    """)


@adhesive.task('Log Error')
def log_error(context: adhesive.Token[Data]) -> None:
    print(context.data._error)


@adhesive.task('Exit with error')
def exit_with_error(context: adhesive.Token) -> None:
    sys.exit(2)


def wait_for_url(url: str) -> None:
    """
    Waits for the URL to be available and return a 200
    response.
    """
    LOG.info(f"Waiting for: {url}")

    def wait_for_server():
        try:
            LOG.info("new request")
            r = requests.get(url)
            if r.status_code // 100 == 2:
                return True
        except Exception as e:
            LOG.info(f"Wait failed: {e}")

        return False

    for i in range(2500):  # 2500 * 0.4 = 1000 seconds
        if wait_for_server():
            return
        time.sleep(0.4)

    raise Exception("Timeouted.")


def main() -> None:
    domain_names = os.getenv("DOMAIN_NAMES")

    if not domain_names:
        print("No DOMAIN_NAMES were available in the environment")
        sys.exit(1)

    kubernetes_namespace = os.getenv("KUBERNETES_NAMESPACE")
    if not kubernetes_namespace:
        print("NO KUBERENETES_NAMESPACE was available in the environment")
        sys.exit(3)

    adhesive.bpmn_build(
        "new-certificate.bpmn",
        initial_data={
            "namespace": os.getenv('KUBERNETES_NAMESPACE'),
            "domain_names": domain_names.split(" ")
        })


def read_file_base64(file_name: str) -> str:
    with open(file_name, 'rb') as f:
        return base64.urlsafe_b64encode(f.read()).decode('utf-8')


if __name__ == '__main__':
    main()
