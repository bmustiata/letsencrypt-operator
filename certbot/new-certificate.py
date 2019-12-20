from typing import Optional, List, Set

import adhesive
from adhesive.kubeapi import KubeApi
import yamldict
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
    ingress_object: str


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


@adhesive.task('Create service for registering the domain')
def create_service_for_registering_the_domain(context: adhesive.Token[Data]) -> None:
    kubeapi = KubeApi(context.workspace, context.data.namespace)

    kubeapi.apply(f"""
        apiVersion: v1
        kind: Service
        metadata:
            name: register-domain
        spec:
            type: ClusterIP
            ports:
            - name: http
              port: {PORT}
            selector:
              app: register-domain
    """)


@adhesive.task('Delete service for registering domains')
def delete_service_for_registering_domains(context: adhesive.Token[Data]) -> None:
    kubeapi = KubeApi(context.workspace, context.data.namespace)
    kubeapi.delete(kind="service", name="register-domain")


@adhesive.task('Wait for HTTP Server to be up')
def wait_for_http_server_to_be_up(context: adhesive.Token[Data]) -> None:
    wait_for_url(f'http://localhost:{PORT}/')


@adhesive.task('Wait for domain {loop.value}')
def wait_for_domain_loop_value_(context: adhesive.Token[Data]) -> None:
    assert context.loop
    wait_for_url(f"http://{context.loop.value}/.well-known/")


@adhesive.task('Wait for service to be up')
def wait_for_service_to_be_up(context: adhesive.Token) -> None:
    wait_for_url(f'http://register-domain:{PORT}/')


@adhesive.task('Patch Ingress Object {ingress_object}')
def patch_ingress_object_ingress_object_(context: adhesive.Token[Data]) -> None:
    kubeapi = KubeApi(context.workspace, context.data.namespace)
    ingress = kubeapi.get(kind="ingress",
                          name=context.data.ingress_object,
                          namespace=context.data.namespace)

    domain_names: Set[str] = set()

    for rule in ingress.spec.rules:
        domain_names.add(rule.host)
        rule.http.paths._raw.insert(0, yamldict.create(f"""
            backend:
              serviceName: register-domain
              servicePort: http
            path: /.well-known/
        """))

    # W/A for:
    # https://github.com/kubernetes/ingress-nginx/issues/1567
    # NginX always redirects to ssl for some reason, even if no TLS
    # is configured.
    if not ingress.spec.tls:
        ingress.metadata.annotations["nginx.ingress.kubernetes.io/ssl-redirect"] = "false"

    context.data.domain_names = list(domain_names)
    kubeapi.apply(ingress)


def remove_well_known_paths(ingress):
    if "nginx.ingress.kubernetes.io/ssl-redirect" in ingress.metadata.annotations:
        del ingress.metadata.annotations["nginx.ingress.kubernetes.io/ssl-redirect"]

    for rule in ingress.spec.rules:
        for i in reversed(range(len(rule.http.paths))):
            path = rule.http.paths[i].path
            if path == '/.well-known/':
                del rule.http.paths[i]


@adhesive.task('Revert Ingress Object {ingress_object}')
def revert_ingress_object_ingress_object_(context: adhesive.Token[Data]) -> None:
    kubeapi = KubeApi(context.workspace, context.data.namespace)
    ingress = kubeapi.get(kind="ingress",
                          name=context.data.ingress_object,
                          namespace=context.data.namespace)

    remove_well_known_paths(ingress)

    kubeapi.apply(ingress)


@adhesive.task('Add TLS secret to ingress {ingress_object}')
def add_tls_secret_to_ingress(context: adhesive.Token[Data]) -> None:
    kubeapi = KubeApi(context.workspace, context.data.namespace)
    ingress = kubeapi.get(kind="ingress",
                          name=context.data.ingress_object,
                          namespace=context.data.namespace)

    remove_well_known_paths(ingress)

    ingress.spec.tls = [
        {
            "hosts": context.data.domain_names,
            "secretName": context.data.ingress_object
        }
    ]

    kubeapi.apply(ingress)


@adhesive.task('Create Certificate for {domain_names}')
def create_certificate_for_domain_name_(context: adhesive.Token[Data]) -> None:
    domains_as_string = f"-d {' -d '.join(context.data.domain_names)}"

    context.workspace.run(f"""
        export LE_AUTO_SUDO=
        certbot-auto certonly \\
                --webroot \\
                --agree-tos \\
                --no-bootstrap \\
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


@adhesive.task('Create Secret {ingress_object}')
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
            name: {context.data.ingress_object}
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
            r = requests.get(url, verify=False)  # we might get our own TLS
            if r.status_code // 100 == 2:
                return True
        except Exception as e:
            LOG.info(f"Wait failed: {e}")

        return False

    for i in range(500):  # 500 * 2 = 1000 seconds
        if wait_for_server():
            return
        time.sleep(2)

    raise Exception("Timeouted.")


def read_env(envvar: str) -> str:
    result = os.getenv(envvar)

    if not result:
        print(f"No {envvar} was available in the environment")
        sys.exit(1)

    return result


def main() -> None:
    kubernetes_namespace = read_env("KUBERNETES_NAMESPACE")
    ingress_object_name = read_env("INGRESS_OBJECT")

    adhesive.bpmn_build(
        "new-certificate.bpmn",
        initial_data={
            "namespace": kubernetes_namespace,
            "ingress_object": ingress_object_name,
        })


def read_file_base64(file_name: str) -> str:
    with open(file_name, 'rb') as f:
        return base64.urlsafe_b64encode(f.read()).decode('utf-8')


if __name__ == '__main__':
    main()
