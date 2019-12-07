from typing import Optional

import adhesive
import http.server
import socketserver
import time
import requests

PORT = 8000


class Data:
    domain_name: str


httpd: Optional[socketserver.TCPServer] = None


@adhesive.task('Start HTTP Server')
def start_http_server(context: adhesive.Token) -> None:
    global httpd

    Handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", PORT), Handler) as httpd:  # type: ignore
        assert httpd

        print("serving at port", PORT)
        httpd.serve_forever(poll_interval=1)


@adhesive.task('Wait for HTTP Server to be up')
def wait_for_http_server_to_be_up(context: adhesive.Token) -> None:
    time.sleep(10)


@adhesive.task('Create Certificate for {domain_name}')
def create_certificate_for_domain_name_(context: adhesive.Token) -> None:
    pass


@adhesive.task('Stop HTTP Server')
def stop_http_server(context: adhesive.Token) -> None:
    global httpd
    assert httpd

    httpd.shutdown()


@adhesive.task('Create Secret')
def create_secret(context: adhesive.Token) -> None:
    pass


@adhesive.task('Wait for Connectivity')
def wait_for_connectivity(context: adhesive.Token) -> None:
    pass


@adhesive.task('Log Error')
def log_error(context: adhesive.Token) -> None:
    pass


adhesive.bpmn_build("new-certificate.bpmn")
