from typing import Dict, Set, Any, Optional
import addict
from kubernetes import client, config, watch
from adhesive.kubeapi import KubeApi
import shlex


import adhesive
import time
import datetime
import base64
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from adhesive import Token

LOG = logging.getLogger(__name__)


try:
    config.load_kube_config()
    LOG.info("Loaded local Kubernetes config")
except Exception:
    config.load_incluster_config()
    LOG.info("Loaded cluster Kubernetes config")

already_running: Set[str] = set()
pending_events: Dict[str, Any] = dict()


class IngressObject:
    """
    The ingress object event read from the kubectl API.
    """
    pass


class IngressEvent:
    """
    Contains an ingress notification object that needs to be updated.
    """
    id: str
    namespace: str
    state: str
    event: Any


class Data:
    event: IngressEvent
    _error: Optional[str]
    valid_certificate: Optional[bool]


def get_event_id(event: IngressEvent) -> str:
    return event.id


@adhesive.message('Scan current certificates every hour.')
def message_scan_current_certificates_every_hour_(context):
    """
    We just compile a list of all the ingresses.
    """
    kubeapi = KubeApi(context.workspace)

    while True:
        try:
            time.sleep(3600)
            ingresses = kubeapi.getall(
                kind="ingress",
                namespace=KubeApi.ALL,
                filter="")

            for ingress in ingresses:
                yield addict.Dict({
                    "event": ingress,
                    "id": ingress.metadata.name,
                    "namespace": ingress.metadata.namespace,
                    "state": "new"
                })
        except Exception as e:
            LOG.error(f"Failure in scan certs every hour: {e}")
            time.sleep(1)


@adhesive.message('Listen for Ingress Objects')
def message_start_event(context: adhesive.Token[Data]):
    w = watch.Watch()
    beta = client.ExtensionsV1beta1Api()

    while True:
        try:
            for event in w.stream(beta.list_ingress_for_all_namespaces):
                obj = event["object"]

                if not obj.metadata.name or not obj.metadata.namespace:
                    LOG.warn(f"Don't know how to process: {event}")
                    continue

                yield addict.Dict({
                    "event": event,
                    "id": event["object"].metadata.name,
                    "namespace": event["object"].metadata.namespace,
                    "state": "new"
                })
        except Exception as e:
            # ignore exceptions on purpose
            LOG.info(f"Failure in listen for ingress objects: {e}")
            time.sleep(1)


@adhesive.gateway('Is certificate {event.id} in valid range?')
def is_certificate_event_id_in_valid_range_(context: Token[Data]):
    namespace = context.data.event.namespace
    name = context.data.event.id

    kubeapi = KubeApi(context.workspace)

    if not kubeapi.exists(
            kind="secret",
            name=name,
            namespace=namespace):
        context.data.valid_certificate = False
        LOG.info(f"Certificate for {namespace}/{name} not valid. Secret not found")
        return

    secret = kubeapi.get(
        kind="secret",
        name=name,
        namespace=namespace)

    if not secret:
        context.data.valid_certificate = False
        LOG.info(f"Certificate for {namespace}/{name} not valid. Secret not found")
        return

    if "tls.crt" not in secret.data:
        LOG.info(f"Certificate for {namespace}/{name} not valid. tls.crt not in secret")
        context.data.valid_certificate = False
        return

    try:
        certificate_data = base64.b64decode(secret.data["tls.crt"])
        cert = x509.load_pem_x509_certificate(certificate_data, default_backend())
    except Exception as e:
        LOG.info(f"Certificate for {namespace}/{name} not valid. Failure reading cert {e}")
        context.data.valid_certificate = False
        return

    now = datetime.datetime.now()
    # delta = datetime.timedelta(hours=1)
    delta = datetime.timedelta(days=7)

    if now < cert.not_valid_before:
        LOG.info(f"Certificate for {namespace}/{name} not valid. We're in the past. "
                 f"Now is {now}, certificate is between {cert.not_valid_before} and "
                 f"{cert.not_valid_after}.")
        context.data.valid_certificate = False
        return

    if now > cert.not_valid_after:
        LOG.info(f"Certificate for {namespace}/{name} not valid. We're in the future. "
                 f"Now is {now}, certificate is between {cert.not_valid_before} and "
                 f"{cert.not_valid_after}.")
        context.data.valid_certificate = False
        return

    if cert.not_valid_before + delta < now:
        LOG.info(f"Certificate for {namespace}/{name} not valid. Delta expired. "
                 f"Now is {now}, certificate is between {cert.not_valid_before} and "
                 f"{cert.not_valid_after}.")
        context.data.valid_certificate = False
        return

    LOG.info(f"Certificate for {namespace}/{name} is valid. Now is {now}, "
             f"certificate is between {cert.not_valid_before} and "
             f"{cert.not_valid_after}.")
    context.data.valid_certificate = True


@adhesive.task('Deduplicate Events for {event.id}')
def deduplicate_events(context: Token[Data]):
    global already_running
    global pending_events

    data = context.data

    # No event
    if not data.event:
        return

    event: IngressEvent = data.event

    # Since we already have events running, we let this token
    # pass through. Since the state will be "new" and not "process"
    # we'll drop this token.
    if event.state == "new" and event.id in already_running:
        pending_events[event.id] = event
        return context.data

    # If we're getting notified that a task finished, we're marking
    # the task as not running anymore for that event id type
    if event.state == "done":
        already_running.remove(event.id)

    # If we did a loop and we returned with the done event, and nothing
    # else is waiting we return
    if event.state == "done" and event.id not in pending_events:
        return context.data

    # we have either a new event, or a done event arriving
    if event.state == "done":
        context.data.event = pending_events[event.id]
        del pending_events[event.id]

    event.state = "process"
    already_running.add(event.id)

    return context.data


@adhesive.task('Create/Renew Certificate for {event.id}')
def create_or_renew_certificate_for_event_id_(context: adhesive.Token[Data]) -> None:
    kubeapi = KubeApi(context.workspace)

    try:
        kubeapi.apply(f"""
          apiVersion: batch/v1
          kind: Job
          metadata:
            name: {context.data.event.id}
            namespace: {context.data.event.namespace}
          spec:
            template:
              metadata:
                labels:
                  app: register-domain
              spec:
                containers:
                - name: register-domain
                  image: germaniumhq/certbot
                  imagePullPolicy: Always
                  command: ["python", "new-certificate.py"]
                  env:
                  - name: INGRESS_OBJECT
                    value: {context.data.event.id}
                  - name: KUBERNETES_NAMESPACE
                    value: {context.data.event.namespace}
                  - name: ADHESIVE_POOL_SIZE
                    value: "100"
                restartPolicy: Never
            backoffLimit: 4
        """)

        context.workspace.run(f"""
            kubectl wait \\
                    --for=condition=complete \\
                    --timeout=300s \\
                    --namespace={context.data.event.namespace} \\
                    job/{context.data.event.id}
        """)

    finally:
        kubeapi.delete(
            kind="job",
            name=context.data.event.id,
            namespace=context.data.event.namespace)
    # kubeapi.wait_job(
    #    name=context.data.event.id,
    #    namespace=context.data.event.namespace,
    #    timeout=300)  # 5 minutes


@adhesive.task('Log error')
def log_error(context: Token[Data]):
    LOG.error(f"Error: {context.data._error}")


@adhesive.task('Set the event as processed for {event.id}')
def set_the_event_as_processed(context: Token[Data]):
    assert context.data.event
    context.data.event.state = "done"


adhesive.bpmn_build(
    "letsencrypt-operator.bpmn",
    wait_tasks=False)
