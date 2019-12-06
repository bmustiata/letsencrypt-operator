from typing import Dict, Set, Any, Optional
from kubernetes import client, config, watch


import adhesive
import time
import unittest
import logging

from adhesive import Token

LOG = logging.getLogger(__name__)


config.load_kube_config()

test = unittest.TestCase()

already_running: Set[str] = set()
pending_events: Dict[str, Any] = dict()


class IngressEvent:
    id: str
    state: str
    event: Any


class Data:
    event: Optional[IngressEvent]


def get_event_id(event: IngressEvent) -> str:
    return event.id


@adhesive.task('Delete Secrets without Ingress')
def scan_for_secrets_without_ingress(context: Token[Data]):
    pass


@adhesive.gateway('Is certificate {id} in valid range?')
def is_certificate_event_id_in_valid_range_(context: Token[Data]):
    pass


@adhesive.message('Scan current certificates every hour.')
def message_scan_current_certificates_every_hour_(context):
    while True:
        time.sleep(3600)
    # message_data = 'data'
    # yield message_data


@adhesive.message('Listen for Ingress Objects')
def message_start_event(context: adhesive.Token[Data]):
    w = watch.Watch()
    beta = client.ExtensionsV1beta1Api()

    while True:
        try:
            for event in w.stream(beta.list_ingress_for_all_namespaces):
                print(event["object"].metadata.name)
                yield {
                    "event": event,
                    "id": event["object"].metadata.name,
                    "state": "new"
                }
        except Exception as e:
            # ignore exceptions on purpose
            LOG.info(f"Exception {e} ignored.")
            time.sleep(1)


@adhesive.task('Deduplicate Events')
def deduplicate_events(context: Token[Data]):
    global already_running
    global pending_events

    data = context.data
    assert data.event

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
    if event.state == "done" and not pending_events:
        return context.data

    # we have either a new event, or a done event arriving
    if event.state == "done":
        context.data.event = pending_events[event.id]
        del pending_events[event.id]

    event.state = "process"
    already_running.add(event.id)

    return context.data


@adhesive.task('Ensure certificate is valid for {event.id}')
def ensure_certificate_is_valid_for_event_id_(context: Token[Data]):
    pass


@adhesive.task('Set the event as processed')
def set_the_event_as_processed(context: Token[Data]):
    assert context.data.event
    context.data.event.state = "done"


adhesive.bpmn_build(
    "letsencrypt-operator.bpmn",
    wait_tasks=False)
