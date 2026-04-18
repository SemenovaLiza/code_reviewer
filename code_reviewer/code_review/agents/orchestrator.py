import logging

from agents.agent import security_agent


logger = logging.getLogger(__name__)


def orchestrator(payload):
    print(payload)