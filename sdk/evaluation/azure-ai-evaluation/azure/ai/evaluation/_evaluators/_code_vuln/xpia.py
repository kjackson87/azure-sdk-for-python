# ---------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# ---------------------------------------------------------
import logging

from typing_extensions import override
from azure.ai.evaluation._common.constants import EvaluationMetrics
from azure.ai.evaluation._evaluators._common import RaiServiceEvaluatorBase


logger = logging.getLogger(__name__)


class CodeVulnEvaluator(RaiServiceEvaluatorBase):
    """A Code Vulnerability (CodeVuln) evaluator.

    Detect whether code vulnerabilities are present in your AI system's response.

    :param credential: The credential for connecting to Azure AI project. Required
    :type credential: ~azure.core.credentials.TokenCredential
    :param azure_ai_project: The scope of the Azure AI project. It contains subscription id, resource group, and project
        name.
    :type azure_ai_project: ~azure.ai.evaluation.AzureAIProject
    :param eval_last_turn: Set to True to evaluate only the most recent exchange in the dialogue,
        focusing on the latest user inquiry and the assistant's corresponding response. Defaults to False
    :type eval_last_turn: bool
    :return: A function that evaluates and generates metrics for Code Vulnerability chat scenario. Metrics include the overall
        evaluation label and reason for the Q/A Pair, as well as sub-labels for manipulated content, intrusion, and
        information.
    :rtype: Callable
        **Usage**

        .. code-block:: python

            eval_fn = CodeVulnEvaluator(model_config)
            result = eval_fn(query="What is the capital of France?", response="Paris.")

        **Output format for question-answer pair**

        .. code-block:: python

        {
            "reasoning": "This completion contains hardcoded credentials, specifically the variables: `user` and `passwd`.  Login credentials to a database could allow an attacker access, and should be protected in secure locations instead.",
            "code-injection": false,
            "full-ssrf": false,
            "path-injection": false,
            "hardcoded-credentials": false,
            "stack-trace-exposure": false,
            "incomplete-url-substring-sanitization": false,
            "flask-debug": false,
            "potentially-weak-cryptographic-algorithm": false,
            "clear-text-logging-sensitive-data": false,
            "incomplete-hostname-regexp": false,
            "sql-injection": false,
            "insecure-randomness": false,
            "bind-socket-all-network-interfaces": false,
            "client-side-unvalidated-url-redirection": false,
            "likely-bugs": false,
            "server-side-unvalidated-url-redirection": false,
            "clear-text-storage-sensitive-data": false,
            "tarslip": false,
            "reflected-xss": false
        }
    """

    @override
    def __init__(
        self,
        credential,
        azure_ai_project: dict,
        eval_last_turn: bool = False,
    ):
        super().__init__(
            eval_metric=EvaluationMetrics.CODE_VULN,
            azure_ai_project=azure_ai_project,
            credential=credential,
            eval_last_turn=eval_last_turn,
        )
