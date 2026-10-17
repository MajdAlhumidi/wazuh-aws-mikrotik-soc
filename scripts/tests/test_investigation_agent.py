import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

import investigation_agent


class InvestigationAgentPolicyTests(unittest.TestCase):
    def setUp(self):
        self.alert = {
            "rule": {"id": "100201", "level": 8, "description": "Suspicious connection"},
            "agent": {"id": "001", "name": "test-host", "ip": "10.0.0.15"},
            "data": {"srcip": "198.51.100.10"},
            "full_log": "Connection from 198.51.100.10 to host",
        }
        self.tempdir = tempfile.TemporaryDirectory()
        self.audit_path = os.path.join(self.tempdir.name, "audit.jsonl")
        self.env_patch = patch.dict(
            os.environ,
            {"SOC_AUDIT_LOG_PATH": self.audit_path, "SOC_AGENT_MAX_TOOL_STEPS": "2"},
        )
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()
        self.tempdir.cleanup()

    @patch("investigation_agent._dispatch_tool")
    def test_blocks_agent_scoped_query_to_another_host(self, dispatch):
        context = investigation_agent._new_context(self.alert, "INC-TEST")
        result = investigation_agent._execute_tool(
            context,
            "inspect_process_tree",
            {"agent_id": "999", "time_range_minutes": 30},
        )
        self.assertEqual(json.loads(result)["status"], "blocked")
        dispatch.assert_not_called()

    @patch("investigation_agent._dispatch_tool")
    def test_blocks_ip_not_observed_in_alert_or_evidence(self, dispatch):
        context = investigation_agent._new_context(self.alert, "INC-TEST")
        result = investigation_agent._execute_tool(
            context, "check_ip_reputation", {"ip": "8.8.8.8"}
        )
        self.assertEqual(json.loads(result)["status"], "blocked")
        dispatch.assert_not_called()

    @patch(
        "investigation_agent._dispatch_tool",
        return_value='{"status":"success","matches_count":1}',
    )
    @patch("investigation_agent.requests.post")
    def test_ollama_tool_result_is_fed_back_before_final_report(self, post, dispatch):
        tool_response = Mock()
        tool_response.raise_for_status = Mock()
        tool_response.json.return_value = {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "search_historical_incidents",
                            "arguments": {"query": "Suspicious connection"},
                        }
                    }
                ],
            }
        }
        final_response = Mock()
        final_response.raise_for_status = Mock()
        final_response.json.return_value = {
            "message": {
                "role": "assistant",
                "content": "# Incident Investigation Report\nEvidence reviewed.",
            }
        }
        post.side_effect = [tool_response, final_response]

        with patch.dict(
            os.environ,
            {
                "SOC_OLLAMA_URL": "http://localhost:11434/api/chat",
                "SOC_OLLAMA_MODEL": "test-model",
            },
        ):
            report, context = investigation_agent.run_dynamic_ollama_agent(
                self.alert, "system instructions", "INC-TEST"
            )

        self.assertIn("Incident Investigation Report", report)
        self.assertEqual(context["tool_calls"], 1)
        self.assertEqual(post.call_count, 2)
        second_body = post.call_args_list[1].kwargs["json"]
        self.assertTrue(
            any(message.get("role") == "tool" for message in second_body["messages"])
        )
        dispatch.assert_called_once()


if __name__ == "__main__":
    unittest.main()
