import unittest
from unittest.mock import patch

import requests
from requests.auth import HTTPDigestAuth

import retrieve_events


class FakeAdapter:
    def __init__(self):
        self.close_count = 0

    def close(self):
        self.close_count += 1


class FakeResponse:
    def __init__(self, status_code, result=None):
        self.status_code = status_code
        self.result = result or {}
        self.closed = False

    def raise_for_status(self):
        if self.status_code >= 400:
            error = requests.exceptions.HTTPError(
                f"{self.status_code} response"
            )
            error.response = self
            raise error

    def json(self):
        return self.result

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.adapters = {"http://": FakeAdapter()}
        self.auth = None
        self.call_count = 0

    def post(self, *args, **kwargs):
        self.call_count += 1
        return next(self.responses)


class EventPageRetryTests(unittest.TestCase):
    def setUp(self):
        self.device = {
            "name": "Test device",
            "username": "admin",
            "password": "secret",
        }

    @patch.object(retrieve_events.time_module, "sleep", return_value=None)
    def test_401_refreshes_digest_auth_and_retries(self, _sleep):
        unauthorized = FakeResponse(401)
        expected = {"AcsEvent": {"InfoList": []}}
        session = FakeSession(
            [unauthorized, FakeResponse(200, expected)]
        )

        result = retrieve_events.request_event_page(
            session,
            "http://device/events",
            self.device,
            {"AcsEventCond": {}},
            450,
        )

        self.assertEqual(result, expected)
        self.assertEqual(session.call_count, 2)
        self.assertTrue(unauthorized.closed)
        self.assertIsInstance(session.auth, HTTPDigestAuth)
        self.assertEqual(session.adapters["http://"].close_count, 1)

    @patch.object(retrieve_events.time_module, "sleep", return_value=None)
    def test_repeated_401_uses_all_attempts(self, _sleep):
        session = FakeSession(
            [
                FakeResponse(401)
                for _ in range(retrieve_events.EVENT_REQUEST_ATTEMPTS)
            ]
        )

        with self.assertRaises(retrieve_events.EventRetrievalError) as raised:
            retrieve_events.request_event_page(
                session,
                "http://device/events",
                self.device,
                {"AcsEventCond": {}},
                540,
            )

        self.assertEqual(
            raised.exception.attempts,
            retrieve_events.EVENT_REQUEST_ATTEMPTS,
        )
        self.assertEqual(
            session.call_count,
            retrieve_events.EVENT_REQUEST_ATTEMPTS,
        )


if __name__ == "__main__":
    unittest.main()
