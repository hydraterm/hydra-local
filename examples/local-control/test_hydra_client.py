"""Client contract tests; demo.py supplies the separate real-daemon acceptance."""

import base64
import json
import socket
import unittest
from unittest.mock import patch

import hydra_client as sdk

INFO = {"ev": "daemon_info", "protocol_version": 3, "build_version": "fixture",
        "daemon_instance_id": "a" * 32, "generation_conditional_attach": True,
        "generation_conditional_mutations": True, "output_generation_echo": True}
SESSION = sdk.SessionRef("fixture", "generation-one", INFO["daemon_instance_id"])
GRID = {"ev": "grid", "id": SESSION.id, "output_generation": 1,
        "grid": {"generation": SESSION.generation, "revision": 1}}


def frame(value):
    return json.dumps(value).encode() + b"\n"


class Socket:
    def __init__(self, data=b"", fragment=65536):
        self.data = bytearray(frame(INFO) + data)
        self.fragment = fragment
        self.sent = []
        self.closed = False
        self.timeout = None

    def connect(self, endpoint):
        self.endpoint = endpoint

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.sent.append(json.loads(data))

    def recv(self, count):
        count = min(count, self.fragment)
        result = bytes(self.data[:count])
        del self.data[:count]
        return result

    def close(self):
        self.closed = True


class ClientTests(unittest.TestCase):
    def connect(self, data=b"", fragment=65536):
        sock = Socket(data, fragment)
        with patch.object(sdk.socket, "socket", return_value=sock):
            connection = sdk._Connection("/fixture.sock", 5)
        self.addCleanup(connection.close)
        return connection, sock

    def test_fragmented_unicode_and_coalesced_events_remain_in_order(self):
        first = {"ev": "test", "value": "界😀"}
        connection, _ = self.connect(frame(first) + frame({"ev": "next"}), fragment=1)
        self.assertEqual(connection.read(5), first)
        self.assertEqual(connection.read(5), {"ev": "next"})

    def test_invalid_and_truncated_frames_fail(self):
        for value in (b"[]\n", b"{}\n", b"null\n", b"{\n", b"\xff\n", b'{"ev":"test"}',
                      b'{"ev":"test","number":NaN}\n'):
            with self.subTest(value=value):
                connection, _ = self.connect(value)
                with self.assertRaises(sdk.HydraError):
                    connection.read(5)

    def test_incoming_and_outgoing_frame_caps_do_not_truncate(self):
        connection, sock = self.connect(b"x" * 65)
        with patch.object(sdk, "MAX_LINE_BYTES", 64):
            with self.assertRaisesRegex(sdk.HydraError, "wire limit"):
                connection.read(5)
            before = list(sock.sent)
            with self.assertRaisesRegex(sdk.HydraError, "nothing sent"):
                connection.send({"op": "write", "data": "x" * 65})
            self.assertEqual(sock.sent, before)

    def test_exact_wire_limit_includes_newline(self):
        event = {"ev": "test"}
        for adjustment, accepted in ((0, True), (-1, False)):
            connection, _ = self.connect(frame(event))
            with patch.object(sdk, "MAX_LINE_BYTES", len(frame(event)) + adjustment):
                if accepted:
                    self.assertEqual(connection.read(5), event)
                else:
                    with self.assertRaises(sdk.HydraError):
                        connection.read(5)
        connection, sock = self.connect()
        request = {"op": "list_sessions"}
        size = len(json.dumps(request, separators=(",", ":")).encode()) + 1
        with patch.object(sdk, "MAX_LINE_BYTES", size):
            connection.send(request)
        before = list(sock.sent)
        with patch.object(sdk, "MAX_LINE_BYTES", size - 1):
            with self.assertRaises(sdk.HydraError):
                connection.send(request)
        self.assertEqual(sock.sent, before)

    def test_deadline_does_not_reset_with_each_fragment(self):
        connection, sock = self.connect(b"abc", fragment=1)
        with patch.object(sdk.time, "monotonic", side_effect=[0, 0.2, 0.8, 1.1]):
            with self.assertRaises(TimeoutError):
                connection.read(1)
        self.assertAlmostEqual(sock.timeout, 0.2)

    def test_invalid_timeout_rejected(self):
        for value in (0, -1, float("nan"), float("inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                sdk.Hydra("/fixture.sock", value)

    def test_failed_hello_closes_socket(self):
        sock = Socket()
        sock.data = bytearray(frame({"ev": "sessions"}))
        with patch.object(sdk.socket, "socket", return_value=sock):
            with self.assertRaises(sdk.HydraError):
                sdk.Hydra("/fixture.sock").info()
        self.assertTrue(sock.closed)

    def test_listing_retains_exact_daemon_and_generation(self):
        sock = Socket(frame({"ev": "sessions", "sessions": [
            {"id": SESSION.id, "generation": SESSION.generation}]}))
        with patch.object(sdk.socket, "socket", return_value=sock):
            self.assertEqual(sdk.Hydra("/fixture.sock").sessions(), [SESSION])
        self.assertEqual(sock.sent[-1], {"op": "list_sessions"})
        self.assertTrue(sock.closed)

    def test_invalid_listing_never_silently_drops_rows(self):
        for rows in (None, [None], [{}], [{"id": "x", "generation": None}]):
            sock = Socket(frame({"ev": "sessions", "sessions": rows}))
            with self.subTest(rows=rows), patch.object(sdk.socket, "socket", return_value=sock):
                with self.assertRaises(sdk.HydraError):
                    sdk.Hydra("/fixture.sock").sessions()

    def test_actual_empty_daemon_omits_sessions_but_legacy_live_ids_are_not_enough(self):
        sock = Socket(frame({"ev": "sessions", "ids": []}))
        with patch.object(sdk.socket, "socket", return_value=sock):
            self.assertEqual(sdk.Hydra("/fixture.sock").sessions(), [])
        for legacy in ({"ids": [SESSION.id]}, {}, {"ids": None}, {"ids": False}, {"ids": {}}):
            sock = Socket(frame({"ev": "sessions"} | legacy))
            with self.subTest(legacy=legacy), patch.object(sdk.socket, "socket", return_value=sock):
                with self.assertRaises(sdk.HydraError):
                    sdk.Hydra("/fixture.sock").sessions()

    def test_attach_is_generation_conditional_and_close_never_kills(self):
        sock = Socket(frame(GRID))
        with patch.object(sdk.socket, "socket", return_value=sock):
            with sdk.Hydra("/fixture.sock").attach(SESSION, raw_output=True) as stream:
                self.assertEqual(stream.initial, GRID)
        self.assertEqual(sock.sent[-1], {
            "op": "attach", "id": SESSION.id, "expected_session_generation": SESSION.generation,
            "output_generation": 1, "want_raw_output": True})
        self.assertTrue(sock.closed)
        self.assertFalse(any(request["op"] == "kill" for request in sock.sent))

    def test_new_daemon_or_missing_capability_never_sends_attach(self):
        for change in ({"daemon_instance_id": "new"}, {"generation_conditional_attach": False},
                       {"output_generation_echo": False}, {"protocol_version": 2},
                       {"protocol_version": 4}, {"protocol_version": "3"}):
            sock = Socket()
            sock.data = bytearray(frame(INFO | change))
            with self.subTest(change=change), patch.object(sdk.socket, "socket", return_value=sock):
                with self.assertRaises(sdk.HydraError):
                    sdk.Hydra("/fixture.sock").attach(SESSION)
            self.assertEqual(sock.sent, [{"op": "daemon_info"}])
            self.assertTrue(sock.closed)

    def test_query_shares_connection_deadline(self):
        sock = Socket(frame({"ev": "sessions", "sessions": []}))
        times = iter([0, 0.1, 0.2, 0.3, 0.4, 5.1])
        with patch.object(sdk.socket, "socket", return_value=sock), \
                patch.object(sdk.time, "monotonic", side_effect=lambda: next(times, 5.1)):
            with self.assertRaises(TimeoutError):
                sdk.Hydra("/fixture.sock", 5).sessions()
        self.assertEqual(sock.sent, [{"op": "daemon_info"}])
        self.assertTrue(sock.closed)

    def test_wrong_restore_identity_is_rejected(self):
        for change in ({"id": "other"}, {"output_generation": 2}, {"output_generation": True},
                       {"grid": None},
                       {"grid": {"generation": "other"}},
                       {"ev": "session_attach_refused", "reason": "generation_mismatch"}):
            sock = Socket(frame(GRID | change))
            with self.subTest(change=change), patch.object(sdk.socket, "socket", return_value=sock):
                with self.assertRaises(sdk.HydraError):
                    sdk.Hydra("/fixture.sock").attach(SESSION)
            self.assertTrue(sock.closed)

    def test_input_is_exact_utf8_sent_not_execution_receipt(self):
        connection, sock = self.connect()
        stream = sdk.SessionStream(connection, SESSION, GRID)
        text = "sum 界\r\n"
        result = stream.send_text(text)
        self.assertEqual(result, {"status": "sent", "utf8_bytes": len(text.encode()), "executed": None})
        self.assertEqual(sock.sent[-1], {"op": "write", "id": SESSION.id,
                                       "expected_generation": SESSION.generation, "data": text})
        connection.info["generation_conditional_mutations"] = False
        before = len(sock.sent)
        with self.assertRaises(sdk.HydraError):
            stream.send_text(text)
        self.assertEqual(len(sock.sent), before)

    def test_ambiguous_input_is_never_retried(self):
        connection, sock = self.connect()
        with patch.object(sock, "sendall", side_effect=socket.timeout) as send:
            with self.assertRaisesRegex(sdk.HydraError, "delivery is unknown"):
                sdk.SessionStream(connection, SESSION, GRID).send_text("hello")
        self.assertEqual(send.call_count, 1)

    def test_stream_preserves_output_and_explicit_resync_in_order(self):
        raw = {"ev": "output", "id": SESSION.id, "generation": SESSION.generation,
               "revision": 2, "data": base64.b64encode(b"\xff\x1b[0m").decode(),
               "live_output_generation": 1}
        resync = {"ev": "resync_required", "id": SESSION.id, "live_output_generation": 1}
        connection, _ = self.connect(frame(raw) + frame(resync))
        stream = sdk.SessionStream(connection, SESSION, GRID)
        self.assertEqual(stream.output_bytes(stream.next_event(5)), b"\xff\x1b[0m")
        self.assertEqual(stream.next_event(5), resync)

    def test_automatic_grid_damage_and_exit_match_daemon_envelopes(self):
        # Resync Grid has no output_generation (only the initial Attach echoes it).
        events = [
            {"ev": "resync_required", "id": SESSION.id, "live_output_generation": 1},
            {"ev": "grid", "id": SESSION.id, "live_output_generation": 1,
             "grid": {"generation": SESSION.generation, "revision": 4}},
            {"ev": "damage", "live_output_generation": 1,
             "frame": {"id": SESSION.id, "generation": SESSION.generation,
                       "base_revision": 4, "revision": 5, "ops": []}},
            {"ev": "session_exited", "id": SESSION.id, "code": 0,
             "live_output_generation": 1},
        ]
        connection, _ = self.connect(b"".join(frame(event) for event in events))
        stream = sdk.SessionStream(connection, SESSION, GRID)
        self.assertEqual([stream.next_event(5) for _ in events], events)

    def test_wrong_live_ownership_is_rejected(self):
        valid = {"ev": "output", "id": SESSION.id, "generation": SESSION.generation,
                 "data": "", "live_output_generation": 1}
        for change in ({"id": "other"}, {"generation": "other"}, {"live_output_generation": 2},
                       {"live_output_generation": True}):
            connection, _ = self.connect(frame(valid | change))
            with self.subTest(change=change), self.assertRaises(sdk.HydraError):
                sdk.SessionStream(connection, SESSION, GRID).next_event(5)

    def test_invalid_base64_and_non_output(self):
        self.assertEqual(sdk.SessionStream.output_bytes({"ev": "grid"}), b"")
        for value in ("not-base64!", None):
            with self.assertRaises(sdk.HydraError):
                sdk.SessionStream.output_bytes({"ev": "output", "data": value})


if __name__ == "__main__":
    unittest.main()
