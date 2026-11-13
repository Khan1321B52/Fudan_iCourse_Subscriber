"""Offline regressions for the UIS TOTP flow; every HTTP request is mocked.

Only public RFC 6238 data and deliberately fake authentication context are used.
Importing main does not call main.run or construct its pipeline components.
"""

import contextlib
import importlib
import io
import os
from pathlib import Path
import re
import runpy
import sys
import unittest
from unittest.mock import Mock, call, patch

import requests


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Never consult the operator's credential/model/SMTP environment at import time.
with patch.dict(os.environ, {}, clear=True):
    from src.api import webvpn
    from src.runtime import config
    main = importlib.import_module("main")


RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # RFC's ASCII 12345678901234567890
RFC_VECTORS = (
    (59, "287082"),
    (1111111109, "081804"),
    (1111111111, "050471"),
    (1234567890, "005924"),
    (2000000000, "279037"),
    (20000000000, "353130"),
)
STUDENT = "fake-student"
PASSWORD = "fake-password-never-log"
ENCRYPTED = "fake-encrypted-password-never-log"
OTP = "654321"
TOKEN = "fake-login-token-never-log"
LCK = "fake-lck-never-log"
REQUEST_NUMBER = "fake-request-number-never-log"
CHAIN = "fake-otp-chain-never-log"
USERNAME = "fake-canonical-user"
SENSITIVE = (RFC_SECRET, PASSWORD, ENCRYPTED, OTP, TOKEN, LCK, REQUEST_NUMBER, CHAIN)


def challenge(**overrides):
    result = {
        "code": 200, "second": True, "moduleCodes": ["userAndOtp"],
        "requestNumber": REQUEST_NUMBER, "authChainCode": CHAIN,
        "userName": USERNAME,
    }
    result.update(overrides)
    return result


def response(payload=None, **attributes):
    result = Mock(spec=requests.Response)
    result.status_code = 200
    result.headers = {}
    result.history = []
    result.text = ""
    result.url = "https://example.invalid/"
    result.json.return_value = payload
    for name, value in attributes.items():
        setattr(result, name, value)
    return result


class OfflineTestCase(unittest.TestCase):
    def setUp(self):
        # A missed mock must fail locally, never reach a real authentication host.
        guard = patch.object(
            requests.sessions.Session, "request",
            side_effect=AssertionError("Unexpected real HTTP request"),
        )
        guard.start()
        self.addCleanup(guard.stop)
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        for name, value in (("STUDENT_ID", STUDENT), ("PASSWORD", PASSWORD),
                            ("TOTP_SECRET", RFC_SECRET)):
            setting = patch.object(config, name, value)
            setting.start()
            self.addCleanup(setting.stop)

    def vpn(self):
        http = Mock(spec=requests.Session)
        http.headers = {}
        with patch.object(webvpn.requests, "Session", return_value=http):
            vpn = webvpn.WebVPNSession()
        return vpn

    def assert_redacted(self, *extra):
        text = self.output.getvalue() + "\n" + "\n".join(map(str, extra))
        for value in SENSITIVE:
            self.assertNotIn(value, text)

    def otp_request(self, vpn, offered=None, **kwargs):
        return vpn._authenticate_totp(
            challenge() if offered is None else offered,
            STUDENT, LCK, config.ICOURSE_BASE, "fake-request-type", **kwargs,
        )


class TotpCodeTests(OfflineTestCase):
    def test_public_rfc6238_sha1_vectors_use_six_digits(self):
        # RFC lists eight digits; the deployed UIS protocol uses the last six.
        for timestamp, expected in RFC_VECTORS:
            with self.subTest(timestamp=timestamp):
                actual = webvpn.totp_code(RFC_SECRET, timestamp)
                self.assertEqual(actual, expected)
                self.assertRegex(actual, r"^\d{6}$")

    def test_normalizes_case_whitespace_and_base32_padding(self):
        for secret in (RFC_SECRET.lower(), " \t" + RFC_SECRET + "\n",
                       "gez dgnbv\ngy3tqojq gezdgnbv gy3tqojq", RFC_SECRET + "===="):
            with self.subTest(secret=secret):
                self.assertEqual(webvpn.totp_code(secret, 59), "287082")

    def test_uses_default_clock_only_when_timestamp_omitted(self):
        with patch.object(webvpn.time, "time", return_value=59) as clock:
            self.assertEqual(webvpn.totp_code(RFC_SECRET), "287082")
            clock.assert_called_once_with()
        with patch.object(webvpn.time, "time") as clock:
            self.assertEqual(webvpn.totp_code(RFC_SECRET, 0), "755224")
            clock.assert_not_called()

    def test_uses_thirty_second_windows(self):
        self.assertEqual(webvpn.totp_code(RFC_SECRET, 30), "287082")
        self.assertEqual(webvpn.totp_code(RFC_SECRET, 59.999), "287082")
        self.assertNotEqual(webvpn.totp_code(RFC_SECRET, 60), "287082")

    def test_missing_secret_is_actionable_second_factor_error(self):
        for secret in ("", " \t\n", "===="):
            with self.subTest(secret=secret):
                with self.assertRaisesRegex(webvpn.SecondFactorError, "UIS_TOTP_SECRET"):
                    webvpn.totp_code(secret, 59)

    def test_invalid_base32_is_redacted_second_factor_error(self):
        for secret in ("not-a-valid-secret!", "00000000", "A", "otpauth://totp/fake"):
            with self.subTest(secret=secret):
                with self.assertRaises(webvpn.SecondFactorError) as caught:
                    webvpn.totp_code(secret, 59)
                self.assertIn("Base32", str(caught.exception))
                self.assertNotIn(secret, str(caught.exception))
                self.assertTrue(caught.exception.__suppress_context__)


class TotpChallengeTests(OfflineTestCase):
    def test_success_accepts_integer_and_string_200(self):
        for code in (200, "200"):
            with self.subTest(code=code):
                vpn = self.vpn()
                body = {"code": code, "loginToken": TOKEN}
                resp = response(body)
                vpn.session.post.return_value = resp
                with patch.object(webvpn, "totp_code", return_value=OTP) as generator:
                    self.assertIs(self.otp_request(vpn), body)
                generator.assert_called_once_with(RFC_SECRET)
                resp.raise_for_status.assert_called_once_with()
                self.assert_redacted()

    def test_direct_and_vpn_request_preserve_challenge_context(self):
        for via_vpn in (False, True):
            with self.subTest(via_vpn=via_vpn):
                vpn = self.vpn()
                vpn.session.post.return_value = response({"code": 200, "loginToken": TOKEN})
                with patch.object(webvpn, "totp_code", return_value=OTP):
                    self.otp_request(vpn, via_vpn=via_vpn)
                base = webvpn.get_vpn_url(config.IDP_BASE) if via_vpn else config.IDP_BASE
                vpn.session.post.assert_called_once_with(
                    base + "/idp/authn/authExecute",
                    json={
                        "authModuleCode": "userAndOtp", "authChainCode": CHAIN,
                        "entityId": config.ICOURSE_BASE, "requestNumber": REQUEST_NUMBER,
                        "requestType": "fake-request-type", "lck": LCK,
                        "authPara": {"loginName": USERNAME, "otpCode": OTP},
                    },
                    headers={"Content-Type": "application/json", "Referer": base + "/ac/",
                             "Origin": config.WEBVPN_BASE if via_vpn else config.IDP_BASE},
                    timeout=60,
                )

    def test_missing_or_empty_username_falls_back_to_student(self):
        for username in (None, ""):
            with self.subTest(username=username):
                vpn = self.vpn()
                vpn.session.post.return_value = response({"code": 200, "loginToken": TOKEN})
                with patch.object(webvpn, "totp_code", return_value=OTP):
                    self.otp_request(vpn, challenge(userName=username))
                self.assertEqual(vpn.session.post.call_args.kwargs["json"]["authPara"],
                                 {"loginName": STUDENT, "otpCode": OTP})

    def test_unsupported_challenge_never_generates_or_submits_otp(self):
        for modules in (None, [], ["userAndSms"], ["userAndPwd"]):
            with self.subTest(modules=modules):
                vpn = self.vpn()
                with patch.object(webvpn, "totp_code") as generator:
                    with self.assertRaises(webvpn.SecondFactorError) as caught:
                        self.otp_request(vpn, challenge(moduleCodes=modules))
                generator.assert_not_called()
                vpn.session.post.assert_not_called()
                self.assert_redacted(caught.exception)

    def test_incomplete_challenge_never_submits_otp(self):
        for key in ("requestNumber", "authChainCode"):
            for empty in (None, ""):
                with self.subTest(key=key, empty=empty):
                    vpn = self.vpn()
                    offered = challenge(**{key: empty})
                    with patch.object(webvpn, "totp_code") as generator:
                        with self.assertRaises(webvpn.SecondFactorError) as caught:
                            self.otp_request(vpn, offered)
                    generator.assert_not_called()
                    vpn.session.post.assert_not_called()
                    self.assert_redacted(caught.exception)

    def test_missing_or_invalid_secret_never_submits_otp(self):
        for secret in ("", "invalid-secret!"):
            with self.subTest(secret=secret):
                vpn = self.vpn()
                with patch.object(config, "TOTP_SECRET", secret):
                    with self.assertRaises(webvpn.SecondFactorError) as caught:
                        self.otp_request(vpn)
                vpn.session.post.assert_not_called()
                self.assert_redacted(caught.exception)
                if secret:
                    self.assertNotIn(secret, str(caught.exception))

    def test_unsuccessful_or_non_object_json_is_second_factor_error(self):
        for body in (None, [], "invalid", 200, {"code": 401, "message": TOKEN},
                     {"code": "500", "data": REQUEST_NUMBER}, {}, {"loginToken": TOKEN}):
            with self.subTest(body=body):
                vpn = self.vpn()
                vpn.session.post.return_value = response(body)
                with patch.object(webvpn, "totp_code", return_value=OTP):
                    with self.assertRaises(webvpn.SecondFactorError) as caught:
                        self.otp_request(vpn)
                self.assert_redacted(caught.exception)

    def test_additional_factor_or_absent_token_is_second_factor_error(self):
        for body in ({"code": 200, "second": True, "loginToken": TOKEN},
                     {"code": "200"}, {"code": 200, "loginToken": ""}):
            with self.subTest(body=body):
                vpn = self.vpn()
                vpn.session.post.return_value = response(body)
                with patch.object(webvpn, "totp_code", return_value=OTP):
                    with self.assertRaises(webvpn.SecondFactorError) as caught:
                        self.otp_request(vpn)
                self.assert_redacted(caught.exception)

    def test_invalid_json_is_redacted_second_factor_error(self):
        vpn = self.vpn()
        resp = response()
        resp.json.side_effect = ValueError(" ".join(SENSITIVE))
        vpn.session.post.return_value = resp
        with patch.object(webvpn, "totp_code", return_value=OTP):
            with self.assertRaises(webvpn.SecondFactorError) as caught:
                self.otp_request(vpn)
        self.assertTrue(caught.exception.__suppress_context__)
        self.assert_redacted(caught.exception)

    def test_request_exceptions_are_redacted_second_factor_errors(self):
        for error_type in (requests.RequestException, requests.Timeout, requests.ConnectionError):
            with self.subTest(error_type=error_type):
                vpn = self.vpn()
                vpn.session.post.side_effect = error_type(" ".join(SENSITIVE))
                with patch.object(webvpn, "totp_code", return_value=OTP):
                    with self.assertRaises(webvpn.SecondFactorError) as caught:
                        self.otp_request(vpn)
                self.assertTrue(caught.exception.__suppress_context__)
                self.assert_redacted(caught.exception)

    def test_http_errors_are_redacted_before_json_parsing(self):
        vpn = self.vpn()
        resp = response()
        resp.raise_for_status.side_effect = requests.HTTPError(" ".join(SENSITIVE))
        vpn.session.post.return_value = resp
        with patch.object(webvpn, "totp_code", return_value=OTP):
            with self.assertRaises(webvpn.SecondFactorError) as caught:
                self.otp_request(vpn)
        resp.json.assert_not_called()
        self.assertTrue(caught.exception.__suppress_context__)
        self.assert_redacted(caught.exception)


class AuthenticationWiringTests(OfflineTestCase):
    def execute_password(self, vpn):
        return vpn._auth_execute(STUDENT, ENCRYPTED, LCK, config.WEBVPN_BASE,
                                 "fake-password-chain", "fake-request-type")

    def test_auth_execute_without_second_factor_remains_one_request(self):
        for code in (200, "200"):
            with self.subTest(code=code):
                vpn = self.vpn()
                vpn.session.post.return_value = response({"code": code, "loginToken": TOKEN})
                with patch.object(vpn, "_authenticate_totp") as otp:
                    self.assertEqual(self.execute_password(vpn), TOKEN)
                otp.assert_not_called()
                vpn.session.post.assert_called_once()
                self.assertEqual(vpn.session.post.call_args.kwargs["json"]["authPara"],
                                 {"loginName": STUDENT, "password": ENCRYPTED, "verifyCode": ""})
                self.assert_redacted()

    def test_auth_execute_second_factor_wires_real_helper(self):
        vpn = self.vpn()
        vpn.session.post.side_effect = [response(challenge()),
                                       response({"code": "200", "loginToken": TOKEN})]
        with patch.object(webvpn, "totp_code", return_value=OTP):
            self.assertEqual(self.execute_password(vpn), TOKEN)
        self.assertEqual(vpn.session.post.call_count, 2)
        self.assertEqual(vpn.session.post.call_args.kwargs["headers"]["Origin"], config.IDP_BASE)
        self.assertEqual(vpn.session.post.call_args.kwargs["json"]["authModuleCode"], "userAndOtp")
        self.assert_redacted()

    def test_auth_execute_failure_and_missing_token_do_not_echo_response(self):
        for body in ({"code": 401, "message": " ".join(SENSITIVE)},
                     {"code": 200, "message": " ".join(SENSITIVE)}):
            with self.subTest(body=body):
                vpn = self.vpn()
                vpn.session.post.return_value = response(body)
                with self.assertRaises(RuntimeError) as caught:
                    self.execute_password(vpn)
                self.assert_redacted(caught.exception)

    def prepare_icourse(self, vpn, *, second):
        ticket = config.ICOURSE_BASE + "/?ticket=fake-cas-ticket"
        vpn.session.get.side_effect = [
            response(), response(url=config.IDP_BASE + "/ac/?lck=" + LCK),
            response({"data": "fake-public-key"}), response(), response({"code": 0}),
        ]
        password_result = challenge() if second else {"code": 200, "loginToken": TOKEN}
        posts = [response({"data": [{"moduleCode": "userAndPwd",
                                     "authChainCode": "fake-password-chain"}],
                           "requestType": "fake-request-type"}), response(password_result)]
        if second:
            posts.append(response({"code": "200", "loginToken": TOKEN}))
        posts.append(response(text='locationValue = "' + ticket + '";'))
        vpn.session.post.side_effect = posts
        return webvpn.get_vpn_url(ticket)

    def test_authenticate_icourse_wires_real_otp_helper_with_mock_http(self):
        vpn = self.vpn()
        ticket = self.prepare_icourse(vpn, second=True)
        with patch.object(vpn, "_encrypt_password", return_value=ENCRYPTED) as encrypt, \
                patch.object(webvpn, "totp_code", return_value=OTP) as generator:
            self.assertTrue(vpn.authenticate_icourse(STUDENT, PASSWORD))
        encrypt.assert_called_once_with(PASSWORD, "fake-public-key")
        generator.assert_called_once_with(RFC_SECRET)
        self.assertEqual(vpn.session.get.call_count, 5)
        self.assertEqual(vpn.session.post.call_count, 4)
        otp_call = vpn.session.post.call_args_list[2]
        base = webvpn.get_vpn_url(config.IDP_BASE)
        self.assertEqual(otp_call.args, (base + "/idp/authn/authExecute",))
        self.assertEqual(otp_call.kwargs["headers"],
                         {"Content-Type": "application/json", "Referer": base + "/ac/",
                          "Origin": config.WEBVPN_BASE})
        self.assertEqual(otp_call.kwargs["json"], {
            "authModuleCode": "userAndOtp", "authChainCode": CHAIN,
            "entityId": config.ICOURSE_BASE, "requestNumber": REQUEST_NUMBER,
            "requestType": "fake-request-type", "lck": LCK,
            "authPara": {"loginName": USERNAME, "otpCode": OTP},
        })
        self.assertEqual(vpn.session.post.call_args.kwargs["data"], {"loginToken": TOKEN})
        self.assertEqual(vpn.session.get.call_args_list[-2],
                         call(ticket, allow_redirects=True, timeout=90))
        self.assert_redacted()

    def test_authenticate_icourse_without_second_factor_skips_otp(self):
        vpn = self.vpn()
        self.prepare_icourse(vpn, second=False)
        with patch.object(vpn, "_encrypt_password", return_value=ENCRYPTED), \
                patch.object(vpn, "_authenticate_totp") as otp:
            self.assertTrue(vpn.authenticate_icourse(STUDENT, PASSWORD))
        otp.assert_not_called()
        self.assertEqual(vpn.session.post.call_count, 3)
        self.assert_redacted()

    def test_authenticate_icourse_propagates_second_factor_error(self):
        vpn = self.vpn()
        self.prepare_icourse(vpn, second=True)
        failure = webvpn.SecondFactorError("fake intervention required")
        with patch.object(vpn, "_encrypt_password", return_value=ENCRYPTED), \
                patch.object(vpn, "_authenticate_totp", side_effect=failure):
            with self.assertRaises(webvpn.SecondFactorError) as caught:
                vpn.authenticate_icourse(STUDENT, PASSWORD)
        self.assertIs(caught.exception, failure)
        self.assertEqual(vpn.session.post.call_count, 2)  # Never exchange a CAS ticket.
        self.assert_redacted(caught.exception)


class LoginRetryTests(OfflineTestCase):
    def test_second_factor_from_login_or_cas_closes_once_without_retry_or_sleep(self):
        for stage in ("login", "authenticate_icourse"):
            with self.subTest(stage=stage):
                vpn = Mock()
                failure = webvpn.SecondFactorError("fake intervention required")
                getattr(vpn, stage).side_effect = failure
                with patch.object(main, "WebVPNSession", return_value=vpn) as factory, \
                        patch.object(main.time, "sleep") as sleep:
                    with self.assertRaises(webvpn.SecondFactorError) as caught:
                        main.login_with_retry(max_attempts=4)
                self.assertIs(caught.exception, failure)
                factory.assert_called_once_with()
                vpn.login.assert_called_once_with()
                if stage == "login":
                    vpn.authenticate_icourse.assert_not_called()
                else:
                    vpn.authenticate_icourse.assert_called_once_with()
                vpn.session.close.assert_called_once_with()
                sleep.assert_not_called()
                self.assert_redacted(caught.exception)

    def test_runtime_error_from_login_or_cas_still_retries_with_fresh_session(self):
        for stage in ("login", "authenticate_icourse"):
            with self.subTest(stage=stage):
                first, second = Mock(), Mock()
                getattr(first, stage).side_effect = RuntimeError("fake transient outage")
                with patch.object(main, "WebVPNSession", side_effect=[first, second]) as factory, \
                        patch.object(main.time, "sleep") as sleep:
                    self.assertIs(main.login_with_retry(max_attempts=2), second)
                self.assertEqual(factory.call_count, 2)
                sleep.assert_called_once_with(5)
                second.login.assert_called_once_with()
                second.authenticate_icourse.assert_called_once_with()
                second.session.close.assert_not_called()

    def test_runtime_error_exhaustion_reraises_after_bounded_retries(self):
        sessions = [Mock(), Mock(), Mock()]
        failure = RuntimeError("fake persistent outage")
        for vpn in sessions:
            vpn.login.side_effect = failure
        with patch.object(main, "WebVPNSession", side_effect=sessions) as factory, \
                patch.object(main.time, "sleep") as sleep:
            with self.assertRaises(RuntimeError) as caught:
                main.login_with_retry(max_attempts=3)
        self.assertIs(caught.exception, failure)
        self.assertEqual(factory.call_count, 3)
        self.assertEqual(sleep.call_args_list, [call(5), call(5)])

    def test_success_returns_session_without_sleep_or_close(self):
        vpn = Mock()
        with patch.object(main, "WebVPNSession", return_value=vpn) as factory, \
                patch.object(main.time, "sleep") as sleep:
            self.assertIs(main.login_with_retry(), vpn)
        factory.assert_called_once_with()
        vpn.login.assert_called_once_with()
        vpn.authenticate_icourse.assert_called_once_with()
        vpn.session.close.assert_not_called()
        sleep.assert_not_called()


class ConfigurationWiringTests(unittest.TestCase):
    def test_config_reads_and_trims_explicit_totp_environment(self):
        with patch.dict(os.environ, {"UIS_TOTP_SECRET": " \t" + RFC_SECRET + "\n"}, clear=True):
            isolated = runpy.run_path(str(ROOT / "src" / "runtime" / "config.py"))
        self.assertEqual(isolated["TOTP_SECRET"], RFC_SECRET)

    def test_config_defaults_missing_totp_environment_to_empty(self):
        with patch.dict(os.environ, {}, clear=True):
            isolated = runpy.run_path(str(ROOT / "src" / "runtime" / "config.py"))
        self.assertEqual(isolated["TOTP_SECRET"], "")

    def test_both_workflows_bind_totp_secret_in_main_run_step_environment(self):
        # Deliberately inspect only the Run step's env block, not other steps.
        for filename in ("check.yml", "single_run.yml"):
            with self.subTest(workflow=filename):
                lines = (ROOT / ".github" / "workflows" / filename).read_text(encoding="utf-8").splitlines()
                starts = [i for i, line in enumerate(lines)
                          if re.fullmatch(r"\s*- name: Run\s*", line)]
                self.assertEqual(len(starts), 1)
                start = starts[0]
                env = {}
                in_env = False
                for line in lines[start + 1:]:
                    if line.startswith("      - "):
                        break
                    if re.fullmatch(r"        env:\s*", line):
                        in_env = True
                        continue
                    if line.startswith("        run:"):
                        break
                    if in_env:
                        match = re.fullmatch(r"          ([A-Za-z_][A-Za-z_0-9]*):\s*(.*?)\s*", line)
                        if match:
                            self.assertNotIn(match.group(1), env)
                            env[match.group(1)] = match.group(2)
                self.assertEqual(env.get("UIS_TOTP_SECRET"), "${{ secrets.UIS_TOTP_SECRET }}")
                self.assertEqual(env.get("StuId"), "${{ secrets.STUID }}")
                self.assertEqual(env.get("UISPsw"), "${{ secrets.UISPSW }}")


if __name__ == "__main__":
    unittest.main()
