import unittest
from unittest.mock import Mock, patch
from src.attachment_analysis import analyze_attachments
from src.google_safe_browsing import check_google_safe_browsing
from src.ml.predictor import predict_url
from src.redirects import get_redirect_chain
from src.scoring import score_url
from src.whitelist import is_whitelisted

class SecurityTests(unittest.TestCase):
    def test_boundary_safe_whitelist(self):
        self.assertTrue(is_whitelisted('https://google.com')[0])
        self.assertTrue(is_whitelisted('https://mail.google.com')[0])
        self.assertFalse(is_whitelisted('https://google.com.evil.com')[0])

    def test_scoring_is_safe_for_malformed_and_risky_urls(self):
        self.assertEqual(score_url('not a url')[1], 'UNKNOWN')
        self.assertEqual(score_url('http://192.168.1.1/login')[1], 'HIGH RISK')
        self.assertEqual(score_url('http://paypal-verify-login.tk/signin')[1], 'HIGH RISK')

    @patch('src.redirects.requests.head')
    def test_redirect_relative_and_loop_are_structured(self, head):
        first, second = Mock(), Mock()
        first.status_code, first.headers = 302, {'Location': '/login'}
        second.status_code, second.headers = 302, {'Location': 'https://example.com'}
        head.side_effect = [first, second]
        chain, error = get_redirect_chain('https://example.com', max_hops=3)
        self.assertEqual(chain, ['https://example.com', 'https://example.com/login'])
        self.assertEqual(error, 'Redirect loop detected')

    def test_malformed_redirect_and_missing_threat_key_are_partial_results(self):
        self.assertIsNotNone(get_redirect_chain('bad-url')[1])
        result = check_google_safe_browsing('https://example.com')
        self.assertIn('available', result)
        self.assertIsNone(result['malicious'])

    def test_attachment_metadata_without_execution(self):
        attachment = analyze_attachments([{'filename':'invoice.pdf.exe','mime_type':'application/octet-stream','content':b'x'}])['attachment_results'][0]
        self.assertEqual(attachment['risk'], 'SUSPICIOUS')
        self.assertEqual(len(attachment['sha256']), 64)

    def test_model_available_and_probabilities_are_bounded(self):
        result = predict_url('https://www.google.com')
        self.assertTrue(result['available'])
        self.assertGreaterEqual(result['phishing_probability'], 0)
        self.assertLessEqual(result['phishing_probability'], 1)

if __name__ == '__main__': unittest.main()
