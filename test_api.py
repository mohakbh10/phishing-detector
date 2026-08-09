import subprocess, time, urllib.request, urllib.error, json, socket, sys

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def run_api_tests():
    print("==================================================")
    print("RUNNING API ENDPOINT INTEGRATION TESTS (Zero-Dep)")
    print("==================================================")
    
    port = 8888
    if is_port_in_use(port):
        print(f"Port {port} is in use.")
        return

    print(f"Starting FastAPI app on port {port} using {sys.executable}...")
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "src.api:app", "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    time.sleep(2.0)
    base_url = f"http://127.0.0.1:{port}"
    
    try:
        # 1. GET /
        print("\n--- 1. Testing GET / ---")
        req = urllib.request.Request(f"{base_url}/")
        with urllib.request.urlopen(req) as res:
            data = json.loads(res.read().decode())
            print("Response:", data)
            assert "running" in data["message"].lower()

        # 2. GET /health
        print("\n--- 2. Testing GET /health ---")
        req = urllib.request.Request(f"{base_url}/health")
        with urllib.request.urlopen(req) as res:
            data = json.loads(res.read().decode())
            print("Response:", data)
            assert data["status"] == "healthy"

        # 3. POST /analyze/url
        print("\n--- 3. Testing POST /analyze/url ---")
        payload = json.dumps({"url": "http://paypal-verify-login.tk/signin"}).encode()
        req = urllib.request.Request(
            f"{base_url}/analyze/url", data=payload, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as res:
            data = json.loads(res.read().decode())
            print("Verdict:", data["verdict"])
            print("Score:", data["score"])
            assert data["verdict"] == "HIGH RISK"

        # 4. POST /analyze/email
        print("\n--- 4. Testing POST /analyze/email ---")
        payload = json.dumps({
            "email_text": "Check out http://1.1.1.1/update and http://google.com/"
        }).encode()
        req = urllib.request.Request(
            f"{base_url}/analyze/email", data=payload, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as res:
            data = json.loads(res.read().decode())
            print("Urls Found:", data["urls_found"])
            print("Overall Verdict:", data["overall_verdict"])
            assert data["urls_found"] == 2
            assert data["overall_verdict"] == "HIGH RISK"

        # 5. POST /analyze/eml
        print("\n--- 5. Testing POST /analyze/eml ---")
        eml_data = b"""From: "PayPal Security" <security@paypal.com>
To: target@victim.com
Subject: Notice: Account suspended
Date: Mon, 9 Aug 2026 12:00:00 +0000
Message-ID: <abc@paypal.com>
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: multipart/mixed; boundary="boundary"

--boundary
Content-Type: text/plain; charset=utf-8

We found suspicious activity. Verify here: http://paypal-verify-login.tk/signin

--boundary
Content-Type: application/octet-stream; name="invoice.exe"
Content-Disposition: attachment; filename="invoice.exe"

EXE-BYTES
--boundary--
"""
        boundary = "boundary123"
        content_type = f"multipart/form-data; boundary={boundary}"
        
        body = [
            f"--{boundary}".encode(),
            f'Content-Disposition: form-data; name="file"; filename="test.eml"'.encode(),
            b'Content-Type: message/rfc822',
            b'',
            eml_data,
            f"--{boundary}--".encode(),
            b''
        ]
        payload_eml = b'\r\n'.join(body)
        
        req = urllib.request.Request(
            f"{base_url}/analyze/eml", data=payload_eml,
            headers={"Content-Type": content_type, "Content-Length": str(len(payload_eml))}
        )
        with urllib.request.urlopen(req) as res:
            data = json.loads(res.read().decode())
            print("Email Subject:", data["email"]["subject"])
            print("Overall Verdict:", data["overall_verdict"])
            print("Overall Score:", data["overall_score"])
            print("SPF:", data["headers"]["spf"])
            print("Attachments count:", len(data["attachments"]))
            
            assert data["overall_verdict"] == "HIGH RISK"
            assert data["urls_found"] == 1
            assert len(data["attachments"]) == 1
            assert data["headers"]["spf"] == "fail"

        print("\n==================================================")
        print("ALL API ENDPOINT INTEGRATION TESTS PASSED!")
        print("==================================================")

    except urllib.error.HTTPError as e:
        print("HTTP Error occurred:", e.code, e.reason)
        print("Response body:", e.read().decode())
        raise e
    except Exception as e:
        print("An error occurred:", str(e))
        raise e
    finally:
        print("Shutting down FastAPI app subprocess...")
        process.terminate()
        try: process.wait(timeout=5)
        except Exception: process.kill()

if __name__ == "__main__":
    run_api_tests()
