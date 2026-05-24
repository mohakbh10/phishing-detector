from src.scoring import score_url
url = "http://paypal-account-verify.tk/login"

score, verdict, reasons = score_url(url)

print(score)
print(verdict)
print(reasons)