import os

import dotenv

dotenv.load_dotenv()


AWS_ACCESS_KEY_ID = os.environ.get("ALB_CERT_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("ALB_CERT_SECRET_ACCESS_KEY")
AWS_SESSION_TOKEN = os.environ.get("ALB_CERT_SESSION_TOKEN")

ALB_LISTENER_ARN = os.environ.get("ALB_LISTENER_ARN")

CERT_PRIVATE_KEY = os.environ.get("ALB_CERT_PRIVATE_KEY")
CERT_PUBLIC_KEY = os.environ.get("ALB_CERT_PUBLIC_KEY")
CERT_CHAIN = os.environ.get("ALB_CERT_CHAIN")
