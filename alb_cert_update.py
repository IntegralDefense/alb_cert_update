import boto3
from loguru import logger
import pem

from config import (
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    AWS_SESSION_TOKEN,
    ALB_LISTENER_ARN,
    CERT_PRIVATE_KEY,
    CERT_PUBLIC_KEY,
    CERT_CHAIN,
)


def _read_pem_file(pem_file):
    cert = pem.parse_file(pem_file)
    return cert.as_bytes()


class ElbHandler:
    """ API for attaching certificate to ELB listener.

    Attributes:
        _client (obj): boto3.session.client with service name
            of 'elbv2'.
        _listener (str): ARN of the ELB listener where the certificate
            will be added.
    """

    def __init__(self, client):
        self._client = client
        if ALB_LISTENER_ARN is None:
            raise ValueError("No ALB Listener ARN defined.")
        self.listener = ALB_LISTENER_ARN

    def add_listener_certificate(self, cert_arn, default=True):
        """ Adds certificate to an ELB listener.

        Parameters:
            cert_arn (str): AWS ARN of the certificate from the
                AWS Certificate Manager.
            default (bool): Sets the certificate to default cert
                on the listener if True.

        Returns:
            response (dict): Dictionary containing certificates from
                boto3 library.
        """

        certs = [
            {
                "CertificateArn": cert_arn,
                "IsDefault": default,
            }
        ]
        response = self._client.add_listener_certificates(
            ListenerArn=self.listener,
            Certificates=certs,
        )
        return response


class AcmHandler:
    def __init__(self, client):
        self._client = client
        self._private_key = None
        self._public_key = None
        self._chain = None
        self.arn = None

    @property
    def private_key(self):
        pass

    @private_key.getter
    def private_key(self):
        return self._private_key

    @private_key.setter
    def private_key(self, pem_file):
        self._private_key = _read_pem_file(pem_file)
        logger.info(f"Private key staged from {pem_file}.")

    @property
    def public_key(self):
        pass

    @public_key.getter
    def public_key(self):
        return self._public_key

    @public_key.setter
    def public_key(self, pem_file):
        self._public_key = _read_pem_file(pem_file)
        logger.info(f"Public key staged from {pem_file}")

    @property
    def chain(self):
        pass

    @chain.getter
    def chain(self):
        return self._chain

    @chain.setter
    def chain(self, pem_file):
        self._chain = _read_pem_file(pem_file)
        logger.info(f"Chain file staged from {pem_file}")

    def import_certificate(self):
        """
        https://boto3.amazonaws.com/v1/documentation/api/latest/
        reference/services/acm.html#ACM.Client.import_certificate
        """
        response = self._client.import_certificate(
            Certificate=self._public_key,
            PrivateKey=self._private_key,
            CertificateChain=self._chain,
        )
        self.arn = response.get('CertificateArn')
        logger.info(
            f"Imported certificate and received CertificateArn of {self.arn}"
        )


def main():

    elb_client = boto3.client(
        'elbv2',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        aws_session_token=AWS_SESSION_TOKEN,
    )

    acm_client = boto3.client(
        'acm',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        aws_session_token=AWS_SESSION_TOKEN,
    )

    elb = ElbHandler(elb_client)
    acm = AcmHandler(acm_client)

    acm.private_key = CERT_PRIVATE_KEY
    acm.public_key = CERT_PUBLIC_KEY
    acm.chain = CERT_CHAIN

    acm.import_certificate()

    response = elb.add_listener_certificate(acm.arn)

    logger.info(f"Cert added to listener {elb.listener}:\n{response}")

    return


if __name__ == "__main__":

    exit(main())
