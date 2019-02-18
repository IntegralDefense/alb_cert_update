# alb_cert_update

A script to add a cert to AWS Certificate Manager and then update an ELB listener with
that certificate.

# Install

1. Clone the repo.
2. Setup environment:
    ```bash
    $ cd /path/to/alb_cert_update
    $ python3.7 -m venv venv
    $ source venv/bin/activate
    (venv) $ pip install -r requirements.txt
    ```
3. Create your own ```.env``` file from the template:
    ```bash
    $ cp .env.template .env
    ```
    
    _.env_
    
    ```python   
    # Credentials for alb_cert_update script
    ALB_CERT_ACCESS_KEY_ID=some_access_key_id_from_aws
    ALB_CERT_SECRET_ACCESS_KEY=some_access_key_from_aws
    ALB_CERT_SESSION_TOKEN=some_optional_session_token_from_aws
    
    # ALB information... which listener you're going to apply the
    # cert to.
    ALB_LISTENER_ARN=the_listenter_ARN_from_the_ELB
    
    # Certificate information (/path/to/whatever.pem)
    ALB_CERT_PRIVATE_KEY=/path/to/key.pem
    ALB_CERT_PUBLIC_KEY=/path/to/cert.pem
    ALB_CERT_CHAIN=/path/to/chain.pem
    ```
4. Run the script

    ```bash
    (venv) $ python alb_cert_update.py
    ```

Take a look at the boto3 documentation for more information.