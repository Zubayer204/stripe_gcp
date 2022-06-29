# Import the Secret Manager client library.
from google.cloud import secretmanager
import google_crc32c
import logging
import traceback
import stripe
import json


PROJECT_ID = "lexical-helix-354113"
STRIPE_PLAN_ID = "plan_LsaghAN57FC81F"
STRIPE_SECRET_ID = "stripe_secret"


def try_catch_log(wrapped_func):
  def wrapper(*args, **kwargs):
    try:
      response = wrapped_func(*args, **kwargs)
    except Exception:
      # Replace new lines with spaces so as to prevent several entries which
      # would trigger several errors.
      error_message = traceback.format_exc().replace('\n', '  ')
      logging.error(error_message)
      return 'Error';
    return response;
  return wrapper;


def create_stripe_plan(customer_id, payment_method_id):
  return stripe.Subscription.create(
    customer = customer_id,
    items = [{
      "plan": STRIPE_PLAN_ID
    }],
    default_payment_method = payment_method_id
  ).get("id")

def create_payment_method(payment_info):
  return stripe.PaymentMethod.create(
    type = "card",
    card = {
      "number": payment_info.get('cardNumber'),
      "exp_month": payment_info.get('expirationMonth'),
      "exp_year": payment_info.get('expirationYear'),
      "cvc": payment_info.get('ccv'),
    }).get('id')

def create_stripe_customer(email, user_data, payment_info):
  customer = stripe.Customer.create(email = email, metadata = user_data)
  customer_id = customer['id']
  payment_method_id = create_payment_method(payment_info)
  stripe.PaymentMethod.attach(
    payment_method_id,
    customer = customer_id
  )
  return {
    "customer_id": customer,
    "plan": create_stripe_plan(customer_id, payment_method_id)
  }


@try_catch_log
def access_secret_version(project_id, secret_id, version_id, client):
    """
    Access the payload for the given secret version if one exists. The version
    can be a version number as a string (e.g. "5") or an alias (e.g. "latest").
    """

    # Create the Secret Manager client.

    # Build the resource name of the secret version.
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"

    # Access the secret version.
    response = client.access_secret_version(request={"name": name})

    # Verify payload checksum.
    crc32c = google_crc32c.Checksum()
    crc32c.update(response.payload.data)
    if response.payload.data_crc32c != int(crc32c.hexdigest(), 16):
        print("Data corruption detected.")
        return response

    # Print the secret payload.
    #
    # WARNING: Do not print the secret in a production environment - this
    # snippet is showing how to access the secret material.
    payload = response.payload.data.decode("UTF-8")
    return payload

@try_catch_log
def signup(request):

    if request.method == 'POST':
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '3600'
        }

        client = secretmanager.SecretManagerServiceClient()
        s_key = access_secret_version(PROJECT_ID, STRIPE_SECRET_ID, '1', client)
        # p_key = access_secret_version(PROJECT_ID, "stripe_publishable", '1', client)

        form_data = request.get_json()
        stripe.api_key = s_key

        if form_data:
            result = json.dumps(create_stripe_customer(form_data['email'], form_data['attributes'], form_data['card_data']), indent=4)
            return (result, 200, headers)

        return ('Please provide JSON data', 200, headers)

    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type'
    }

    return ("Only POST requests are allowed", 200, headers)

