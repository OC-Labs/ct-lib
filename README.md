# CT OgWallet Integration Library

## Installation

```bash
pip install ct-lib
```

## Usage

### Login

```python
from ct_lib.og_wallet import OgWallet, GenerateLoginUrlResponse, AuthenticateResponse

base_url = "https://www.example.com/api/v1"
client_id = "client_id"
client_secret = "client_secret"

og_wallet = OgWallet(base_url, client_id, client_secret) # raises error on missing or invalid credentials/URL

# generate login URL
try:
    response = og_wallet.generate_login_url("http://crowdtransfer.com/login_callback", ["scope1", "scope2"])
except ValueError as e:
    print("Invalid URL or scopes provided!")
except RuntimeError as e:
    print("Network error or server responded with non 2xx status code!")
except Exception as e:
    print(f"An unexpected error occurred: {e}")

if not isinstance(response, GenerateLoginUrlResponse):
    print(f"Failed to generate login URL")
    exit(1)

login_url = response["url"]

# redirect user to login_url
# ... user logs in and authorizes scopes ...
# user is redirected back to the callback URL with the auth token
#
# the following code should be in the callback URL controller/handler
from django.http import HttpResponse
from ct_lib.og_wallet import OgWallet, GenerateLoginUrlResponse, AuthenticateResponse

og_wallet = OgWallet(base_url, client_id, client_secret)

def og_wallet_login_callback(request):
    token = request.GET.get("token")

    if not token:
        return HttpResponse("Token not found in request", status=400)

    try:
        response = og_wallet.authenticate(token)
    except ValueError as e:
        return HttpResponse("Invalid token provided!", status=400)
    except RuntimeError as e:
        return HttpResponse("Network error or server responded with non 2xx status code!", status=500)
    except Exception as e:
        return HttpResponse(f"An unexpected error occurred: {e}", status=500)

    if not isinstance(response, AuthenticateResponse):
        return HttpResponse("Unexpected response from server", status=500)

    print(f"User authenticated: {response.id} - {response.email}")

### rest of the code...
```

## Development

### Requirements
- Python 3.11
- Poetry

```bash
poetry install
```

### Testing

```bash
poetry run pytest
```


