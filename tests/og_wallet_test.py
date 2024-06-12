from pytest_httpserver import HTTPServer
from ct_lib.og_wallet import OgWallet, GenerateLoginUrlResponse, AuthenticateResponse
from urllib.parse import quote
import pytest

client_id = "acme_id"
client_secret = "acme_secret"
redirect_uri = "https://acme.com/callback"

headers = {
    "Authorization": f"Bearer {client_secret}",
    "Content-Type": "application/json",
    "Accept": "application/json"
}

def test_generate_login_url_will_return_a_generate_login_url_response_instance_when_success(httpserver: HTTPServer):
    
    og_wallet = OgWallet(httpserver.url_for('/'), client_id, client_secret)

    scopes = ["email", "profile"]
    stringified_scopes = ",".join(scopes)
    query_string = f"clientId={client_id}&redirectURI={quote(redirect_uri)}&scopes={stringified_scopes}"

    httpserver.expect_oneshot_request(uri="/sso/generateURL", query_string=query_string, headers=headers) \
        .respond_with_json({"success": True, "url": "https://onchainlabs.ch/api/v1/sso/login?token=acme_token"})
    
    response = og_wallet.generate_login_url(redirect_uri, scopes)

    assert isinstance(response, GenerateLoginUrlResponse)
    assert response.success == True
    assert response.url == "https://onchainlabs.ch/api/v1/sso/login?token=acme_token"


def test_generate_login_url_will_raise_value_error_when_redirect_uri_is_invalid(httpserver: HTTPServer):
    
    og_wallet = OgWallet(httpserver.url_for('/'), client_id, client_secret)

    scopes = ["email", "profile"]

    with pytest.raises(ValueError) as e:
        og_wallet.generate_login_url("invalid_uri", scopes)

def test_generate_login_url_will_raise_value_error_when_scopes_is_invalid(httpserver: HTTPServer):
    
    og_wallet = OgWallet(httpserver.url_for('/'), client_id, client_secret)

    scopes = "email,profile"

    with pytest.raises(ValueError) as e:
        og_wallet.generate_login_url(redirect_uri, scopes)

def test_generate_login_url_will_raise_value_error_when_scopes_is_empty(httpserver: HTTPServer):
    
    og_wallet = OgWallet(httpserver.url_for('/'), client_id, client_secret)

    scopes = []

    with pytest.raises(ValueError) as e:
        og_wallet.generate_login_url(redirect_uri, scopes)

def test_generate_login_url_will_raise_runtime_error_when_response_status_code_is_not_2xx(httpserver: HTTPServer):
    
    og_wallet = OgWallet(httpserver.url_for('/'), client_id, client_secret)

    scopes = ["email", "profile"]
    stringified_scopes = ",".join(scopes)
    query_string = f"clientId={client_id}&redirectURI={quote(redirect_uri)}&scopes={stringified_scopes}"

    codes = [400, 401, 403, 404, 500]
    for code in codes:
        httpserver.expect_oneshot_request(uri="/sso/generateURL", query_string=query_string, headers=headers) \
            .respond_with_json({}, status=code)
        
        with pytest.raises(RuntimeError) as e:
            og_wallet.generate_login_url(redirect_uri, scopes)



def test_authenticate_will_return_an_authenticate_response_instance_when_success(httpserver: HTTPServer):
    
    og_wallet = OgWallet(httpserver.url_for('/'), client_id, client_secret)
    succesful_authenticate_response = {
        "success": True,
        "id": "00000000-0000-0000-0000-000000000000",
        "username": "Paco",
        "avatar": "https://acme.com/avatar.jpg",
        "email": "user@gmail.com",
        "key_2fa": None,
        "verified": True,
        "banned": True,
        "role": {
            "id": 1,
            "name": "Guest",
            "slug": "guest",
            "description": "Guest",
            "image": "https://acme.com/guest.jpg"
        },
        "permissions": [],
        "wallet": {
            "eth_address": "0x0000000000000000000000000000000000000000"
        }
    }

    token = "acme_token"
    query_string = f"clientId={client_id}"
    payload = {
        "ssoToken": token,
        "clientId": client_id
    }

    httpserver.expect_oneshot_request(uri="/sso/authenticate", query_string=query_string, headers=headers, method="POST", json=payload) \
        .respond_with_json(succesful_authenticate_response)
    
    response = og_wallet.authenticate(token)

    assert isinstance(response, AuthenticateResponse)
    assert response.success == True
    assert response.id == "00000000-0000-0000-0000-000000000000"
    assert response.username == "Paco"
    assert response.avatar == "https://acme.com/avatar.jpg"
    assert response.email == "user@gmail.com"
    assert response.key_2fa == None
    assert response.verified == True
    assert response.banned == True
    assert response.role == {
        "id": 1,
        "name": "Guest",
        "slug": "guest",
        "description": "Guest",
        "image": "https://acme.com/guest.jpg"
    }

    assert response.permissions == []
    assert response.wallet == {
        "eth_address": "0x0000000000000000000000000000000000000000"
    }

def test_authenticate_will_raise_value_error_when_token_is_invalid(httpserver: HTTPServer):
        
        og_wallet = OgWallet(httpserver.url_for('/'), client_id, client_secret)
    
        with pytest.raises(ValueError) as e:
            og_wallet.authenticate("")

def test_authenticate_will_raise_runtime_error_when_response_status_code_is_not_2xx(httpserver: HTTPServer):
    
    og_wallet = OgWallet(httpserver.url_for('/'), client_id, client_secret)
    token = "invalid_token"
    query_string = f"clientId={client_id}"
    payload = {
        "ssoToken": token,
        "clientId": client_id
    }

    codes = [400, 401, 403, 404, 500]
    for code in codes:
        httpserver.expect_oneshot_request(uri="/sso/authenticate", query_string=query_string, headers=headers, method="POST", json=payload) \
            .respond_with_json({}, status=code)
        
        with pytest.raises(RuntimeError) as e:
            og_wallet.authenticate(token)




