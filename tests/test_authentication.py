import json


def login_with_user_admin(client):
    """Login with admin user
    Return:
        access_token: string
    """
    # get access token
    response = client.post(
        '/api/v1/auth/login',
        json={"username": "Admin", "password": "1234567"}
    )
    json_response = json.loads(response.data.decode())
    data = json_response['data']
    access_token = data['access_token']
    return access_token


def test_login_with_correct_username_password(client):
    """
    GIVEN correct username, password
    WHEN login with correct username, password
    THEN response has access_token
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"username": "Admin", "password": "1234567"}
    )
    json_response = json.loads(response.data.decode())
    data = json_response['data']
    assert 200 == json_response['code']  # check code is 200
    assert type(data['access_token']) is str  # check access token is string
    assert data['username'] == 'Admin'  # Check group is Admin


def test_login_with_username_contain_space(client):
    """
    GIVEN correct username, password
    WHEN login with correct username contains space chars
    THEN response has access_token
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"username": "  Admin   ", "password": "L9soVDs7VV1ylGnbY5ER"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert True is json_response['status']  # check status is True
    assert type(json_response['data']['access_token']) is str  # check access token is string
    assert json_response['data']['username'] == 'Admin'  # Check group is Admin


def test_login_with_password_contain_space(client):
    """
    GIVEN correct username, password
    WHEN login with correct password contains space chars
    THEN response has access_token
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"username": "Admin", "password": "   L9soVDs7VV1ylGnbY5ER   "}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert True is json_response['status']  # check status is True
    assert type(json_response['data']['access_token']) is str  # check access token is string
    assert json_response['data']['username'] == 'Admin'  # Check group is Admin


def test_login_with_username_greater_than_50_chars(client):
    """
    GIVEN correct username, password
    WHEN login with username greater than 50 chars
    THEN error message in response
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"username": "Adminnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn", "password": "1234567"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Please check your requests body'  # Check response message
    assert json_response['data']['username'] == ["Length must be between 1 and 50."]  # Check response data


def test_login_with_password_greater_than_32_chars(client):
    """
    GIVEN correct username, password
    WHEN login with password greater than 50 chars
    THEN error message in response
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"username": "Admin", "password": "L9soVDs7VV1ylGnbY5Ek5j5i4j0df3R9459482JI049j909dj3JI93"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Please check your requests body'  # Check response message
    assert json_response['data']['password'] == ["Length must be between 8 and 32."]  # Check response data


def test_login_with_username_only_contains_space(client):
    """
    GIVEN correct username, password
    WHEN login with username only contains space chars
    THEN error message in response
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"username": "            ", "password": "L9soVDs7VV1ylGnbY5ER"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Please check your requests body'  # Check response message
    assert json_response['data']['username'] == ["Length must be between 1 and 50."]  # Check response data


def test_login_with_password_only_contains_space(client):
    """
    GIVEN correct username, password
    WHEN login with password only contains space chars
    THEN error message in response
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"username": "Admin", "password": "            "}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Please check your requests body'  # Check response message
    assert json_response['data']['password'] == ["Length must be between 8 and 32."]  # Check response data


def test_login_with_incorrect_username(client):
    """
    GIVEN correct username, password
    WHEN login with incorrect username
    THEN error message in response
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"username": "Admin3if", "password": "L9soVDs7VV1ylGnbY5ER"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Invalid username or password.\nPlease try again'  # Check response message


def test_login_with_incorrect_password(client):
    """
    GIVEN correct username, password
    WHEN login with incorrect password
    THEN error message in response
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"username": "Admin", "password": "De9jjd6i03jD"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Invalid username or password.\nPlease try again'  # Check response message


def test_logout(client):
    """
    GIVEN login with admin user
    WHEN logout
    THEN return success status
    """

    access_token = login_with_user_admin(client)

    response = client.delete(
        '/api/v1/auth/logout',
        headers={'Authorization': 'Bearer {}'.format(access_token)}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert True is json_response['status']  # check status is True


def test_refresh_access_token(client):
    """
    GIVEN login with admin user
    WHEN refresh access_token with refresh_token
    THEN return new access_token in response
    """

    response = client.post(
        '/api/v1/auth/login',
        json={"username": "Admin", "password": "L9soVDs7VV1ylGnbY5ER"}
    )
    json_response = json.loads(response.data.decode())
    data = json_response['data']
    refresh_token = data['refresh_token']
    assert 200 == json_response['code']  # check code is 200
    assert True is json_response['status']  # check status is True

    # get a new access token
    response = client.post(
        '/api/v1/auth/refresh'.format(),
        headers={'Authorization': 'Bearer {}'.format(refresh_token)}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert True is json_response['status']  # check status is True
    assert b'access_token' in response.data
