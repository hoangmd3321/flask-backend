import json



def test_login_with_correct_email_password(client):
    """
    GIVEN correct email, password
    WHEN login with correct email, password
    THEN response has access_token
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"email": "admin@gmail.com", "password": "12345678"}
    )
    json_response = json.loads(response.data.decode())
    print(json_response)
    data = json_response['data']
    assert 200 == json_response['code']  # check code is 200
    assert type(data['access_token']) is str  # check access token is string
    assert type(data['refresh_token']) is str
    assert data['email'] == 'admin@gmail.com'  # Check email is admin@gmail.com
    assert json_response['message']  == "Logged in successfully!"

def test_login_with_correct_phone_otp(client):
    """
    GIVEN correct phone, otp
    WHEN login with correct phone, otp
    THEN response has access_token
    """
    response = client.post(
        '/api/v1/auth/send_otp',
        json={"phone": "0123455678"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']
    assert True == json_response['status']


    response = client.post(
        '/api/v1/auth/login',
        json={"phone": "0123455678", "otp": "123456"}
    )

    json_response = json.loads(response.data.decode())
    print(json_response)
    data = json_response['data']
    assert 200 == json_response['code']  # check code is 200
    assert type(data['access_token']) is str  # check access token is string
    assert type(data['refresh_token']) is str
    assert data['email'] == 'admin@gmail.com'  # Check email is admin@gmail.com
    assert data['phone'] == '0123455678'
    assert json_response['message']  == "Logged in successfully!"    


def test_login_with_email_contain_space(client):
    """
    GIVEN correct email, password
    WHEN login with correct email contains space chars
    THEN response has access_token
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"email": "  admin@gmail.com   ", "password": "12345678"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert True is json_response['status']  # check status is True
    assert type(json_response['data']['access_token']) is str  # check access token is string
    assert json_response['data']['email'] == 'admin@gmail.com'  # Check email is amdin@gmail.com


def test_login_with_password_contain_space(client):
    """
    GIVEN correct email, password
    WHEN login with correct password contains space chars
    THEN response has access_token
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"email": "admin@gmail.com", "password": "   12345678   "}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert True is json_response['status']  # check status is True
    assert type(json_response['data']['access_token']) is str  # check access token is string
    assert json_response['data']['email'] == 'admin@gmail.com'  # Check email is amdin@gmail.com
    

def test_login_with_email_greater_than_50_chars(client):
    """
    GIVEN email, password
    WHEN login with email greater than 50 chars
    THEN error message in response
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"email": "Adminnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn", "password": "12345678"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Please check your requests body'  # Check response message
    assert json_response['data']['email'] == ["Length must be between 1 and 50."]  # Check response data


def test_login_with_no_email_and_phone(client):
    """
    GIVEN correct email, password
    login with no email and phone
    THEN error message in response
    """
    response = client.post('api/v1/auth/login', json = {'password': "12345678"})
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']
    assert False is json_response['status']
    assert json_response['message'] == 'Invalid email/phone or password.\nPlease try again'
    print(json_response)


def test_login_with_password_greater_than_32_chars(client):
    """
    GIVEN email, password
    WHEN login with password greater than 50 chars
    THEN error message in response
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"email": "admin@gmail.com", "password": "L9soVDs7VV1ylGnbY5Ek5j5i4j0df3R9459482JI049j909dj3JI93"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Please check your requests body'  # Check response message
    assert json_response['data']['password'] == ["Length must be between 8 and 32."]  # Check response data

def test_login_with_email_only_contains_space(client):
    """
    GIVEN email, password
    WHEN login with email only contains space chars
    THEN error message in response
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"email": "            ", "password": "L9soVDs7VV1ylGnbY5ER"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Please check your requests body'  # Check response message
    assert json_response['data']['email'] == ["Length must be between 1 and 50."]  # Check response data


def test_login_with_password_only_contains_space(client):
    """
    GIVEN correct email, password
    WHEN login with password only contains space chars
    THEN error message in response
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"email": "admin@gmail.com", "password": "            "}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Please check your requests body'  # Check response message
    assert json_response['data']['password'] == ["Length must be between 8 and 32."]  # Check response data


def test_login_with_otp_greater_than_6(client):
    """
    GIVEN correct phone, otp
    WHEN login with otp length greater than 6
    THEN response has access_token
    """
    response = client.post(
        '/api/v1/auth/send_otp',
        json={"phone": "0123455678"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']
    assert True == json_response['status']


    response = client.post(
        '/api/v1/auth/login',
        json={"phone": "0123455678", "otp": "x1243523"}
    )

    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']
    assert json_response['message'] == 'Please check your requests body'
    assert json_response['data']['otp'] == ['Length must be between 1 and 6.']




def test_login_with_incorrect_email(client):
    """
    GIVEN correct email, password
    WHEN login with incorrect email
    THEN error message in response
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"email": "admin123@gmail.com", "password": "12345678"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Invalid email/phone or password.\nPlease try again'  # Check response message


def test_login_with_incorrect_password(client):
    """
    GIVEN correct email, password
    WHEN login with incorrect password
    THEN error message in response
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"email": "admin@gmail.com", "password": "De9jjd6i03jD"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Invalid email/phone or password.\nPlease try again'  # Check response message

def test_login_with_incorrect_otp(client):
    """
    GIVEN correct phone, otp
    WHEN login with incorrect otp
    THEN response has access_token
    """
    response = client.post(
        '/api/v1/auth/send_otp',
        json={"phone": "0123455678"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']
    assert True == json_response['status']


    response = client.post(
        '/api/v1/auth/login',
        json={"phone": "0123455678", "otp": "6346"}
    )

    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']
    assert json_response['message'] == 'Invalid OTP.\nPlease try again'
    print(json_response)


def test_send_otp_with_wrong_request_data_type(client):
    response = client.post(
        '/api/v1/auth/send_otp',
        data={"phone": "0123455678"}
    )
    json_response = json.loads(response.data.decode())
    assert 442 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Please check your json requests'  # Check response message
    print(json_response)

def test_send_otp_with_no_request_data(client):
    response = client.post(
        '/api/v1/auth/send_otp'
    )
    
    json_response = json.loads(response.data.decode())

    assert 442 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Please check your json requests'  # Check response message
    print(json_response)

def test_send_otp_with_correct_phone_number(client):
    response = client.post(
        '/api/v1/auth/send_otp',
        json={"phone": "0123455678"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert True is json_response['status']  # check status is false
    assert json_response['message'] == 'An otp has successfully sent to your phone!'  # Check response message
    print(json_response)


def test_send_otp_with_phone_number_greater_than_50(client):
    response = client.post(
        '/api/v1/auth/send_otp',
        json={"phone": "0123455678728394092349023409238402938092348932482394781923"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Please check your requests body'  # Check response message

def test_send_otp_with_phone_number_contains_only_space(client):
    response = client.post(
        '/api/v1/auth/send_otp',
        json={"phone": "                        "}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Please check your requests body'  # Check response message
    assert json_response['data']['phone'] == ['Length must be between 1 and 50.']
    

def test_send_otp_with_correct_phone_number_contains_space(client):
    response = client.post(
        '/api/v1/auth/send_otp',
        json={"phone": "           0123455678        "}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert True is json_response['status']  # check status is false
    assert json_response['message'] == 'An otp has successfully sent to your phone!'  # Check response message
    print(json_response)


def test_send_otp_with_incorrect_phone_number(client):
    response = client.post(
        '/api/v1/auth/send_otp',
        json={"phone": "092147892374"}
    )
    json_response = json.loads(response.data.decode())
    assert 200 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is false
    assert json_response['message'] == 'Account not existed. Please try again with other phone number'  # Check response message

def test_logout(client):
    """
    GIVEN login with admin user
    WHEN logout
    THEN return success status
    """
    response = client.post(
        '/api/v1/auth/login',
        json={"email": "admin@gmail.com", "password": "12345678"}
    )
    json_response = json.loads(response.data.decode())
    # print(json_response)
    data = json_response['data']
    assert 200 == json_response['code']  
    assert type(data['access_token']) is str  
    assert type(data['refresh_token']) is str
    assert data['email'] == 'admin@gmail.com'  
    assert json_response['message']  == "Logged in successfully!"
    
    access_token = data['access_token']

    response = client.delete(
        '/api/v1/auth/logout',
        headers={'Authorization': 'Bearer {}'.format(access_token)}
    )
    json_response = json.loads(response.data.decode())
    print(json_response)
    assert 200 == json_response['code']  # check code is 200
    assert True is json_response['status']  # check status is True
    assert json_response['message'] == 'Logout successfully!'

def test_logout_with_no_token(client):
    response = client.delete(
        '/api/v1/auth/logout',
    )
    json_response = json.loads(response.data.decode())
    print(json_response)
    assert 401 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is True
    assert json_response['message'] == 'Missing Authorization Header'

def test_logout_with_invalid_token(client):
    access_token = "fjwlaekfkle.wejrlkefkawklef"

    response = client.delete(
        '/api/v1/auth/logout',
        headers={'Authorization': 'Bearer {}'.format(access_token)}
    )
    json_response = json.loads(response.data.decode())
    print(json_response)
    assert 442 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is True
    

def test_refresh_access_token_success(client):

    response = client.post(
        '/api/v1/auth/login',
        json={"email": "admin@gmail.com", "password": "12345678"}
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
    print(json_response)
    assert 200 == json_response['code']  # check code is 200
    assert True is json_response['status']  # check status is True
    assert b'access_token' in response.data

def test_refresh_access_token_with_no_authenticate_token_fail(client):
    response = client.post(
        '/api/v1/auth/refresh'.format()
    )
    json_response = json.loads(response.data.decode())
    assert 401 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is True
    assert json_response['message'] == 'Missing Authorization Header'
    print(json_response)

def test_refresh_access_token_with_invalid_token(client):
    response = client.post(
        '/api/v1/auth/login',
        json={"email": "admin@gmail.com", "password": "12345678"}
    )
    json_response = json.loads(response.data.decode())
    data = json_response['data']
    access_token = data['access_token']
    assert 200 == json_response['code']  # check code is 200
    assert True is json_response['status']  # check status is True

    # get a new access token
    response = client.post(
        '/api/v1/auth/refresh'.format(),
        headers={'Authorization': 'Bearer {}'.format(access_token)}
    )
    json_response = json.loads(response.data.decode())
    print(json_response)
    assert 442 == json_response['code']  # check code is 200
    assert False is json_response['status']  # check status is True