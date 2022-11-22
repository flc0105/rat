import datetime

import jwt

from server.config import SECRET_KEY


def generate_token():
    return jwt.encode({
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
        'iat': datetime.datetime.utcnow(),
    }, SECRET_KEY, algorithm='HS256')


def validate_token(token):
    try:
        jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return True, 'Success'
    except jwt.ExpiredSignatureError:
        return False, 'Token expired'
    except jwt.InvalidTokenError:
        return False, 'Invalid token'
