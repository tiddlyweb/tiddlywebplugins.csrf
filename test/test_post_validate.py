"""
Tests to ensure that POST requests all come from the same domain.

i.e. tests that ensure we are not vulnerable to CSRF
"""

from wsgi_intercept import httplib2_intercept
import wsgi_intercept
import httplib2
import Cookie
import os
import shutil

from datetime import datetime, timedelta


from tiddlywebplugins.utils import get_store
from tiddlyweb.config import config
from tiddlyweb.web.serve import load_app
from tiddlyweb.model.tiddler import Tiddler
from tiddlyweb.model.bag import Bag
from tiddlyweb.model.user import User
from tiddlyweb.util import sha
from tiddlywebplugins.csrf import CSRFProtector, InvalidNonceError


BAD_MATCH_MESSAGE = 'CSRF token does not match'


def get_auth(username, password):
    http = httplib2.Http()
    response, _ = http.request(
            'http://0.0.0.0:8080/challenge/cookie_form',
            body='user=%s&password=%s' % (username, password),
            method='POST',
            headers={'Content-Type': 'application/x-www-form-urlencoded'})
    assert response.previous['status'] == '303'

    user_cookie = response.previous['set-cookie']
    cookie = Cookie.SimpleCookie()
    cookie.load(user_cookie)
    return cookie['tiddlyweb_user'].value


def setup_module(module):
    if os.path.exists('store'):
        shutil.rmtree('store')

    if CSRFProtector not in config['server_request_filters']:
        config['server_request_filters'].append(CSRFProtector)
                
    app = load_app()
    def app_fn():
        return app

    httplib2_intercept.install()
    wsgi_intercept.add_wsgi_intercept('0.0.0.0', 8080, app_fn)
    wsgi_intercept.add_wsgi_intercept('foo.0.0.0.0', 8080, app_fn)

    module.http = httplib2.Http()


def test_validator_no_nonce():
    """
    test the validator directly
    ensure that it fails when the nonce is not present
    """
    try:
        csrf = CSRFProtector({})
        csrf.check_csrf({}, None)
        raise AssertionError('check_csrf succeeded when no csrf_token supplied')
    except InvalidNonceError, exc:
        assert exc.message == 'No csrf_token supplied'

def test_validator_nonce_success():
    """
    test the validator directly
    ensure that it succeeds when the nonce passed in is correct
    """
    username = 'foo'
    hostname = 'foo.0.0.0.0:8080'
    secret = '12345'
    timestamp = datetime.now().strftime('%Y%m%d%H')
    nonce = '%s:%s:%s' % (timestamp, username,
        sha('%s:%s:%s:%s' % (username, timestamp, hostname, secret)).
        hexdigest())
    environ = {
       'tiddlyweb.usersign': {'name': username},
       'tiddlyweb.config': {
           'secret': secret,
           'server_host': {
               'host': '0.0.0.0',
               'port': '8080'
           }
        },
        'HTTP_HOST': 'foo.0.0.0.0:8080'
    }

    csrf = CSRFProtector({})
    result = csrf.check_csrf(environ, nonce)

    assert result == True

def test_validator_nonce_fail():
    """
    test the validator directly
    ensure that it fails when the nonce doesn't match
    """
    nonce = 'dwaoiju277218ywdhdnakas72'
    username = 'foo'
    secret = '12345'
    environ = {
       'tiddlyweb.usersign': {'name': username},
       'tiddlyweb.config': {
           'secret': secret,
           'server_host': {
               'host': '0.0.0.0',
               'port': '8080'
           }
        },
        'HTTP_HOST': 'foo.0.0.0.0:8080'
    }

    try:
        csrf = CSRFProtector({})
        csrf.check_csrf(environ, nonce)
        raise AssertionError('check_csrf succeeded when nonce didn\'t match')
    except InvalidNonceError, exc:
        assert exc.message == BAD_MATCH_MESSAGE

def test_validator_nonce_hash_fail():
    """
    test the validator directly
    ensure that it fails when the hash section of the nonce is incorrect
    """
    username = 'foo'
    hostname = 'foo.0.0.0.0:8080'
    secret = '12345'
    timestamp = datetime.now().strftime('%Y%m%d%H')
    nonce = '%s:%s:dwaoiju277218ywdhdnakas72' % (timestamp, username)
    environ = {
       'tiddlyweb.usersign': {'name': username},
       'tiddlyweb.config': {
           'secret': secret,
           'server_host': {
               'host': '0.0.0.0',
               'port': '8080'
           }
        },
        'HTTP_HOST': hostname
    }

    try:
        csrf = CSRFProtector({})
        csrf.check_csrf(environ, nonce)
        raise AssertionError('check_csrf succeeded when nonce didn\'t match')
    except InvalidNonceError, exc:
        assert exc.message == BAD_MATCH_MESSAGE

def test_post_data_form_urlencoded():
    """
    test that a form POST requires a nonce
    test using application/x-www-form-urlencoded
    """
    store = get_store(config)
    hostname = 'foo.0.0.0.0:8080'
    user = User('foo')
    user.set_password('foobar')
    store.put(user)
    store.put(Bag('foo_public'))
    timestamp = datetime.now().strftime('%Y%m%d%H')
    secret = config['secret']
    nonce = '%s:%s:%s' % (timestamp, user.usersign,
        sha('%s:%s:%s:%s' % (user.usersign, timestamp, hostname, secret)).
        hexdigest())

    user_cookie = get_auth('foo', 'foobar')
    csrf_token = 'csrf_token="%s"' % nonce
    data = 'title=foobar&text=hello%20world'

    #test success
    response, content = http.request('http://foo.0.0.0.0:8080/bags/foo_public/tiddlers',
        method='POST',
        headers={
            'Content-type': 'application/x-www-form-urlencoded',
            'Cookie': 'tiddlyweb_user="%s"; %s' % (user_cookie, csrf_token)
        },
        body='%s&csrf_token=%s' % (data, nonce))
    assert response['status'] == '204', content

    #test failure
    response, content = http.request('http://0.0.0.0:8080/bags/foo_public/tiddlers',
        method='POST',
        headers={
            'Content-type': 'application/x-www-form-urlencoded',
            'Cookie': 'tiddlyweb_user="%s"' % user_cookie
        },
        body='%s' % data)
    assert response['status'] == '400', content


def test_post_data_multipart_form():
    """
    test that a form POST requires a nonce
    test using multipart/form-data
    """
    store = get_store(config)
    hostname = 'foo.0.0.0.0:8080'
    user = User('foo')
    user.set_password('foobar')
    store.put(user)
    timestamp = datetime.now().strftime('%Y%m%d%H')
    secret = config['secret']
    nonce = '%s:%s:%s' % (timestamp, user.usersign,
        sha('%s:%s:%s:%s' % (user.usersign, timestamp, hostname, secret)).
        hexdigest())

    user_cookie = get_auth('foo', 'foobar')
    csrf_token = 'csrf_token=%s' % nonce
    data = '''---------------------------168072824752491622650073
Content-Disposition: form-data; name="title"

foobar
---------------------------168072824752491622650073
Content-Disposition: form-data; name="text"

Hello World
---------------------------168072824752491622650073--'''

    #test success
    uri = 'http://foo.0.0.0.0:8080/bags/foo_public/tiddlers?%s' % csrf_token
    response, content = http.request(uri,
        method='POST',
        headers={
            'Content-Type': 'multipart/form-data; ' \
            'boundary=---------------------------168072824752491622650073',
            'Cookie': 'tiddlyweb_user="%s"' % user_cookie,
            'Content-Length': '390'
        },
        body=data)
    assert response['status'] == '204', content

    #test failure
    response, _ = http.request('http://foo.0.0.0.0:8080/bags/foo_public/tiddlers',
        method='POST',
        headers={
            'Content-Type': 'multipart/form-data; ' \
            'boundary=---------------------------168072824752491622650073',
            'Cookie': 'tiddlyweb_user="%s"' % user_cookie,
            'Content-Length': '267'
        },
        body=data)
    assert response['status'] == '400'

def test_nonce_not_left_over():
    """
    Test that the nonce is not left over in the tiddler after a POST
    i.e. check that it is removed before the request continues
    """
    store = get_store(config)
    hostname = 'foo.0.0.0.0:8080'
    user = User('foo')
    user.set_password('foobar')
    store.put(user)
    timestamp = datetime.now().strftime('%Y%m%d%H')
    secret = config['secret']
    nonce = '%s:%s:%s' % (timestamp, user.usersign,
        sha('%s:%s:%s:%s' % (user.usersign, timestamp, hostname, secret)).
        hexdigest())

    user_cookie = get_auth('foo', 'foobar')
    data = 'title=foobar&text=hello%20world&extra_field=baz'

    #test success
    response, _ = http.request('http://foo.0.0.0.0:8080/bags/foo_public/tiddlers',
        method='POST',
        headers={
            'Content-type': 'application/x-www-form-urlencoded',
            'Cookie': 'tiddlyweb_user="%s"' % user_cookie
        },
        body='%s&csrf_token=%s' % (data, nonce))
    assert response['status'] == '204'

    new_tiddler = Tiddler('foobar')
    new_tiddler.bag = 'foo_public'
    new_tiddler = store.get(new_tiddler)

    assert new_tiddler.title == 'foobar'
    assert new_tiddler.text == 'hello world'
    assert new_tiddler.fields.get('extra_field') == 'baz'
    assert new_tiddler.fields.get('nonce') == None


def test_cookie_set():
    """
    test that we get a cookie relating to the space we are in
    """
    store = get_store(config)
    hostname = 'foo.0.0.0.0:8080'
    user = User('foo')
    user.set_password('foobar')
    store.put(user)

    user_cookie = get_auth('foo', 'foobar')

    response, content = http.request('http://foo.0.0.0.0:8080/',
        method='GET',
        headers={
            'Cookie': 'tiddlyweb_user="%s"' % user_cookie
        })

    assert response['status'] == '200', content

    time = datetime.now().strftime('%Y%m%d%H')
    cookie = 'csrf_token=%s:%s:%s' % (time, user.usersign,
        sha('%s:%s:%s:%s' % (user.usersign,
        time, hostname, config['secret'])).hexdigest())
    assert response['set-cookie'] == cookie

def test_guest_no_cookie_set():
    """
    Test that we don't get a cookie if we are a guest
    """
    response, _ = http.request('http://0.0.0.0:8080/',
        method='GET')

    assert response['status'] == '200'
    cookie = response.get('set-cookie')
    if cookie:
        assert 'csrf_token' not in cookie

def test_no_cookie_sent():
    """
    Test no cookie is sent if one is already present
    """
    store = get_store(config)
    hostname = 'foo.0.0.0.0:8080'
    user = User('foo')
    user.set_password('foobar')
    store.put(user)

    user_cookie = get_auth('foo', 'foobar')
    time = datetime.now().strftime('%Y%m%d%H')
    token_cookie = 'csrf_token=%s:%s:%s' % (time, user.usersign,
        sha('%s:%s:%s:%s' % (user.usersign,
        time, hostname, config['secret'])).hexdigest())

    response, _ = http.request('http://foo.0.0.0.0:8080/status',
        method='GET',
        headers={
            'Cookie': 'tiddlyweb_user="%s"; %s' % (user_cookie, token_cookie)
        })

    cookie = response.get('set-cookie')
    if cookie:
        assert 'csrf_token' not in cookie

    # When making transition from logged in to GUEST, expire
    # csrf_token.
    response, _ = http.request('http://foo.0.0.0.0:8080/status',
        method='GET',
        headers={
            'User-Agent': 'MSIE',
            'Cookie': '%s' % token_cookie
        })

    cookie = response.get('set-cookie')
    assert 'csrf_token' in cookie
    assert 'Expires=' in cookie

def test_invalid_cookie():
    """
    Test that an invalid/old cookie causes a new cookie to be sent
    """
    store = get_store(config)
    hostname = 'foo.0.0.0.0:8080'
    user = User('foo')
    user.set_password('foobar')
    store.put(user)

    user_cookie = get_auth('foo', 'foobar')
    time = datetime.now() - timedelta(hours=3)
    time = time.strftime('%Y%m%d%H')
    cookie = 'csrf_token=%s:%s:%s' % (time, user.usersign,
        sha('%s:%s:%s:%s' % (user.usersign,
        time, hostname, config['secret'])).hexdigest())

    response, _ = http.request('http://foo.0.0.0.0:8080/status',
        method='GET',
        headers={
            'Cookie': 'tiddlyweb_user="%s"; %s' % (user_cookie, cookie)
        })

    assert 'csrf_token' in response['set-cookie']

    cookie = 'csrf_token=adiudh9389wefnf98'
    response, _ = http.request('http://foo.0.0.0.0:8080/status',
        method='GET',
        headers={
            'Cookie': 'tiddlyweb_user="%s"; %s' % (user_cookie, cookie)
        })

    assert 'csrf_token' in response['set-cookie']

    user2 = User('bar')
    user2.set_password('foobar')
    store.put(user2)
    user2_cookie = get_auth('bar', 'foobar')

    response, _ = http.request('http://foo.0.0.0.0:8080/status',
        method='GET',
        headers={
            'Cookie': 'tiddlyweb_user="%s"; %s' % (user2_cookie, cookie)
        })

    assert 'csrf_token' in response.get('set-cookie', '')
