import sqlite3
from flask import Flask, abort, jsonify
from flask_restful import Resource, Api, reqparse
from itsdangerous import BadSignature, SignatureExpired, TimedJSONWebSignatureSerializer as Serializer
from passlib.apps import custom_app_context as pwd_context

app = Flask("Test")
api = Api(app)
app.config['SECRET_KEY'] = 'asonetubaoeu'
db_name = 'testdb.sqlite'
'''
create table users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, mail TEXT);

'''


def generate_token(uid, expiration=6000):
    s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
    pickledict = {'id': int(uid)}
    return s.dumps(pickledict)


def verify_auth_token(token):
    s = Serializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except SignatureExpired:
        return None
    except BadSignature:
        return None
    retus = get_user_by_id(data['id'])
    retus['id'] = data['id']
    return retus

def get_user_by_id(uid):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    query = 'select username, password, mail from users where id=?'
    cursor.execute(query, [uid])
    retval = cursor.fetchone()
    if retval:
        return {'username': retval[0], 'passwdhash': retval[1], 'mail': retval[2]}
    return {}

def get_user_by_name(username):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    query = 'select id, password, mail from users where username=?'
    cursor.execute(query, [username])
    retval = cursor.fetchone()
    if retval:
        return {'id': retval[0], 'passwdhash': retval[1], 'mail': retval[2]}
    return {}

def write_user_to_db(username, password_hash, mail):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    query = 'INSERT INTO users(username, password, mail) VALUES(?,?,?)'
    conn.execute(query, [username, password_hash, mail])
    conn.commit()

def auth_user(username, password_hash):
    pass




class User(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('username', type=str, required=True, help='No Username Provided')
        self.reqparse.add_argument('mail', type=str, required=False, help='No Mail Provided')
        self.reqparse.add_argument('password', type=str, required=True, help='No Password Provided')
        #self.reqparse.add_argument('token', type=str, required=False, help='token')
        super(User, self).__init__()

    # used for debugging
    def get(self, id):
        #user = get_user_by_id(id)
        #if len(user) == 0:
        #    abort(404)
        #return jsonify({'user': {'username' : user[0], 'password' : user[1], 'mail' : user[2]}})
        pass

    def put(self, id):
        pass

    def post(self):
        args = self.reqparse.parse_args()
        user, passwd, mail = args['username'],args['password'],args['mail']
        passwd = pwd_context.encrypt(passwd)
        write_user_to_db(user, passwd, mail)
        return jsonify({'args': args})


    def delete(self, id):
        pass

class Journal(Resource):

    def post(self, name, document):
        pass #post to IPFS or sql

class Wallet(Resource):

    def get(self, token):
        pass #which details?

class Authenticate(Resource):

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('token', type=str, required=False, help='No Token Provided')
        self.reqparse.add_argument('username', type=str, required=False, help='No Username Provided')
        self.reqparse.add_argument('mail', type=str, required=False, help='No Mail Provided')
        self.reqparse.add_argument('password', type=str, required=False, help='No Password Provided')

    def post(self):
        args = self.reqparse.parse_args()
        if 'token' in args and args['token']:
            token = args['token']
            s = verify_auth_token(token)
            if s:
                new_token = generate_token(s['id']).decode('ascii')
                return jsonify({'token': new_token})
            else:
                print('invalid token')
        if 'username' in args and 'password' in args:
            userdata = get_user_by_name(args['username'])
            if not userdata:
                return None
            #user exists, but we didn't check PW yet!
            token = generate_token(userdata['id']).decode('ascii')
            return jsonify({'token': token})
        return None

class WhoAmI(Resource):

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('token', type=str, required=True, help='No Token Provided')

    def post(self, token):
        args = self.reqparse.parse_args()
        token = args['token']
        s = verify_auth_token(token)
        if not s:
            return None
        return get_user_by_id(s['id'])



api.add_resource(User, '/user/', endpoint='user')
api.add_resource(Authenticate, '/authenticate/', endpoint='authenticate')
api.add_resource(WhoAmI, '/whoami/', endpoint='whoami')
api.add_resource(Wallet, '/wallet/', endpoint='wallet')
api.add_resource(Journal, '/journal/', endpoint='journal')


if __name__ == '__main__':
    app.run(debug=True)
