Dependencies:

sqlite3, flask, flask_restful, itsdangerous, passlib
You should be able to install them using pip install ...
sqlite3 may also need to get installed separately

Current sqlite contains only one table:
create table users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, mail TEXT);

I uploaded a testdb.sqlite (which I used for my tests), should be good to go

Passwords are hashed, but not yet correctly validated
--> where do you want to handle this?

Running the local flask server:

export FLASK_APP=__init__.py
export FLASK_DEBUG=TRUE
flask

it auto reloads on changes, as expected.
Currently the following endpoints are implemented:

/user /authenticate /whoami
