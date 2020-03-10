import flask
from flask import jsonify, request

from data import db_session
from data.users import User
db_session.global_init("db/blogs.sqlite")
blueprint = flask.Blueprint('user_api', __name__,
                            template_folder='templates')


@blueprint.route('/api/users', methods=['GET'])
def get_users():
    session = db_session.create_session()
    users = session.query(User).all()
    return jsonify(
        {
            'users':[
                item.to_dict(only=(['id'])) for item in users
            ]
        }
    )
@blueprint.route('/api/new_user', methods=['POST'])
def new_user():
    try:
        if not request.json:
            return jsonify({'error': 'Empty request'})
        elif not all(key in request.json for key in ['password','name','email','about']):
            return jsonify({'error': 'Bad request'})
        session = db_session.create_session()
        user = User(
            name=request.json['name'],
            email=request.json['email'],
            about=request.json['about'],
            )
        user.set_password(request.json['password'])

        session.add(user)
        session.commit()
        return jsonify({'success': 'OK'})
    except Exception as e:
        print(e)

@blueprint.route('/api/user/<int:user_id>')
def get_user(user_id):
    session = db_session.create_session()
    user = session.query(User).filter(User.id==user_id).all()
    return jsonify(
        {
            'user':[
                item.to_dict(only=('id','name')) for item in user
            ]
        }
    )

