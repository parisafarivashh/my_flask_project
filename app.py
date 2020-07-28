from flask import  Flask, request ,jsonify ,make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime 

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecreatkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///example.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique =True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
 

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String())
    complate = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x_access_token' in request.headers:
            token = request.headers['x_access_token']
        
        if not token:
            return jsonify({'message':'Token is Missing'})
        
        try:
            data = jwt.decode(token ,app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'Token':'Token is invalid'}),401
            
        return f(current_user, *args, **kwargs)
    return decorated        



@app.route('/user', methods=['GET'])
@token_required
def get_all_user(current_user):


    if not current_user.admin:
        return jsonify({'message':'can not perform that function'})


    users = User.query.all()

    output =[]
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({"users":output})    


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message':'can not perform that function'})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message":'Not User Found'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin 
      
    return jsonify({'user':user_data})


@app.route('/user', methods =['POST'])
@token_required
def create_user(current_user):

    if not create_user.admin:
        return jsonify({'message':'can not performe that function'})

    data = request.get_json()
  
    hashed_password = generate_password_hash(data['password'], method = 'sha256')  
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password = hashed_password ,admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message":'New User Created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promot_user(create_user, public_id):

    
    if not create_user.admin:
        return jsonify({'message':'can not performe that function'})


    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'Not User Found'})

    user.admin = True
    db.session.commit()

    return jsonify({"message":'the user has been promoted'})


@app.route('/userr/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user , public_id):

    if not current_user.admin:
        return jsonify({'message':'can not perform that function'})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'Not User Found'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({"message":'the user has been deleted'}) 
    


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401)
    
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify', 401)
        current_
    
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])


        return jsonify({'token':token.decode('UTF-8')})

    return make_response('Could not verify', 401)


@app.route('/todo' , methods=['GET'])
@token_required
def get_all_todos(current_user):
    
    todos = Todo.query.filter_by(user_id = current_user.id).all()

    out_put = []

    for todo in todos :
        todo_data = {}
        todo_data['id'] = todo.id 
        todo_data['text'] = todo.text
        todo_data['complate'] = todo.complate
        out_put.append(todo_data)

    return jsonify({'todos':out_put})


@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user , todo_id):

    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message':'no todo find'})

    todo_data = {}
    todo_data['id'] = todo.id 
    todo_data['text'] = todo.text
    todo_data['complate'] = todo.complate
    return jsonify(todo_data)


@app.route('/todo' ,methods=['POST'])
@token_required
def create_todo(current_user):

    data = request.get_json()
    new_todo = Todo(text=data['text'], complate=False , user_id = current_user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message':'Todo Created!'})


@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complate_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message':'no todo find'})

    todo.complate =True
    db.session.commit()

    return jsonify({'message':'todo item has been complated'})



@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message':'no todo find'})

    db.session.delete(todo)
    db.session.commit()

    return jsonify({'message':'todo item deleted'})







if __name__ == '__main__':
    app.run(debug=True)

