"""
    Aodhan O'Brien - 22/07/23
    MySuccess: Back-end
    Description: An Application built for routine and habit tracking.
"""

from flask import Flask, request, jsonify, make_response
from pymongo import MongoClient
from bson import ObjectId, json_util
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import jwt
import bcrypt
import datetime
from functools import wraps
from flask_cors import CORS
import json
import string
from mongoengine import Document, StringField
import secrets

# secret_key = secrets.token_hex(32)
app = Flask(__name__)
CORS(app, origins="http://localhost:4200")
app.config["SECRET_KEY"] = "mysecret"

# Mongo Database Connection-String
client = MongoClient(
    "mongodb://127.0.0.1:27017/27017?directConnection=true&serverSelectionTimeoutMS=2000"
)

# Database
db = client.habitDB

# Collections
habits = db.habits
users = db.users
blacklist = db.blacklist


# Bson in PyMongo distribution provides json_util - you can use that one instead to handle BSON types
def parse_json(data):
    return json.loads(json_util.dumps(data))


"""
    Aodhan O'Brien - 22/07/23
    create/authentication/login
"""


def jwt_required(func):
    @wraps(func)
    def jwt_required_wrapper(*args, **kwargs):
        # token = request.args.get('token')
        token = None
        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
        if not token:
            return parse_json({"message": "Token is missing"}), 401
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"])
        except:
            return parse_json({"message": "Token is invalid"}), 401
        bl_token = blacklist.find_one({"token": token})
        if bl_token is not None:
            return make_response(
                parse_json({"message": "Token has been cancelled"}), 401
            )
        return func(*args, **kwargs)

    return jwt_required_wrapper


# def admin_required(func):
#     @wraps(func)
#     def admin_required_wrapper(*args, **kwargs):
#         token = request.headers["x-access-token"]
#         data = jwt.decode(token, app.config["SECRET_KEY"])
#         if data["admin"]:
#             return func(*args, **kwargs)
#         else:
#             return make_response(jsonify({"message": "Admin access required"}), 401)

#     return admin_required_wrapper


# create user account
@app.route("/api/v1.0/users/registration", methods=["POST"])
# @jwt_required
def add_user():
    if "username" in request.form and "password" in request.form:
        new_user = {
            "password": Bcrypt().generate_password_hash(request.form["password"]),
            "username": request.form["username"],
        }
        new_user_id = users.insert_one(new_user)
        new_user_link = (
            "http://localhost:5000/api/v1.0/users/registration"
            + "/"
            + str(new_user_id.inserted_id)
        )
        return make_response(parse_json({"url": new_user_link}), 200)


# get user
@app.route("/api/v1.0/users/<_id>", methods=["GET"])
# @jwt_required
def show_one_user(_id):
    user = users.find_one({"_id": ObjectId(_id)})
    if user is not None:
        user["_id"] = str(user["_id"])
        return make_response(parse_json(user), 200)
    else:
        return make_response(parse_json({"error": "Invalid user ID"}), 404)


#
@app.route("/api/v1.0/login", methods=["GET"])
def login():
    auth = request.authorization
    if auth:
        user = users.find_one({"username": auth.username})
        if user is not None:
            if bcrypt.checkpw(bytes(auth.password, "UTF-8"), user["password"]):
                token = jwt.encode(
                    {
                        "user": auth.username,
                        "admin": user["admin"],
                        "exp": datetime.datetime.utcnow()
                        + datetime.timedelta(minutes=30),
                    },
                    app.config["SECRET_KEY"],
                )
                return make_response(parse_json({"token": token.decode("UTF-8")}), 200)
            else:
                return make_response(parse_json({"message": "Bad password"}), 401)
        else:
            return make_response(parse_json({"message": "Bad username"}), 401)
    return make_response(parse_json({"message": "Authentication required"}), 401)


"""
    Aodhan O'Brien - 22/07/23
    CRUD: habtis/habit
"""


# Show all habits
@app.route("/api/v1.0/habits", methods=["GET"])
def show_all_habits():
    page_num, page_size = 1, 10
    if request.args.get("pn"):
        page_num = int(request.args.get("pn"))
    if request.args.get("ps"):
        page_size = int(request.args.get("ps"))
    page_start = page_size * (page_num - 1)

    data_to_return = []
    for habit in habits.find().skip(page_start).limit(page_size):
        habit["_id"] = str(habit["_id"])
        data_to_return.append(habit)
    return make_response(parse_json(data_to_return), 200)


# Show one habit
@app.route("/api/v1.0/habits/<string:id>", methods=["GET"])
def show_one_habit(id):
    if len(id) != 24 or not all(c in string.hexdigits for c in id):
        return make_response(parse_json({"Error": "Invalid Habit ID"}), 404)
    habit = habits.find_one({"_id": ObjectId(id)})
    if habit is not None:
        habit["_id"] = str(habit["_id"])
        return make_response(parse_json([habit]), 200)
    else:
        return make_response(
            parse_json({"Error": "Invalid Habit ID or no longer exists"}), 404
        )


# Add a habit
@app.route("/api/v1.0/habits", methods=["POST"])
def add_habit():
    if (
        "title" in request.form
        and "habit" in request.form
        and "priority" in request.form
    ):
        new_habit = {
            "title": request.form["title"],
            "habit": request.form["habit"],
            "priority": request.form["priority"],
            "notes": [request.form],
        }
        new_habit_id = habits.insert_one(new_habit)
        new_habit_link = "http://localhost:5000/api/v1.0/habits/", str(
            new_habit_id.inserted_id
        )
        return make_response(parse_json({"url": new_habit_link}), 201)
    else:
        return make_response(parse_json({"Incorrect Parameters Enters"}))


# edit one habit
@app.route("/api/v1.0/habits/<string:id>", methods=["PUT"])
def edit_event(id):
    if "title" in request.form and "habit" in request.form:
        result = habits.update_one(
            {"_id": ObjectId(id)},
            {"$set": {"habit": request.form["habit"], "title": request.form["title"]}},
        )
        if result.matched_count == 1:
            edited_habit_link = "http://localhost:5000/api/v1.0/habits/" + id
            return make_response(parse_json({"url": edited_habit_link}), 200)
        else:
            return make_response(
                parse_json({"Error": "invalide habit id or no longer exists"}), 404
            )
    else:
        return make_response(parse_json({"Error": "Missing from data"}), 404)


# remove one habit
@app.route("/api/v1.0/habits/<string:id>", methods=["DELETE"])
def delete_habit(id):
    result = habits.delete_one({"_id": ObjectId(id)})
    if result.deleted_count == 1:
        return make_response(parse_json({}), 204)
    else:
        make_response(parse_json({"Error": "Invalid Habit ID"}), 404)


"""
    Aodhan O'Brien - 22/07/23
    CRUD: notes/note
"""


# add new note
@app.route("/api/v1.0/habits/<string:id>/notes", methods=["POST"])
def add_new_note(id):
    new_note = {
        "_id": ObjectId(),
        "notes": request.form["notes"],
        "priority": request.form["priority"],
    }
    habits.update_one({"_id": ObjectId(id)}, {"$push": {"notes": new_note}})
    new_note_link = (
        "http://localhost:5000/api/v1.0/habits/" + id + "/notes/" + str(new_note["_id"])
    )
    return make_response(parse_json({"url": new_note_link}), 201)


# fetch all notes
@app.route("/api/v1.0/habits/<string:id>/notes", methods=["GET"])
def fetch_all_notes(id):
    data_to_return = []
    habit = habits.find_one({"_id": ObjectId(id)}, {"notes": 1, "_id": 0})
    for note in habit["notes"]:
        note["_id"] = str(note["_id"])
        data_to_return.append(note)
    return make_response(parse_json(data_to_return), 200)


# fetch one note
@app.route("/api/v1.0/habits/<string:id>/notes/<string:note_id>", methods=["GET"])
def fetch_one_note(id, note_id):
    habit = habits.find_one({"note._id": ObjectId(note_id)}, {"_id": 0, "notes.$": 1})
    if habit is None:
        return make_response(jsonify({"Error": "Invalid Habit or Note ID"}), 404)
    else:
        habit["notes"][0]["_id"] = str(habit["notes"][0]["_id"])
        return make_response(parse_json(habit["notes"][0]), 200)


# edit one note
@app.route("/api/v1.0/habits/<string:id>/notes/<string:note_id>", methods=["UPDATE"])
def edit_note(id, note_id):
    edited_note = {
        "notes.$.notes": request.form["notes"],
        "notes.$.priority": request.form["priority"],
    }
    habits.update_one({"notes._id": ObjectId(note_id)}, {"$set": edited_note})
    edit_note_url = "http://localhost:5000/habits/" + id + "/notes/" + note_id
    return make_response(parse_json({"url": edit_note_url}), 200)


# remove note
@app.route("/api/v1.0/habits/<string:id>/notes/<string:note_id>", methods=["DELETE"])
def delete_note(id, note_id):
    habits.update_one(
        {"_id": ObjectId(id)}, {"$pull": {"notes": {"note_id": ObjectId(note_id)}}}
    )
    return make_response(parse_json({}), 204)


if __name__ == "__main__":
    app.run(debug=True)
