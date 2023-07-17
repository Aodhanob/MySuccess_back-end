from flask import Flask, request, jsonify, make_response
from pymongo import MongoClient
from bson import ObjectId
import jwt
import bcrypt
import datetime
from functools import wraps
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config["SECRET_KEY"] = "mysecret"

# client = MongoClient("mongodb://127.0.0.1:27017")
client = MongoClient("mongodb://localhost:27017")
db = client.sportDB
users = db.users
blacklist = db.blacklist
sports = db.olympics


def jwt_required(func):
    @wraps(func)
    def jwt_required_wrapper(*args, **kwargs):
        # token = request.args.get('token')
        token = None
        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
        if not token:
            return jsonify({"message": "Token is missing"}), 401
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"])
        except:
            return jsonify({"message": "Token is invalid"}), 401
        bl_token = blacklist.find_one({"token": token})
        if bl_token is not None:
            return make_response(jsonify({"message": "Token has been cancelled"}), 401)
        return func(*args, **kwargs)

    return jwt_required_wrapper


def admin_required(func):
    @wraps(func)
    def admin_required_wrapper(*args, **kwargs):
        token = request.headers["x-access-token"]
        data = jwt.decode(token, app.config["SECRET_KEY"])
        if data["admin"]:
            return func(*args, **kwargs)
        else:
            return make_response(jsonify({"message": "Admin access required"}), 401)

    return admin_required_wrapper


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
                return make_response(jsonify({"token": token.decode("UTF-8")}), 200)
            else:
                return make_response(jsonify({"message": "Bad password"}), 401)
        else:
            return make_response(jsonify({"message": "Bad username"}), 401)
    return make_response(jsonify({"message": "Authentication required"}), 401)


@app.route("/api/v1.0/logout", methods=["GET"])
@jwt_required
def logout():
    token = None
    if "x-access-token" in request.headers:
        token = request.headers["x-access-token"]
    if not token:
        return make_response(jsonify({"message": "Token is missing"}), 401)
    else:
        blacklist.insert_one({"token": token})
        return make_response(jsonify({"message": "Logout successful"}), 200)


# //shows all games
@app.route("/api/v1.0/sports", methods=["GET"])
def show_all_games():
    page_num, page_size = 1, 6
    if request.args.get("pn"):
        page_num = int(request.args.get("pn"))
    if request.args.get("ps"):
        page_size = int(request.args.get("ps"))
    page_start = page_size * (page_num - 1)

    data_to_return = []
    for sport in sports.find().skip(page_start).limit(page_start):
        sport["_id"] = str(sport["_id"])
        data_to_return.append(sport)
    return make_response(jsonify(data_to_return), 200)


# //shows one game
@app.route("/api/v1.0/sports/<string:id>", methods=["GET"])
def show_one_game(id):
    sport = sports.find_one({"_id": ObjectId(id)})
    if sport is not None:
        sport["_id"] = str(sport["_id"])
        return make_response(jsonify(sport), 200)
    else:
        return make_response(jsonify({"error": "Invalid game id"}), 404)


# // adds new game
@app.route("/api/v1.0/sports", methods=["POST"])
def add_game():
    if "gender" in request.form and "name" in request.form and "url" in request.form:
        new_sport = {
            "games": [],
            "gender": request.form["gender"],
            "name": request.form["name"],
            "url": request.form["url"],
        }
        new_sport_id = sports.insert_one(new_sport)
        new_sport_link = "http://localhost:5000/api/v1.0/sports/", str(
            new_sport_id.inserted_id
        )
        return make_response(jsonify({"url": new_sport_link}), 201)


# edit one event
@app.route("/api/v1.0/sports/<string:id>", methods=["PUT"])
def edit_event(id):
    if "gender" in request.form and "name" in request.form and "url" in request.form:
        result = sports.update_one(
            {"_id": ObjectId(id)},
            {
                "$set": {
                    "gender": request.form["gender"],
                    "name": request.form["name"],
                    "url": request.form["url"],
                }
            },
        )
        if result.matched_count == 1:
            edited_sport_link = "http://localhost:5000/api/v1.0/sports/" + id
            return make_response(jsonify({"url": edited_sport_link}), 200)
        else:
            return make_response(jsonify({"error": "invalide sport id"}), 404)
    else:
        return make_response(jsonify({"error": "Missing from data"}), 404)


# // adds new event
@app.route("/api/v1.0/sports/<string:gid>/games", methods=["POST"])
def add_new_game(gid):
    new_game = {
        "location": request.form["location"],
        "results": [],
        "year": request.form["year"],
    }
    sports.update_one({"_id": ObjectId(gid)}, {"$push": {"games": new_game}})
    new_game_link = (
        "http://localhost:5000/api/v1.0/sports/"
        + gid
        + "/games/"
        + str(new_game["location"])
    )
    return make_response(jsonify({"url": new_game_link}), 201)


# // shows one event
@app.route("/api/v1.0/sports/<string:id>/games/<string:location>", methods=["GET"])
def fetch_one_event(id, location):
    # return(tkey)
    group = sports.find_one({"games.location": location}, {"games.$": 1})
    if group is None:
        return make_response(jsonify({"error": "Invalid sports ID or location"}), 404)

    return make_response(jsonify(group["games"][0]), 200)


# // remove one event
@app.route("/api/v1.0/sports/<string:id>/games/<string:location>", methods=["DELETE"])
def remove_one_event(id, location):
    group = sports.update_one(
        {"_id": ObjectId(id), "games.location": location},
        {"$pull": {"games": {"location": location}}},
    )
    return make_response(jsonify({}), 204)


# // shows all events for a game
@app.route("/api/v1.0/sports/<string:id>/games", methods=["GET"])
def fetch_all_events(id):
    data_to_return = []
    group = sports.find_one(
        {"_id": ObjectId(id)},
        {
            "games": 1,
            "_id": 0,
        },
    )
    for game in group["games"]:
        data_to_return.append(game)
    return make_response(jsonify(data_to_return), 200)


# // shows results for a location
@app.route(
    "/api/v1.0/sports/<string:id>/games/<string:location>/results", methods=["GET"]
)
def fetch_results_for_location(id, location):
    data_to_return = []
    game = sports.find_one(
        {"_id": ObjectId(id), "games.location": location},
        {"games.location.$": 1, "games.results": 1},
    )
    for results in game["games"]:
        data_to_return.append(results)
    return make_response(jsonify(data_to_return), 200)


# // adds results to location
@app.route(
    "/api/v1.0/sports/<string:id>/games/<string:location>/results", methods=["POST"]
)
def add_results_to_location(id, location):
    new_results = {
        "medal": request.form["medal"],
        "name": request.form["name"],
        "nationality": request.form["nationality"],
        "result": request.form["result"],
    }
    sports.update(
        {"_id": ObjectId(id), "games.location": location},
        {"$push": {"games.$.results": new_results}},
    )
    edit_results_url = (
        "http://localhost:5000/api/v1.0/sports/"
        + id
        + "/games/"
        + location
        + request.form["name"]
    )
    return make_response(jsonify({"url": edit_results_url}), 204)


@app.route("/api/v1.0/searchGames/<string:name>/", methods=["GET"])
def search_games(name):
    page_num, page_size = 1, 4
    if request.args.get("pn"):
        page_num = int(request.args.get("pn"))
    if request.args.get("ps"):
        page_size = int(request.args.get("ps"))
    page_start = page_size * (page_num - 1)

    data_to_return = []
    for games in (
        sports.find({"name": {"$regex": name}}).skip(page_start).limit(page_size)
    ):
        games["_id"] = str(games["_id"])

        data_to_return.append(games)

    return make_response(jsonify(data_to_return), 200)


if __name__ == "__main__":
    app.run(debug=True)
