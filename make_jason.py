import random, json


def generate_dummy_data():
    habits = [
        "Gym",
        "Walking",
        "Running",
        "Reading",
        "Podcasting",
        "Brushing Teeth",
        "Making Bed",
        "Eating breakfast",
    ]

    habit_list = []

    for i in range(8):
        name = "Habit" + str(i)
        habit = habits[random.randint(0, len(habits) - 1)]
        rating = random.randint(1, 5)
        habit_list.append({"name": name, "habit": habit, "rating": rating, "notes": []})

    return habit_list


habits = generate_dummy_data()
fout = open("data.json", "w")
fout.write(json.dumps(habits))
fout.close()
