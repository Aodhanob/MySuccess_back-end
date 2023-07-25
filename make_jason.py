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
        "Walk Dog",
    ]

    habit_list = []

    for i in range(8):
        title = "Habit" + str(i)
        habit = habits[random.randint(0, len(habits) - 1)]
        priority = random.randint(1, 5)
        notes = "Notes on how to best carry out habits or any information will be here."
        habit_list.append(
            {"title": title, "habit": habit, "priority": priority, "notes": []}
        )

    return habit_list


habits = generate_dummy_data()
fout = open("data.json", "w")
fout.write(json.dumps(habits))
fout.close()
