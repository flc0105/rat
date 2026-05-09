SCRIPT_METADATA = {
    "name": "common/terminal/random_identity",
    "display_name": "Random Identity Generator",
    "description": "Generate a random fake identity",
    "platforms": ["common"],
    "category": "Terminal",
    "params": []
}

import random
import datetime


FIRST_NAMES = [
    "Alex", "Sam", "Jordan", "Taylor", "Morgan", "Casey", "Jamie", "Riley",
    "Chris", "Robin", "Drew", "Avery", "Quinn", "Skyler"
]

LAST_NAMES = [
    "Smith", "Johnson", "Brown", "Miller", "Davis", "Wilson", "Moore",
    "Taylor", "Anderson", "Thomas", "Jackson", "White"
]

STREETS = [
    "Maple St", "Oak Ave", "Pine Road", "Cedar Lane", "Sunset Blvd",
    "Lake View Dr", "Hillcrest Way", "Market Street"
]

CITIES = [
    "Springfield", "Riverside", "Fairview", "Franklin", "Greenville",
    "Madison", "Georgetown", "Arlington"
]

JOBS = [
    "Systems Administrator",
    "Coffee Machine Whisperer",
    "Backend Developer",
    "Network Goblin",
    "Spreadsheet Archaeologist",
    "Bug Reproduction Specialist",
    "Legacy Code Therapist",
    "Terminal Historian"
]

COMPANIES = [
    "Umbrella Labs", "Acme Corp", "Globex", "Initech", "Stark Industries",
    "Soylent Systems", "Cyberdyne", "Wayne Enterprises"
]


def rand_phone():
    return "+1-{}-{}-{}".format(
        random.randint(200, 999),
        random.randint(200, 999),
        random.randint(1000, 9999)
    )


def rand_birthday():
    year = random.randint(1960, 2003)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return datetime.date(year, month, day)


def rand_mac():
    return ":".join("{:02x}".format(random.randint(0, 255)) for _ in range(6))


def rand_ip():
    return "{}.{}.{}.{}".format(
        random.randint(10, 223),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(1, 254)
    )


def make_identity():
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    username = (first[0] + last + str(random.randint(10, 99))).lower()
    email = username + random.choice(["@example.com", "@mail.test", "@fake.invalid"])

    return {
        "Name": first + " " + last,
        "Username": username,
        "Email": email,
        "Phone": rand_phone(),
        "Birthday": str(rand_birthday()),
        "Address": "{} {}, {}".format(
            random.randint(100, 9999),
            random.choice(STREETS),
            random.choice(CITIES)
        ),
        "Job": random.choice(JOBS),
        "Company": random.choice(COMPANIES),
        "MAC": rand_mac(),
        "IPv4": rand_ip(),
    }


def main():
    person = make_identity()

    print("Random Identity")
    print("-" * 40)

    for k, v in person.items():
        print("{:<10} {}".format(k + ":", v))


if __name__ == "__main__":
    main()
