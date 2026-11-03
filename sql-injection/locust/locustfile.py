"""Cardinal Phase 1 — benign employee traffic.

Models the normal mix a staff member performs: log in, browse the directory,
search for colleagues, view profiles. This is the ambient noise the SQLi
attack must be distinguished from — the *same* endpoints (/login, /search,
/profile) the attacker uses, differing only in the input.

Runs against the proxy (edge-net), so benign traffic crosses the same choke
point as the attack.
"""
import random

from locust import HttpUser, SequentialTaskSet, between, task

# Seeded accounts (username -> password) from db/seed.sql.
USERS = {"alice": "alicepw", "bob": "bobpw", "carol": "carolpw"}

# Terms a normal user would type — names and departments present in the seed,
# so searches return plausible, non-empty results.
SEARCH_TERMS = [
    "Alice", "Bob", "Carol", "David", "Erin", "Grace", "Ivy", "Jamal",
    "Nguyen", "Carter", "Osei", "Park", "Rossi", "Sharma",
    "Engineering", "Finance", "Product", "HR", "IT", "Sales", "Marketing",
    "Legal", "Facilities",
]


class EmployeeBehavior(SequentialTaskSet):
    def on_start(self):
        username = random.choice(list(USERS))
        self.client.post(
            "/login",
            data={"username": username, "password": USERS[username]},
            name="/login",
        )

    @task(3)
    def search_directory(self):
        term = random.choice(SEARCH_TERMS)
        self.client.get(f"/search?q={term}", name="/search?q=[term]")

    @task(2)
    def browse_directory(self):
        self.client.get("/search", name="/search (browse)")

    @task(2)
    def browse_home(self):
        self.client.get("/", name="/")

    @task(2)
    def view_profile(self):
        pid = random.randint(1, 17)  # 17 directory entries in the seed
        self.client.get(f"/profile/{pid}", name="/profile/[id]")

    @task(1)
    def split_search(self):
        term = random.choice(SEARCH_TERMS)
        half = max(1, len(term) // 2)
        self.client.get(
            f"/search?split=on&q={term[:half]}&q={term[half:]}",
            name="/search?split=on&q=[half]&q=[half]",
        )

class BenignUser(HttpUser):
    tasks = [EmployeeBehavior]
    wait_time = between(1, 5)  # human-plausible pacing
    # host is provided on the CLI (--host=http://172.30.0.10, the proxy).
