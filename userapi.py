import json

# Python dictionary
user = {
    "name": "Augustine",
    "username": "augustine28",
    "age": 28
}

# Convert dictionary into JSON
json_data = json.dumps(user)

print(json_data)