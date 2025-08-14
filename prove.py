import json


logs = ['{ "nome":"Giacomo", "eta":23}',
        '{ "nome":"Luca", "eta":25}',
        '{ "nome":"Alex", "eta":33}',
        '{ "nome":"Matteo", "eta":50}',
        '{ "nome":"Giulia", "eta":23}',
        '{ "nome":"Francesco", "eta":44}',
        '{ "nome":"Sara", "eta":25}',
        '{ "nome":"Tommaso", "eta":21}',
        '{ "nome":"Carlo", "eta":39}']

sumA = 0
sumB = 0

for x in logs:
    val = json.loads(x)
    sumA += val['eta']
    sumB += len(val['nome'])

avg = sumA / len(logs)
print(avg)

avg = sumB / len(logs)
print(avg)

# avg = sum(logs["eta"]) / len(logs)

# x = json.loads(logs)
# print(x[3]["eta"])