import json

# 读取 json 文件
with open('file.json', 'r') as f:
    data = json.load(f)

# 去重
unique_data = []
for i in range(len(data)):
    unique = True
    for j in range(i+1, len(data)):
        if data[i]['cms'] == data[j]['cms'] and data[i]['keyword'] == data[j]['keyword']:
            unique = False
            break
    if unique:
        unique_data.append(data[i])

# 输出去重后的结果
print(unique_data)

# 将去重后的结果写入新的 json 文件
with open('unique_file.json', 'w') as f:
    json.dump(unique_data, f)

