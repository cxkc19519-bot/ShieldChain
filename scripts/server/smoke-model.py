import json
import sys
import time
import urllib.error
import urllib.request

base = 'http://127.0.0.1:8080/api/v1/qwen'
target = sys.argv[1]

def call(path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(base + path, data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)

assert call('/select', {'model': 'not-allowed'})[0] == 422
last = None
for attempt in range(120):
    _, state = call('/models')
    value = (state.get('phase'), state.get('active_model'), state.get('message'))
    if value != last:
        print('STATE', value, flush=True)
        last = value
    if state.get('ready') and state.get('active_model') == target:
        break
    if state.get('phase') == 'error':
        raise RuntimeError(state)
    time.sleep(10)
else:
    raise TimeoutError('Model did not become ready')

payload = {'model': target, 'messages': [{'role': 'user', 'content': '请只回答：模型连接测试成功'}], 'max_tokens': 64, 'temperature': 0}
start = time.monotonic()
code, result = call('/chat', payload)
print('CHAT', code, 'seconds', round(time.monotonic()-start, 2), json.dumps(result, ensure_ascii=False), flush=True)
assert code == 200 and result.get('content')
expected = 'shieldchain-qwen38-27b' if target == 'qwen38' else 'shieldchain-qwen3-30b'
assert result['model'] == expected
payload['messages'] += [{'role': 'assistant', 'content': result['content']}, {'role': 'user', 'content': '上一条我要求你回答什么？只复述那句话。'}]
code, result = call('/chat', payload)
print('MULTITURN', code, json.dumps(result, ensure_ascii=False), flush=True)
assert code == 200 and result.get('content')
payload['model'] = 'qwen3' if target == 'qwen38' else 'qwen38'
code, result = call('/chat', payload)
assert code == 409, (code, result)
print('PASS: model routing, multi-turn chat, inactive model guard, allowlist', flush=True)
