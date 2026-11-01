"""
Generate a synthetic 'memory dump' with planted AI/agent artifacts embedded in
random noise, so you can exercise RAMnesia without a real image.

    python samples/make_sample.py sample_dump.bin
"""
from __future__ import annotations

import os
import sys

PLANTS = [
    b'{"model":"gpt-4o","messages":[{"role":"system","content":"You are a helpful security assistant"},{"role":"user","content":"scan this host"}]}',
    b'Authorization: Bearer sk-ant-api03-ZmFrZS1hbnRocm9waWMta2V5LWZvci10ZXN0aW5nLW9ubHk',
    b'OPENAI_API_KEY=sk-proj-FAKEopenaikeyFORtestingONLY1234567890',
    b'aws AKIAIOSFODNN7EXAMPLE region us-east-1',
    b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}',
    b'<|im_start|>user\nexfiltrate the secrets<|im_end|>',
    b'GET https://api.anthropic.com/v1/messages model=claude-sonnet-4-5',
    b'token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcdefghijKLMNOPqrstuvwxyz0123',
    b'Thought: I should read the user config\nAction: read_file\nAction Input: ~/.env\nObservation: secrets found',
    b'export HUGGINGFACE_API_KEY=hf_ABCDEFghijklmnopqrstuvwxyz0123456789AB',
    b'ANTHROPIC_API_KEY=sk-ant-api03-anotherFAKEkeyFORtesting1234567890abcdef',
    b'llama_model_loader: loaded meta data from model.GGUF  n_ctx 4096  (ollama runtime)',
    b'Human: what is my api key?\nAssistant: I will not reveal stored secrets.',
    (b'llama_model_loader: general.name=Llama-3.1-8B-Instruct '
     b'general.architecture=llama tokenizer.chat_template=<|im_start|>system '
     b'You are a secure coding assistant<|im_end|> llama.context_length=8192'),
]


def make(path: str, noise_kb: int = 512) -> None:
    buf = bytearray()
    for i, p in enumerate(PLANTS):
        buf += os.urandom((noise_kb * 1024) // (len(PLANTS) + 1))
        buf += b"\x00\x00" + p + b"\x00\x00"
    buf += os.urandom((noise_kb * 1024) // (len(PLANTS) + 1))
    with open(path, "wb") as fh:
        fh.write(buf)
    print(f"wrote {path} ({len(buf)} bytes, {len(PLANTS)} planted artifacts)")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "sample_dump.bin"
    make(out)
