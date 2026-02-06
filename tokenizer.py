# tokenizer.py
from __future__ import annotations
from typing import Iterator, List

def _is_ascii_alnum(ch: str) -> bool:
    o = ord(ch)
    return (48 <= o <= 57) or (65 <= o <= 90) or (97 <= o <= 122)

def tokenize_text_stream(text: str) -> Iterator[str]:
    token_chars: List[str] = []
    for ch in text:
        if _is_ascii_alnum(ch):
            if "A" <= ch <= "Z":
                ch = chr(ord(ch) + 32)
            token_chars.append(ch)
        else:
            if token_chars:
                yield "".join(token_chars)
                token_chars.clear()

    if token_chars:
        yield "".join(token_chars)
