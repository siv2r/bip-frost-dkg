import json
from typing import NoReturn, List

def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()

def bytes_list_to_hex(lst: List[bytes]) -> List[str]:
    return [l_i.hex().upper() for l_i in lst]

def hex_list_to_bytes(lst: List[str]) -> List[bytes]:
    return [bytes.fromhex(l_i) for l_i in lst]

def write_json(filename: str, data: dict) -> NoReturn:
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def exception_to_dict(e: Exception) -> dict:
    error_info = {"type": e.__class__.__name__}
    error_info.update(e.__dict__)
    # the last argument might contain the error message
    if len(e.args) > 0 and isinstance(e.args[-1], str):
        error_info.setdefault("message", e.args[-1])
    return error_info

def expect_exception(try_fn, expected_exception):
    try:
        try_fn()
    except expected_exception as e:
        return exception_to_dict(e)
    except Exception as e:
        raise AssertionError(f"Wrong exception raised: {type(e).__name__}")
    else:
        raise AssertionError("Expected exception")
