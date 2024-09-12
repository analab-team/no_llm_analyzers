from pydantic import BaseModel
from typing import List

class Vault(BaseModel):
    dangerous_commands_input: List
    dangerous_commands_output: List
    max_dangerous_commands_input: int
    max_dangerous_commands_output: int
    use_py_find_injection: bool
    use_heuristics: bool
    use_sqlparse: bool
    use_ast: bool