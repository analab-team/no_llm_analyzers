from pydantic import BaseModel
from typing import List

class Vault(BaseModel):
    check_known_dangerous_input: bool
    check_known_dangerous_output: bool
    check_executable_input: bool
    check_executable_output: bool
    check_redirects_input: bool
    check_redirects_output: bool
    check_virustotal_input: bool
    check_virustotal_output: bool
    max_allowed_dangerous_links_input: int
    max_allowed_dangerous_links_output: int