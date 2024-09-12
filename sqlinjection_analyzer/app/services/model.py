from models.vault import Vault
from schemas.model_result import ModelResult, Reason
import re
import ast
from typing import List, Tuple
from py_find_injection import Checker
import sqlparse


class SQLInjectionModel:
    """
    Анализатор для обнаружения SQL инъекций с использованием AST и эвристического анализа.
    """
    def __init__(self) -> None:
        self.checker = Checker("")
        
    def input_score(self, text: str, vault: Vault) -> ModelResult:
        metric, reasons = self.detect_sql_injection(text,
                                                    vault,
                                                    dangerous_commands=vault.dangerous_commands_input)
        reject_flg = metric > vault.max_dangerous_commands_input

        model_output = ModelResult(
            metric=metric, reasons=reasons, reject_flg=reject_flg
        )

        return model_output

    def output_score(self, text: str, vault: Vault) -> ModelResult:
        metric, reasons = self.detect_sql_injection(text,
                                                    vault,
                                                    dangerous_commands=vault.dangerous_commands_output)
        reject_flg = metric > vault.max_dangerous_commands_output

        model_output = ModelResult(
            metric=metric, reasons=reasons, reject_flg=reject_flg
        )

        return model_output
    
    def detect_sql_injection(
        self, 
        input_text: str,
        vault: Vault,
        dangerous_commands: List=['drop', 'delete', 'insert', 'update', 'union', 'exec', 'execute']
        ) -> Tuple[int, List[Reason]]:
        """
        Проверка на SQL инъекцию с использованием py-find-injection, эвристического анализа и sqlparse.
        """
        vulnerabilities = []
        if vault.use_py_find_injection or vault.use_ast:
            vulnerabilities.extend(self.analyze_with_py_find_injection(input_text))
        if vault.use_heuristics:
            vulnerabilities.extend(self.analyze_with_heuristics(input_text))
        if vault.use_sqlparse:
            vulnerabilities.extend(self.analyze_with_sqlparse(input_text, dangerous_commands))

        return len(vulnerabilities), vulnerabilities
    
    def analyze_with_py_find_injection(self, input_text: str) -> List[Reason]:
        """
        Использует py-find-injection для поиска SQL инъекций в коде.
        """
        vulnerabilities = []
        try:
            tree = ast.parse(input_text)
            
            self.checker.visit(tree)
            for error in self.checker.errors:
                vulnerabilities.append(Reason(start=error.lineno, stop=error.reason))
        except Exception as e:
            print(e)     
        return vulnerabilities

    @staticmethod
    def analyze_with_heuristics(input_text: str) -> List[Reason]:
        """
        Эвристический анализ текста на SQL инъекции.
        """
        vulnerabilities = []
        sql_injection_patterns = [
            r"or\s+1\s*=\s*1",  # OR 1=1
            r"union\s+select",  # UNION SELECT
            r"--",  # SQL Comment
            r"insert\s+into",  # INSERT INTO
            r"drop\s+table",  # DROP TABLE
            r"select\s.*from\s.*information_schema",  # Access to information_schema
            r"\$\w+\[.*\]",  # Dynamic GET/POST/COOKIE parameters
            r"exec\s",  # EXEC/EXECUTE statements
        ]

        for pattern in sql_injection_patterns:
            for match in re.finditer(pattern, input_text, re.IGNORECASE):
                vulnerabilities.append(Reason(start=match.start(), stop=match.end()))

        return vulnerabilities
    
    @staticmethod
    def analyze_with_sqlparse(input_text: str, dangerous_commands: List) -> List[Reason]:
        """
        Использование sqlparse для анализа опасных SQL-конструкций, таких как UNION SELECT, DROP, и комментарии.
        """
        vulnerabilities = []
        try:
            parsed = sqlparse.parse(input_text)
            for stmt in parsed:
                for token in stmt.tokens:
                    if token.ttype is None and isinstance(token, sqlparse.sql.TokenList):
                        value = token.value.lower()
                        for cmd in dangerous_commands:
                            if cmd in value:
                                absolute_pos = input_text.lower().find(cmd)
                                if absolute_pos != -1:
                                    vulnerabilities.append(Reason(start=absolute_pos, stop=absolute_pos + len(cmd)))

                    if token.ttype == sqlparse.tokens.Comment.Single or token.ttype == sqlparse.tokens.Keyword.DML:
                        absolute_pos = input_text.lower().find(token.value.lower())
                        if absolute_pos != -1:
                            vulnerabilities.append(Reason(start=absolute_pos, stop=absolute_pos + len(token.value)))
        except Exception as e:
            print(e)
        return vulnerabilities