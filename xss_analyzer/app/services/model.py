from models.vault import Vault
from schemas.model_result import ModelResult, Reason
import re
from typing import List, Tuple
from bs4 import BeautifulSoup

XSS_PAYLOADS = [
    '"><svg/onload=alert(1)>',
    '\'><svg/onload=alert(1)>',
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '\'><img src=x onerror=alert(1)>',
    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//--></script>",
    "<Script>alert('XSS')</scripT>",
    "<script>alert(document.cookie)</script>",
]

# Сигнатуры XSS с регулярными выражениями
XSS_REGEX_PATTERNS = [
    r'<script.*?>.*?</script>',
    r'on\w+\s*=\s*["\'].*?["\']',
    r'<iframe.*?src=["\'].*?["\']',
    r'<img.*?src=.*?onerror=.*?>',
    r'<svg.*?onload=.*?>',
    r'value\s*=\s*["\'].*?<.*?>["\']',
    r'value\s*=\s*["\'].*?alert\(.*?\).*?["\']',
]


class BanwordModel:
    """
    Анализатор для поиска XSS уязвимостей в тексте. Использует BeautifulSoup для анализа HTML и регулярные выражения
    для поиска вредоносных полезных нагрузок.
    """
    
    def input_score(self, text: str, vault: Vault) -> ModelResult:
        metric, reasons = self.detect_xss(text, vault.use_regex_input, vault.use_payload_signature_input, vault.use_bs4_input)
        reject_flg = metric > vault.max_allowed_xss_input

        model_output = ModelResult(
            metric=metric, reasons=reasons, reject_flg=reject_flg
        )

        return model_output

    def output_score(self, text: str, vault: Vault) -> ModelResult:
        metric, reasons = self.detect_xss(text, vault.use_regex_output, vault.use_payload_signature_output, vault.use_bs4_output)
        reject_flg = metric > vault.max_allowed_xss_output

        model_output = ModelResult(
            metric=metric, reasons=reasons, reject_flg=reject_flg
        )

        return model_output
    
    def detect_xss(
        self, input_text: str,
        use_regex: bool,
        use_payload_signature: bool,
        use_bs4: bool
        ) -> Tuple[float, List[Reason]]:
        """
        Определяет XSS уязвимости с использованием BeautifulSoup и строкового поиска.
        """
        vulnerabilities = []

        # 1. Прямой парсинг HTML с помощью BeautifulSoup
        soup = BeautifulSoup(input_text, "html.parser")

        # Поиск скриптов и опасных событийных обработчиков
        if use_bs4:
            for script in soup.find_all('script'):
                if any(xss_payload in str(script) for xss_payload in XSS_PAYLOADS):
                    start = input_text.find(str(script))
                    if start != -1:
                        end = start + len(str(script))
                        vulnerabilities.append(Reason(start=start, stop=end))

        # Поиск опасных значений в атрибутах, таких как value
        if use_payload_signature:
            for tag in soup.find_all(True):  # Find all tags
                for attribute in tag.attrs:
                    if attribute == 'value':
                        value = tag.attrs[attribute]
                        if any(xss_payload in value for xss_payload in XSS_PAYLOADS):
                            start = input_text.find(value)
                            if start != -1:
                                end = start + len(value)
                                vulnerabilities.append(Reason(start=start, stop=end))

        # 2. Поиск уязвимостей с помощью регулярных выражений
        if use_regex:
            for pattern in XSS_REGEX_PATTERNS:
                matches = re.finditer(pattern, input_text, re.IGNORECASE)
                for match in matches:
                    if "onload" in match.group(0) or "onerror" in match.group(0):
                        vulnerabilities.append(Reason(start=match.start(), stop=match.end()))

        vulnerabilities = list(set(vulnerabilities))  # Убираем дубликаты
        return len(vulnerabilities), vulnerabilities