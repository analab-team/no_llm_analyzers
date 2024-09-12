from models.vault import Vault
from schemas.model_result import ModelResult, Reason
import re
from typing import List, Tuple
import requests
from urllib.parse import urlparse, quote
import time

class LinkModel:
    """
    Анализатор для извлечения ссылок из входящей строки и проверки их на наличие уязвимостей, включая проверку VirusTotal.
    """
    def __init__(self, virustotal_api_key: str) -> None:
        self.executable_extensions = ['.exe', '.bat', '.cmd', '.sh', '.php', '.pl', '.py']
        self.known_dangerous_links = {"https://vulnerable.com", "https://phishingsite.com"}
        self.virustotal_api_key = virustotal_api_key
        self.virustotal_limit_reached = False
        self.virustotal_last_request_time = 0
        
    def input_score(self, text: str, vault: Vault) -> ModelResult:
        metric, reasons = self.analyze(
            text, 
            vault.check_known_dangerous_input, 
            vault.check_executable_input, 
            vault.check_redirects_input,
            vault.check_virustotal_input
            )
        reject_flg = metric > vault.max_allowed_dangerous_links_input

        model_output = ModelResult(
            metric=metric, reasons=reasons, reject_flg=reject_flg
        )

        return model_output

    def output_score(self, text: str, vault: Vault) -> ModelResult:
        metric, reasons = self.analyze(
            text, 
            vault.check_known_dangerous_output, 
            vault.check_executable_output, 
            vault.check_redirects_output,
            vault.check_virustotal_output
            )
        reject_flg = metric > vault.max_allowed_dangerous_links_output

        model_output = ModelResult(
            metric=metric, reasons=reasons, reject_flg=reject_flg
        )

        return model_output
    
    def extract_links(self, text: str) -> List[Tuple[str, int, int]]:
        """
        Извлекает все ссылки (URL) из текста. Проверяем, является ли текст ссылкой с помощью urlparse.
        Возвращает список кортежей (ссылка, начальная позиция, конечная позиция).
        """
        url_pattern = re.compile(r'(https?://[^\s]+)')
        matches = list(url_pattern.finditer(text))
        links = []

        for match in matches:
            link = match.group(0)
            parsed_link = urlparse(link)
            if all([parsed_link.scheme, parsed_link.netloc]):
                start_pos, end_pos = match.span()
                links.append((link, start_pos, end_pos))
        
        return links
    
    def check_known_dangerous(self, link: str) -> bool:
        """
        Проверяет, находится ли ссылка в базе известных опасных ссылок.
        Возвращает True, если ссылка найдена в базе опасных ссылок.
        """
        parsed_link = urlparse(link)
        base_url = f"{parsed_link.scheme}://{parsed_link.netloc}"
        if base_url in self.known_dangerous_links:
            return True
        return False

    def check_for_executable(self, link: str) -> bool:
        """
        Проверяет, не заканчивается ли ссылка на исполняемый файл (.exe, .bat, .cmd, .sh, .php, .pl, .py и т.д.).
        Возвращает True, если ссылка ведет на исполняемый файл.
        """
        for ext in self.executable_extensions:
            if link.lower().endswith(ext):
                return True
        return False

    def check_virustotal(self, link: str) -> bool:
        """
        Проверяет ссылку через VirusTotal API.
        Возвращает True, если сайт помечен как вредоносный.
        """
        if self.virustotal_limit_reached:
            print(f"Skipping VirusTotal check due to request limit reached.")
            return False

        # Ограничение скорости запросов: не более 4 запросов в минуту
        current_time = time.time()
        if current_time - self.virustotal_last_request_time < 15:
            print("VirusTotal rate limits...")
            return False
        
        self.virustotal_last_request_time = time.time()

        url = "https://www.virustotal.com/api/v3/urls"
        headers = {
            "accept": "application/json",
            "x-apikey": self.virustotal_api_key,
            "content-type": "application/x-www-form-urlencoded"
        }

        # Преобразование ссылки для соответствия требованиям VirusTotal
        encoded_url = quote(link, safe='')
        data = f"url={encoded_url}"

        try:
            response = requests.post(url, headers=headers, data=data)
            if response.status_code == 429:  # Превышен лимит запросов
                self.virustotal_limit_reached = True
                print("VirusTotal request limit reached.")
                return False

            result = response.json()
            id = result['data']['id']
            url = f"https://www.virustotal.com/api/v3/analyses/{id}"
            headers = {"accept": "application/json",
                       "x-apikey": self.virustotal_api_key,}
            response = requests.get(url, headers=headers)
            result = response.json()
            if result['data']['attributes']['stats']['malicious'] > 0:
                print(f"Link flagged by VirusTotal as malicious: {link}")
                return True
        except requests.exceptions.RequestException as e:
            print(f"Ошибка при попытке проверки VirusTotal {link}: {e}")
        
        return False

    def check_for_redirects(self, link: str) -> bool:
        """
        Проверяет, перенаправляет ли ссылка пользователя на другой URL (редирект).
        Возвращает True, если ссылка ведет на редирект.
        """
        try:
            response = requests.head(link, allow_redirects=False, verify=False)
            if response.is_redirect or response.status_code in [301, 302, 303, 307, 308]:
                return True
        except requests.exceptions.RequestException as e:
            print(f"Ошибка при попытке проверки редиректа {link}: {e}")
        return False
    
    def analyze(
        self,
        text: str,
        check_known_dangerous: bool=True,
        check_executable: bool=True,
        check_redirects: bool=True,
        check_virustotal: bool=True
        ) -> Tuple[float, List[Reason]]:
        """
        Анализирует текст на наличие вредоносных ссылок.
        Проверяет через VirusTotal, исполняемые файлы, редиректы и XSS уязвимости.
        Возвращает общий скор и список координат ссылок, где найдены уязвимости.
        """
        links = self.extract_links(text)
        vulnerabilities = []

        for link, start_pos, end_pos in links:
            # Проверка на известные опасные ссылки
            if check_known_dangerous and self.check_known_dangerous(link):
                vulnerabilities.append(Reason(start=start_pos, stop=end_pos))
                continue

            # Проверка на исполняемые файлы
            if check_executable and self.check_for_executable(link):
                vulnerabilities.append(Reason(start=start_pos, stop=end_pos))
                continue

            # Проверка на редиректы
            if check_redirects and self.check_for_redirects(link):
                vulnerabilities.append(Reason(start=start_pos, stop=end_pos))
                continue

            # Проверка через VirusTotal
            if check_virustotal and self.check_virustotal(link):
                vulnerabilities.append(Reason(start=start_pos, stop=end_pos))
                continue

        return len(vulnerabilities), vulnerabilities