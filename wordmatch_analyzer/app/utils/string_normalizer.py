import re
from typing import List
from pymystem3 import Mystem

lemm_model = Mystem()

def normalize_string(input_string: str) -> str:
    """
    Нормализация строки: приведение к нижнему регистру, удаление символов, не являющихся буквами или числами, удаление лишних пробелов и т.д.
    :param input_string: str. Строка для нормализации
    :returns: str. Нормализованная строка
    """
    result = input_string.lower()
    result = re.sub(r"[^\w\s]|_", "", result)
    result = re.sub(r"\s+", " ", result)
    result = result.strip()
    lemmas = lemm_model.lemmatize(input_string)
    return ''.join(lemmas)

def get_input_substrings(normalized_input: str, keyword_length: int) -> List[str]:
    """
    Итерирование по входной строке и получение подстрок с длиной, аналогичной длине строки ключевых слов.
    :param normalized_input: str. Нормализованная входная строка
    :param keyword_length: int. Количество слов в строке инъекции
    :returns: List[str]. Список подстрок.
    """
    words_in_input_string = normalized_input.split(" ")
    return [" ".join(words_in_input_string[i : i + keyword_length]) for i in range(len(words_in_input_string) - keyword_length + 1)]

def get_matched_words_score(substring: str, keyword_parts: List[str], max_matched_words: int) -> float:
    """
    Подсчет количества совпадающих слов между подстрокой и ключевыми словами, и вычисление базовой оценки.
    :param substring: str. Подстрока входной строки
    :param keyword_parts: List[str]. Части ключевых слов
    :param max_matched_words: int. Максимальное количество совпадающих слов
    :returns: float. Оценка совпадения слов
    """
    matched_words_count = len([part for part, word in zip(keyword_parts, substring.split()) if word == part])
    return 0.5 + 0.5 * min(matched_words_count / max_matched_words, 1) if matched_words_count > 0 else 0