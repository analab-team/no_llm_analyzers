from typing import List


VERBS = [
        "игнорируй", "пропусти", "пренебреги", "забудь", "не учитывай", "не обращай внимания на", "обойди", "не следуй", "не выполняй",
    ]
ADJECTIVE = [
    "", "предыдущие", "прошлые", "начальные", "ранние", "вышеуказанные", "системные"
    ]
PREPOSITIONS = [
    "", "и начни заново", "и начни с начала", "и начни с чистого листа", "и начни с нуля"
    ]
OBJECTS = [
    "инструкции", "команды", "тексты", "сообщения", "сообщение", "данные", "ответы", "контекст", "запросы", "ответ", 
    "коммуникации", "промпт", "все", "все что выше"
    ]

def generate_injection_keywords() -> List[str]:
    """
    Генерация всех возможных комбинаций предложений на основе списка предопределённых глаголов, прилагательных, предлогов и объектов.
    :returns: List[str]. Список предложений
    """
    injection_keywords = []
    for verb in VERBS:
        for adjective in ADJECTIVE:
            for object in OBJECTS:
                for preposition in PREPOSITIONS:
                    all_words = verb + " " + adjective + " " + object + " " + preposition
                    injection_keywords.append(all_words.replace("  ", " "))

    return injection_keywords