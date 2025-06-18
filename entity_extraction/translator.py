from googletrans import Translator

translator = Translator()

def to_chinese(text):
    result = translator.translate(text, src='auto', dest='zh-cn')
    return result.text

def to_english(text):
    result = translator.translate(text, src='auto', dest='en')
    return result.text