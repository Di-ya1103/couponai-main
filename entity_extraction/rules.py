import unicodedata
import logging
import re
import jieba
from typing import Optional, Dict, List, Tuple
from mysql.connector import Error
import difflib
from mistralai import Mistral, UserMessage
import os

class EnhancedRuleBasedExtractor:
    def __init__(self, db_connection):
        self.db_connection = db_connection
        self.db = db_connection
        self.categories = []
        self.coupons_data = []
        self.categories_data = {}
        self.area_data = {}
        self.location_tables = ['hong_kong', 'kowloon', 'new_territories']
        self.location_data = {}
        self.last_location = None
        self.mistral_client = Mistral(api_key=os.getenv("MISTRAL_API_KEY"))
        self._fetch_categories_data()
        self._fetchCoupons_data()
        self._fetch_area_data()
        self._fetch_location_data()
        self._initialize_jieba()

    def _fetch_categories_data(self):
        cursor = self.db_connection.cursor(dictionary=True)
        try:
            cursor.execute("SELECT name_en FROM categories WHERE status = '1' AND deleted_at IS NULL")
            self.categories = [row['name_en'] for row in cursor.fetchall() if row['name_en']]
            cursor.execute("SELECT id, name_en, COALESCE(name_cn, '') AS name_cn FROM categories WHERE status = '1' AND deleted_at IS NULL")
            self.categories_data = {row['id']: {'name_en': row['name_en'], 'name_cn': row['name_cn']} for row in cursor.fetchall()}
            logging.debug(f"Fetched {len(self.categories)} categories: {self.categories}")
        except Error as e:
            logging.error(f"Error fetching categories: {e}")
        finally:
            cursor.close()

    def _fetchCoupons_data(self):
        cursor = self.db_connection.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT id, name_en, COALESCE(name_cn, '') AS name_cn, status, quantity, area, selected_area, territory, category_id
                FROM coupons WHERE deleted_at IS NULL
            """)
            self.coupons_data = cursor.fetchall()
            logging.debug(f"Fetched {len(self.coupons_data)} coupons: {[c['name_en'] for c in self.coupons_data[:5]]}")
        except Error as e:
            logging.error(f"Error fetching coupons: {e}")
        finally:
            cursor.close()

    def _fetch_area_data(self):
        cursor = self.db_connection.cursor(dictionary=True)
        try:
            cursor.execute("SELECT id, name_en, COALESCE(name_cn, '') AS name_cn FROM area WHERE status = 1 AND deleted_at IS NULL")
            self.area_data = {str(row['id']): {'name_en': row['name_en'], 'name_cn': row['name_cn']} for row in cursor.fetchall()}
            logging.debug(f"Fetched {len(self.area_data)} areas: {list(self.area_data.values())[:5]}")
        except Error as e:
            logging.error(f"Error fetching areas: {e}")
        finally:
            cursor.close()

    def _fetch_location_data(self):
        cursor = self.db_connection.cursor(dictionary=True)
        try:
            for table in self.location_tables:
                cursor.execute(f"SELECT id, name_en, COALESCE(name_cn, '') AS name_cn FROM {table} WHERE status = 1 AND deleted_at IS NULL")
                self.location_data[table] = {str(row['id']): {'name_en': row['name_en'], 'name_cn': row['name_cn']} for row in cursor.fetchall()}
                logging.debug(f"Fetched {len(self.location_data[table])} locations from {table}: {list(self.location_data[table].values())[:5]}")
        except Error as e:
            logging.error(f"Error fetching location data: {e}")
        finally:
            cursor.close()

    def _initialize_jieba(self):
        custom_words = ['香港', '九龍', '新界', '港島', '優惠券', '折扣', '高达', '至少', 'gucci', 'gucci store', '灣仔', 'wan chai', '觀塘', 'kwun tong', 'toy kfc', 'whampoa', '黃埔', 'shek o', '石澳']
        for word in custom_words:
            jieba.add_word(word)

    def _mistral_query(self, prompt: str) -> Optional[str]:
        try:
            response = self.mistral_client.chat.complete(
                model="mistral-small-latest",
                messages=[UserMessage(content=prompt)]
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            logging.error(f"Mistral API error: {e}")
            return None

    def _extract_location_from_query(self, query: str) -> Optional[dict]:
        query = unicodedata.normalize('NFC', query.strip())
        query_lower = query.lower().replace('-', ' ').strip()
        is_chinese = any('\u4e00' <= c <= '\u9fff' for c in query)

        prompt = f"""
        Analyze the query: '{query}'
        Determine if the user is referring to the broad area 'Hong Kong' or a specific sub-area within Hong Kong (e.g., Shek O, Wan Chai).
        - If the query explicitly mentions a sub-area (e.g., 'Shek O', 'Wan Chai'), return the sub-area name.
        - If the query only mentions 'Hong Kong' or equivalent (e.g., '香港', 'hongkong'), return 'Hong Kong' as the broad area.
        - If no specific location is identified, return None.
        Respond with only the location name or None.
        """
        mistral_result = self._mistral_query(prompt)
        logging.debug(f"Mistral location analysis: {mistral_result}")

        if mistral_result == 'Hong Kong':
            return {'name': 'Hong Kong', 'type': 'area', 'id': '1'}
        elif mistral_result and mistral_result != 'None':
            for table in self.location_tables:
                for loc_id, loc_info in self.location_data[table].items():
                    if mistral_result.lower() == loc_info['name_en'].lower() or mistral_result.lower() == loc_info['name_cn'].lower():
                        logging.info(f"Mistral matched specific area: {mistral_result} -> {loc_info['name_en']}")
                        return {'name': loc_info['name_en'], 'type': 'selected_area', 'id': loc_id, 'table': table}
            logging.warning(f"Mistral returned area '{mistral_result}' not found in location data")

        stop_words = {
            'i', 'want', 'give', 'coupon', 'coupons', 'for', 'in', 'of', 'the', 'all', 'that', 'expires', 'today',
            'location', 'me', 'off', 'discount', 'percent', 'percentage', 'at', 'least', 'up', 'to', 'atmost', 'most',
            'upto', 'voucher', 'cash', 'dollars', 'fifty', 'cute', 'doggo', 'dog', 'pet', 'paradise', 'store'
        }
        category_keywords = {k.lower() for k in self.categories}
        category_keywords.update({
            'pizza', 'pet', 'pets', 'fitness', 'food', 'restaurant', 'gym', 'tastygo',
            'cute doggo', 'pet paradise', 'test pet', 'gucci'
        })

        words = jieba.lcut(query) if is_chinese else query_lower.split()
        location_candidates = []
        i = 0
        while i < len(words):
            for length in range(4, 0, -1):
                if i + length <= len(words):
                    candidate = ' '.join(words[i:i+length]).strip()
                    if (candidate and candidate.lower() not in stop_words and 
                        candidate.lower() not in category_keywords):
                        location_candidates.append(candidate)
            i += 1

        if not location_candidates:
            logging.info(f"No location candidates found in query: {query}")
            return None

        logging.debug(f"Location candidates: {location_candidates}")

        area_variations = {
            'hong kong': {'name': 'Hong Kong', 'type': 'area', 'id': '1'},
            'hongkong': {'name': 'Hong Kong', 'type': 'area', 'id': '1'},
            'hong kong s.a.r.': {'name': 'Hong Kong', 'type': 'area', 'id': '1'},
            'honkong': {'name': 'Hong Kong', 'type': 'area', 'id': '1'},
            '香港': {'name': 'Hong Kong', 'type': 'area', 'id': '1'},
            '港島': {'name': 'Hong Kong', 'type': 'area', 'id': '1'},
            'kowloon': {'name': 'Kowloon', 'type': 'area', 'id': '2'},
            '九龍': {'name': 'Kowloon', 'type': 'area', 'id': '2'},
            'new territories': {'name': 'New Territories', 'type': 'area', 'id': '3'},
            '新界': {'name': 'New Territories', 'type': 'area', 'id': '3'},
            'wan chai': {'name': 'Wan Chai', 'type': 'selected_area', 'id': None, 'table': 'hong_kong'},
            'wanchai': {'name': 'Wan Chai', 'type': 'selected_area', 'id': None, 'table': 'hong_kong'},
            'wn chai': {'name': 'Wan Chai', 'type': 'selected_area', 'id': None, 'table': 'hong_kong'},
            '灣仔': {'name': 'Wan Chai', 'type': 'selected_area', 'id': None, 'table': 'hong_kong'},
            'kwun tong': {'name': 'Kwun Tong', 'type': 'selected_area', 'id': None, 'table': 'kowloon'},
            '觀塘': {'name': 'Kwun Tong', 'type': 'selected_area', 'id': None, 'table': 'kowloon'},
            'whampoa': {'name': 'Whampoa', 'type': 'selected_area', 'id': None, 'table': 'kowloon'},
            '黃埔': {'name': 'Whampoa', 'type': 'selected_area', 'id': None, 'table': 'kowloon'},
            'shek o': {'name': 'Shek O', 'type': 'selected_area', 'id': None, 'table': 'hong_kong'},
            '石澳': {'name': 'Shek O', 'type': 'selected_area', 'id': None, 'table': 'hong_kong'}
        }

        for candidate in location_candidates:
            candidate_lower = candidate.lower()
            candidate_normalized = ' '.join(candidate_lower.split())
            
            if candidate_lower in area_variations:
                result = area_variations[candidate_lower]
                if result['type'] == 'selected_area':
                    for loc_id, loc_info in self.location_data.get(result['table'], {}).items():
                        if loc_info['name_en'].lower() == result['name'].lower() or loc_info['name_cn'].lower() == candidate_lower:
                            result['id'] = loc_id
                            logging.info(f"Selected area matched: {result['table']} '{result['name']}' with ID {loc_id}")
                            return result
                logging.info(f"Normalized area match: '{candidate}' -> '{result['name']}'")
                return result

            for table in self.location_tables:
                for loc_id, loc_info in self.location_data[table].items():
                    loc_en = loc_info['name_en'].lower() if loc_info['name_en'] else ''
                    loc_cn = loc_info['name_cn'].lower() if loc_info['name_cn'] else ''
                    if candidate_normalized == loc_en or candidate_normalized == loc_cn:
                        logging.info(f"Exact location matched: {table} '{loc_info['name_en']}'")
                        return {'name': loc_info['name_en'], 'type': 'selected_area', 'id': loc_id, 'table': table}
                    matches = difflib.get_close_matches(candidate_normalized, [loc_en, loc_cn], n=1, cutoff=0.8)
                    if matches:
                        logging.info(f"Fuzzy location matched: {table} '{loc_info['name_en']}' with candidate '{candidate}'")
                        return {'name': loc_info['name_en'], 'type': 'selected_area', 'id': loc_id, 'table': table}

            indi_variations = ['india', 'indi', 'gujarat']
            if candidate_lower in indi_variations:
                logging.info(f"Normalized location match: '{candidate}' -> 'India'")
                return {'name': 'India', 'type': 'area', 'id': None}

        logging.info(f"No valid location matched for query: {query}")
        return None

    def _extract_coupon_name_from_query(self, query: str) -> Optional[str]:
        query = unicodedata.normalize('NFC', query.strip())
        query_lower = query.lower().replace('-', ' ').strip()
        is_chinese = any('\u4e00' <= c <= '\u9fff' for c in query)

        prompt = f"""
        Analyze the query: '{query}'
        Identify if the query contains a specific coupon name.
        - Return the exact coupon name if mentioned (e.g., 'Test Coupon', 'Cash coupon 1').
        - Ignore generic terms like 'coupon', 'voucher', 'discount'.
        - If no specific coupon name is identified, return None.
        Respond with only the coupon name or None.
        """
        mistral_result = self._mistral_query(prompt)
        logging.debug(f"Mistral coupon name analysis: {mistral_result}")

        if mistral_result and mistral_result != 'None':
            cursor = self.db_connection.cursor(dictionary=True)
            try:
                cursor.execute("""
                    SELECT name_en, COALESCE(name_cn, '') AS name_cn
                    FROM coupons
                    WHERE deleted_at IS NULL AND (TRIM(LOWER(name_en)) = %s OR TRIM(LOWER(name_cn)) = %s)
                """, (mistral_result.lower(), mistral_result.lower()))
                row = cursor.fetchone()
                if row:
                    coupon_name = row['name_en'] or row['name_cn']
                    logging.info(f"Mistral matched coupon name: '{mistral_result}' -> '{coupon_name}'")
                    return coupon_name
            finally:
                cursor.close()

        query_normalized = ' '.join(query_lower.split())
        stop_words_en = r'\b(i|want|give|for|of|voucher|in|location|me|off|discount|percent|percentage|at|least|up|to|atmost|most|upto|cash|dollars|fifty)\b'
        stop_words_cn = r'(我要|給我|找|搜索|商店)'
        query_clean = re.sub(stop_words_en, ' ', query_lower, flags=re.IGNORECASE)
        query_clean = re.sub(stop_words_cn, ' ', query_clean)
        query_clean = re.sub(r'\s+', ' ', query_clean).strip()
        logging.debug(f"Cleaned query: '{query_clean}'")

        if not query_clean:
            logging.debug(f"Query cleaned to empty: '{query}'")
            return None

        coupon_pattern = r'\bcoupon\s+(\d+)\b'
        coupon_match = re.search(coupon_pattern, query_lower, re.IGNORECASE)
        if coupon_match:
            coupon_name = f"Coupon {coupon_match.group(1)}"
            logging.debug(f"Preserved coupon name: '{coupon_name}'")
            return coupon_name

        cursor = self.db_connection.cursor(dictionary=True)
        names = []
        try:
            cursor.execute("""
                SELECT name_en, COALESCE(name_cn, '') AS name_cn
                FROM coupons
                WHERE deleted_at IS NULL AND (name_en IS NOT NULL OR name_cn IS NOT NULL)
            """)
            fetched_names = [(row['name_en'].lower() if row['name_en'] else '',
                              row['name_en'] or '',
                              row['name_cn'].lower() if row['name_cn'] else '',
                              row['name_cn'] or '',
                              'coupon') for row in cursor.fetchall()]
            names.extend(fetched_names)
            logging.debug(f"Fetched {len(fetched_names)} coupon names: {[name[1] or name[3] for name in fetched_names[:5]]}...")
        except Error as e:
            logging.error(f"Database error fetching names: {e}")
            for coupon in self.coupons_data:
                if coupon['name_en'] or coupon['name_cn']:
                    names.append((
                        coupon['name_en'].lower() if coupon['name_en'] else '',
                        coupon['name_en'] or '',
                        coupon['name_cn'].lower() if coupon['name_cn'] else '',
                        coupon['name_cn'] or '',
                        'coupon_fallback'))
            logging.debug(f"Using fallback names: {len(names)}")
        finally:
            cursor.close()

        for en_lower, en_orig, cn_lower, cn_orig, source in names:
            if not en_lower and not cn_lower:
                continue
            if query_normalized == en_lower or query_normalized == cn_lower:
                logging.info(f"Exact full query match: '{query_normalized}' -> '{en_orig or cn_orig}' from {source}")
                return en_orig or cn_orig
            if query_clean == en_lower or query_clean == cn_lower:
                logging.info(f"Exact cleaned query match: '{query_clean}' -> '{en_orig or cn_orig}' from {source}")
                return en_orig or cn_orig

        query_words = jieba.lcut(query_clean, cut_all=False) if is_chinese else query_clean.split()
        for length in range(len(query_words), 0, -1):
            for i in range(len(query_words) - length + 1):
                phrase = ''.join(query_words[i:i+length]).strip() if is_chinese else ' '.join(query_words[i:i+length]).strip()
                if not phrase:
                    continue
                phrase_normalized = ' '.join(phrase.lower().split())
                for en_lower, en_orig, cn_lower, cn_orig, source in names:
                    if phrase_normalized == en_lower or phrase_normalized == cn_lower:
                        logging.info(f"Exact phrase match: '{phrase}' -> '{en_orig or cn_orig}' from {source}")
                        return en_orig or cn_orig
                    matches = difflib.get_close_matches(phrase_normalized, [en_lower, cn_lower], n=1, cutoff=0.85)
                    if matches:
                        logging.info(f"Fuzzy coupon name match: '{phrase}' -> '{en_orig or cn_orig}' from {source}")
                        return en_orig or cn_orig

        logging.info(f"No coupon name matched for query: '{query}'")
        return None

    def _extract_discount_from_query(self, query: str) -> Optional[dict]:
        query_lower = query.lower()
        is_chinese = any('\u4e00' <= c <= '\u9fff' for c in query)
        
        if is_chinese:
            tokens = jieba.lcut(query_lower, cut_all=False)
            logging.debug(f"Chinese tokens: {tokens}")
            
            up_to_terms = ['高达', '至多', '最多']
            at_least_terms = ['至少', '最少']
            discount_terms = ['折扣', '优惠', '折']
            
            for i, token in enumerate(tokens):
                if token in up_to_terms and i + 1 < len(tokens):
                    next_token = tokens[i + 1]
                    match = re.match(r'(\d+)%?', next_token)
                    if match:
                        max_discount = int(match.group(1))
                        logging.debug(f"Extracted Chinese 'up to' discount: max={max_discount}%")
                        return {'min': 0, 'max': max_discount}
                elif token in at_least_terms and i + 1 < len(tokens):
                    next_token = tokens[i + 1]
                    match = re.match(r'(\d+)%?', next_token)
                    if match:
                        min_discount = int(match.group(1))
                        logging.debug(f"Extracted Chinese 'at least' discount: min={min_discount}%")
                        return {'min': min_discount, 'max': 100}
                elif token in discount_terms and i > 0:
                    prev_token = tokens[i - 1]
                    match = re.match(r'(\d+)%?', prev_token)
                    if match:
                        min_discount = int(match.group(1))
                        logging.debug(f"Extracted Chinese single discount: min={min_discount}%")
                        return {'min': min_discount, 'max': 100}

        up_to_pattern = r'up\s*to\s*(\d+)%?\s*(?: god|discount)'
        range_pattern = r'(\d+)%?\s*(?:to|and)\s*(\d+)%?\s*(?:off|discount)'
        single_pattern = r'(?:at\s*least\s*)?(\d+)%?\s*(?:off|discount)'
        
        up_to_match = re.search(up_to_pattern, query_lower)
        range_match = re.search(range_pattern, query_lower)
        single_match = re.search(single_pattern, query_lower)

        if range_match:
            min_discount = int(range_match.group(1))
            max_discount = int(range_match.group(2))
            logging.debug(f"Extracted English range discount: min={min_discount}%, max={max_discount}%")
            return {'min': min_discount, 'max': max_discount}
        elif up_to_match:
            max_discount = int(up_to_match.group(1))
            logging.debug(f"Extracted English 'up to' discount: max={max_discount}%")
            return {'min': 0, 'max': max_discount}
        elif single_match:
            min_discount = int(single_match.group(1))
            logging.debug(f"Extracted English single/at least discount: min={min_discount}%")
            return {'min': min_discount, 'max': 100}

        return None

    def extract_category(self, query: str) -> Optional[str]:
        query = unicodedata.normalize('NFC', query.strip()).lower()
        is_chinese = any('\u4e00' <= c <= '\u9fff' for c in query)
        words = jieba.lcut(query) if is_chinese else query.split()

        cursor = self.db_connection.cursor(dictionary=True)
        try:
            cursor.execute("SELECT id, name_en, COALESCE(name_cn, '') AS name_cn FROM categories WHERE status = '1' AND deleted_at IS NULL")
            categories = cursor.fetchall()
            best_match = None
            best_score = 0

            logging.debug(f"Extracting category from query: '{query}', words: {words}")

            stop_words = {'coupon', 'coupons', 'store', '優惠券', '券'}
            for category in categories:
                cat_name_en = category['name_en'].lower() if category['name_en'] else ''
                cat_name_cn = category['name_cn'].lower() if category['name_cn'] else ''
                
                for word in words:
                    word = word.strip().lower()
                    if not word or word in stop_words:
                        logging.debug(f"Ignoring word: '{word}'")
                        continue
                    if word == cat_name_en or word == cat_name_cn:
                        logging.info(f"Exact category match: '{word}' -> '{category['name_en']}'")
                        return category['name_en']
                
                for word in words:
                    word = word.strip().lower()
                    if not word or word in stop_words:
                        continue
                    if word in cat_name_en.split() or word in cat_name_cn.split():
                        score = len(word) / max(len(cat_name_en), len(cat_name_cn), 1)
                        if score > best_score:
                            best_match = category['name_en']
                            best_score = score
                            logging.debug(f"Partial category match: '{word}' -> '{best_match}' (score: {score})")
                    matches = difflib.get_close_matches(word, [cat_name_en, cat_name_cn], n=1, cutoff=0.95)
                    if matches:
                        score = difflib.SequenceMatcher(None, word, matches[0]).ratio()
                        if score > best_score:
                            best_match = category['name_en']
                            best_score = score
                            logging.debug(f"Fuzzy category match: '{word}' -> '{best_match}' (score: {score})")

            if best_match:
                logging.info(f"Selected best category: '{query}' -> '{best_match}' (score: {best_score})")
                return best_match

        except Error as e:
            logging.error(f"Error extracting category: {e}")
        finally:
            cursor.close()

        logging.info(f"No category matched for query: {query}")
        return None

    def search_coupons(self, category: str = None, location: dict = None, discount: dict = None, 
                      coupon_name: str = None, limit: int = 20, active_only: bool = False) -> Tuple[List[dict], bool]:
        cursor = self.db_connection.cursor(dictionary=True)
        coupons = []
        fallback = False

        try:
            if category:
                cursor.execute("SELECT COUNT(*) as count FROM categories WHERE TRIM(LOWER(name_en)) = %s AND status = '1' AND deleted_at IS NULL", (category.lower(),))
                if cursor.fetchone()['count'] == 0:
                    logging.warning(f"Category '{category}' not found in categories table")
                    category = None

            if location:
                self.last_location = location
            elif coupon_name and self.last_location:
                location = self.last_location
                logging.debug(f"Using last location context: {self.last_location}")

            location_name = location.get('name') if location else None
            location_type = location.get('type') if location else None
            location_id = location.get('id') if location else None
            location_table = location.get('table') if location else None

            location_ids = []
            expected_area_id = None
            valid_selected_area_ids = []

            area_to_table = {
                '2': 'kowloon',
                '1': 'hong_kong',
                '3': 'new_territories'
            }

            if location_name and location_type == 'selected_area' and location_table:
                cursor.execute(
                    f"SELECT id FROM {location_table} WHERE TRIM(LOWER(name_en)) = %s OR TRIM(LOWER(name_cn)) = %s AND status = 1 AND deleted_at IS NULL",
                    (location_name.lower(), location_name.lower())
                )
                location_ids = [str(row['id']) for row in cursor.fetchall()]
                logging.debug(f"Location IDs for {location_name} in {location_table}: {location_ids}")
                if not location_ids:
                    logging.warning(f"Selected area '{location_name}' not found in {location_table}. No coupons will be returned.")
                    return [], True
                expected_area_id = {'Hong Kong': '1', 'Kowloon': '2', 'New Territories': '3'}.get(location.get('name'), None)

            if location_type == 'area' and location_id in area_to_table:
                expected_area_id = location_id
                cursor.execute(
                    f"SELECT id FROM {area_to_table[location_id]} WHERE status = 1 AND deleted_at IS NULL"
                )
                valid_selected_area_ids = [str(row['id']) for row in cursor.fetchall()]
                logging.debug(f"Valid selected_area IDs for area {location_id}: {valid_selected_area_ids}")
                if not valid_selected_area_ids:
                    logging.warning(f"No valid selected_area IDs found for area {location_id}. Including all coupons for area.")
                    fallback = True

            query = """
                SELECT 
                    c.id, c.name_en, c.name_cn, c.description_en, c.description_cn,
                    c.cash_amount, c.percentage, c.expiry_date, c.quantity, c.status,
                    cat.id as category_id, cat.name_en as category_name_en, 
                    cat.name_cn as category_name_cn,
                    c.area, c.selected_area, c.territory,
                    cities.name as city_name, countries.name as country_name,
                    COALESCE(a.name_en, c.area) as area_name_en, COALESCE(a.name_cn, c.area) as area_name_cn
                FROM coupons c
                LEFT JOIN categories cat ON c.category_id = cat.id
                LEFT JOIN area a ON c.area = a.id
                LEFT JOIN cities ON c.city_id = cities.id
                LEFT JOIN countries ON c.country_id = countries.id
                WHERE c.deleted_at IS NULL
                AND c.quantity >= 0
                AND c.name_en IS NOT NULL
            """
            params = []

            if active_only:
                query += " AND c.status = 1 AND c.expiry_date >= CURDATE()"

            if category:
                query += " AND TRIM(LOWER(cat.name_en)) = %s"
                params.append(category.lower())

            if location_name and location_type == 'area':
                query += " AND c.area = %s"
                params.append(location_id)
                if valid_selected_area_ids and not fallback:
                    placeholders = ','.join(['%s'] * len(valid_selected_area_ids))
                    query += f" AND c.selected_area IN ({placeholders})"
                    params.extend(valid_selected_area_ids)
                logging.debug(f"Searching coupons with area: {location_id}, selected_areas: {valid_selected_area_ids or 'all'}")
            elif location_name and location_type == 'selected_area' and location_ids:
                placeholders = ','.join(['%s'] * len(location_ids))
                query += f" AND c.selected_area IN ({placeholders})"
                if expected_area_id:
                    query += " AND c.area = %s"
                    params.extend(location_ids)
                    params.append(expected_area_id)
                else:
                    params.extend(location_ids)
                logging.debug(f"Searching coupons with selected_area IN {location_ids}, area = {expected_area_id}")

            if discount:
                query += " AND c.percentage >= %s AND c.percentage <= %s"
                params.extend([discount['min'], discount['max']])

            if coupon_name:
                query += " AND (TRIM(LOWER(COALESCE(c.name_en, ''))) = %s OR TRIM(LOWER(COALESCE(c.name_cn, ''))) = %s)"
                params.extend([coupon_name.lower().strip(), coupon_name.lower().strip()])

            query += " ORDER BY c.created_at DESC LIMIT %s"
            params.append(limit)

            logging.debug(f"Executing query: {query} with params: {params}")
            cursor.execute(query, params)
            rows = cursor.fetchall()
            logging.debug(f"Found {len(rows)} rows")

            for row in rows:
                valid_area_ids = []
                if row['area'] in area_to_table:
                    cursor.execute(
                        f"SELECT id FROM {area_to_table[row['area']]} WHERE status = 1 AND deleted_at IS NULL"
                    )
                    valid_area_ids = [str(r['id']) for r in cursor.fetchall()]
                    logging.debug(f"Valid area IDs for coupon ID {row['id']} (area {row['area']}): {valid_area_ids}")
                if row['selected_area'] and valid_area_ids and row['selected_area'] not in valid_area_ids:
                    logging.warning(f"Skipping coupon ID {row['id']} ('{row['name_en']}'): selected_area '{row['selected_area']}' not valid in {area_to_table.get(row['area'], 'unknown')}")
                    continue
                coupons.append({
                    'id': row['id'], 'name_en': row['name_en'], 'name_cn': row['name_cn'],
                    'description_en': row['description_en'] or '', 'description_cn': row['description_cn'] or '',
                    'cash_amount': float(row['cash_amount'] or 0), 'percentage': float(row['percentage'] or 0),
                    'expiry_date': row['expiry_date'], 'quantity': int(row['quantity'] or 0),
                    'status': int(row['status'] or 0), 'category_id': row['category_id'],
                    'category_name_en': row['category_name_en'] or '', 'category_name_cn': row['category_name_cn'] or '',
                    'area': row['area'] or '', 'selected_area': row['selected_area'] or '',
                    'territory': row['territory'] or '', 'city_name': row['city_name'] or '',
                    'country_name': row['country_name'] or '', 'location': row['area_name_en'] or row['area'] or 'Any'
                })

            logging.debug(f"Returning {len(coupons)} coupons for category '{category}', location '{location_name}'")
            return coupons, fallback

        except Error as e:
            logging.error(f"Error searching coupons: {e}")
            return [], True
        finally:
            cursor.close()