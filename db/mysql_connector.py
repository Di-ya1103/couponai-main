import mysql.connector
from mysql.connector import Error
from typing import List, Dict, Optional
import logging
from config import Config

class MySQLConnector:
    def __init__(self):
        self.connection = None
        try:
            self.connection = mysql.connector.connect(**Config.DB_CONFIG)
            if self.connection.is_connected():
                logging.info("MySQL connection established successfully")
            else:
                raise Error("Failed to connect without raising exception")
        except Error as e:
            logging.error(f"Failed to connect to database: {e}")
            raise

    def get_table_info(self, table_name: str) -> List[Dict]:
        if not self.connection or not self.connection.is_connected():
            raise Error("Database connection is not active")
        
        cursor = self.connection.cursor(dictionary=True)
        try:
            cursor.execute(f"DESCRIBE {table_name}")
            return cursor.fetchall()
        except Error as e:
            logging.error(f"Failed to describe table {table_name}: {e}")
            return []
        finally:
            cursor.close()

    def get_coupons_by_category(self, category_name_en: str = None, category_name_cn: str = None, category_key: str = None) -> List[Dict]:
        if not self.connection or not self.connection.is_connected():
            raise Error("Database connection is not active")
                     
        cursor = self.connection.cursor(dictionary=True)
        try:
            if category_key:
                cursor.execute(
                    """
                    SELECT name_en, name_cn, commission_amount, commission_rate
                    FROM categories
                    WHERE LOWER(REPLACE(REPLACE(REPLACE(name_en, ' & ', '_'), ' ', '_'), '&', '_')) = %s 
                    AND status = '1' AND deleted_at IS NULL
                    """,
                    (category_key.lower(),)
                )
            else:
                cursor.execute(
                    """
                    SELECT name_en, name_cn, commission_amount, commission_rate
                    FROM categories
                    WHERE (name_en = %s OR name_cn = %s) AND status = '1' AND deleted_at IS NULL
                    """,
                    (category_name_en, category_name_cn)
                )
            
            results = cursor.fetchall()
            logging.info(f"Found {len(results)} categories for query")
            return results
            
        except Error as e:
            logging.error(f"Database query failed: {e}")
            return []
        finally:
            cursor.close()

    def search_coupons(self, category: str = None, location: str = None, company: str = None, limit: int = 20) -> List[Dict]:
        if not self.connection or not self.connection.is_connected():
            raise Error("Database connection is not active")
        
        cursor = self.connection.cursor(dictionary=True)
        try:
            base_query = """
            SELECT DISTINCT
                c.id, c.name_en, c.name_cn, c.description_en, c.description_cn,
                c.cash_amount, c.percentage, c.expiry_date, c.status,
                cat.name_en as category_name_en, cat.name_cn as category_name_cn,
                comp.name_en as company_name_en, comp.name_cn as company_name_cn,
                cities.name as city_name,
                countries.name as country_name
            FROM coupons c
            LEFT JOIN categories cat ON c.category_id = cat.id
            LEFT JOIN companies comp ON c.created_by = comp.id
            LEFT JOIN cities ON c.city_id = cities.id
            LEFT JOIN countries ON c.country_id = countries.id
            WHERE c.deleted_at IS NULL
            """
            
            conditions = []
            params = []
            
            if category and category != 'other':
                conditions.append("""
                    (LOWER(REPLACE(REPLACE(REPLACE(cat.name_en, ' & ', '_'), ' ', '_'), '&', '_')) = %s
                     OR cat.name_en LIKE %s OR cat.name_cn LIKE %s)
                """)
                params.extend([category.lower(), f"%{category}%", f"%{category}%"])
            
            if location:
                conditions.append("""
                    (cities.name LIKE %s OR countries.name LIKE %s 
                     OR c.territory LIKE %s)
                """)
                params.extend([f"%{location}%", f"%{location}%", f"%{location}%"])
            
            if company:
                conditions.append("""
                    (comp.name_en LIKE %s OR comp.name_cn LIKE %s)
                """)
                params.extend([f"%{company}%", f"%{company}%"])
            
            if conditions:
                base_query += " AND " + " AND ".join(conditions)
            
            base_query += " ORDER BY c.created_at DESC LIMIT %s"
            params.append(limit)
            
            cursor.execute(base_query, params)
            results = cursor.fetchall()
            
            logging.info(f"Found {len(results)} coupons with search criteria")
            return results
            
        except Error as e:
            logging.error(f"Coupon search failed: {e}")
            return []
        finally:
            cursor.close()

    def search_companies(self, query: str, limit: int = 10) -> List[Dict]:
        if not self.connection or not self.connection.is_connected():
            raise Error("Database connection is not active")
        
        cursor = self.connection.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT id, name_en, name_cn, image, status
                FROM companies
                WHERE (name_en LIKE %s OR name_cn LIKE %s)
                AND status = 1 AND deleted_at IS NULL
                ORDER BY name_en
                LIMIT %s
                """,
                (f"%{query}%", f"%{query}%", limit)
            )
            
            results = cursor.fetchall()
            logging.info(f"Found {len(results)} companies for query '{query}'")
            return results
            
        except Error as e:
            logging.error(f"Company search failed: {e}")
            return []
        finally:
            cursor.close()

    def search_locations(self, query: str, limit: int = 10) -> List[Dict]:
        if not self.connection or not self.connection.is_connected():
            raise Error("Database connection is not active")
        
        cursor = self.connection.cursor(dictionary=True)
        locations = []
        
        try:
            cursor.execute(
                """
                SELECT id, name, cost, status, 'city' as type
                FROM cities
                WHERE name LIKE %s AND status = 1 AND deleted_at IS NULL
                LIMIT %s
                """,
                (f"%{query}%", limit // 3)
            )
            locations.extend(cursor.fetchall())
            
            cursor.execute(
                """
                SELECT id, name, code, status, 'country' as type
                FROM countries
                WHERE name LIKE %s AND status = 1 AND deleted_at IS NULL
                LIMIT %s
                """,
                (f"%{query}%", limit // 3)
            )
            locations.extend(cursor.fetchall())
            
            cursor.execute(
                """
                SELECT id, name_en, name_cn, status, 'area' as type
                FROM area
                WHERE (name_en LIKE %s OR name_cn LIKE %s) 
                AND status = 1 AND deleted_at IS NULL
                LIMIT %s
                """,
                (f"%{query}%", f"%{query}%", limit // 3)
            )
            locations.extend(cursor.fetchall())
            
            logging.info(f"Found {len(locations)} locations for query '{query}'")
            return locations[:limit]
            
        except Error as e:
            logging.error(f"Location search failed: {e}")
            return []
        finally:
            cursor.close()

    def get_all_categories(self) -> List[Dict]:
        if not self.connection or not self.connection.is_connected():
            raise Error("Database connection is not active")
                     
        cursor = self.connection.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT id, name_en, name_cn, commission_amount, commission_rate
                FROM categories
                WHERE status = 1 AND deleted_at IS NULL
                ORDER BY name_en
                """
            )
            return cursor.fetchall()
        except Error as e:
            logging.error(f"Failed to fetch categories: {e}")
            return []
        finally:
            cursor.close()

    def get_coupon_details(self, coupon_id: int) -> Optional[Dict]:
        if not self.connection or not self.connection.is_connected():
            raise Error("Database connection is not active")
        
        cursor = self.connection.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT 
                    c.*, 
                    cat.name_en as category_name_en, cat.name_cn as category_name_cn,
                    comp.name_en as company_name_en, comp.name_cn as company_name_cn,
                    cities.name as city_name, 
                    countries.name as country_name
                FROM coupons c
                LEFT JOIN categories cat ON c.category_id = cat.id
                LEFT JOIN companies comp ON c.created_by = comp.id
                LEFT JOIN cities ON c.city_id = cities.id
                LEFT JOIN countries ON c.country_id = countries.id
                WHERE c.id = %s AND c.deleted_at IS NULL
                """,
                (coupon_id,)
            )
            
            result = cursor.fetchone()
            if result:
                logging.info(f"Retrieved details for coupon ID {coupon_id}")
            return result
            
        except Error as e:
            logging.error(f"Failed to get coupon details: {e}")
            return None
        finally:
            cursor.close()

    def get_database_stats(self) -> Dict[str, int]:
        if not self.connection or not self.connection.is_connected():
            raise Error("Database connection is not active")
        
        cursor = self.connection.cursor()
        stats = {}
        
        tables = ['coupons', 'categories', 'companies', 'area', 'cities', 'countries']
        favorite_table = ['coupon_favorites']
        
        try:
            for table in tables:
                try:
                    cursor.execute(f"""
                        SELECT COUNT(*) FROM {table} 
                        WHERE status = 1 AND deleted_at IS NULL
                    """)
                    count = cursor.fetchone()[0]
                    stats[table] = count
                    
                except Error as table_error:
                    logging.warning(f"Could not get count for table {table}: {table_error}")
                    stats[table] = 0
            
            for table in favorite_table:
                try:
                    cursor.execute(f"""
                        SELECT COUNT(*) FROM {table}
                    """)
                    count = cursor.fetchone()[0]
                    stats[table] = count
                    
                except Error as table_error:
                    logging.warning(f"Could not get count for table {table}: {table_error}")
                    stats[table] = 0
            
            return stats
            
        except Error as e:
            logging.error(f"Failed to get database statistics: {e}")
            return {}
        finally:
            cursor.close()

    def get_popular_coupons(self, limit: int = 10) -> List[Dict]:
        if not self.connection or not self.connection.is_connected():
            raise Error("Database connection is not active")
        
        cursor = self.connection.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT 
                    c.id, c.name_en, c.name_cn, c.click_count,
                    c.cash_amount, c.percentage, c.expiry_date,
                    cat.name_en as category_name_en, cat.name_cn as category_name_cn
                FROM coupons c
                LEFT JOIN categories cat ON c.category_id = cat.id
                WHERE c.status = 1 AND c.deleted_at IS NULL
                ORDER BY c.click_count DESC, c.created_at DESC
                LIMIT %s
                """,
                (limit,)
            )
            
            results = cursor.fetchall()
            logging.info(f"Retrieved {len(results)} popular coupons")
            return results
            
        except Error as e:
            logging.error(f"Failed to get popular coupons: {e}")
            return []
        finally:
            cursor.close()

    def close(self):
        if self.connection and self.connection.is_connected():
            self.connection.close()
            logging.info("MySQL connection closed")

    def cursor(self, dictionary=False):
        if not self.connection or not self.connection.is_connected():
            raise Error("Database connection is not active")
        return self.connection.cursor(dictionary=dictionary)