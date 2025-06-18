import mysql.connector 
from entity_extraction.rules import EnhancedRuleBasedExtractor
import logging
import sys
import os
from dotenv import load_dotenv
from typing import Optional, Dict

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def connect_to_db():
    try:
        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", "3306"),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", "root"),
            database=os.getenv("DB_NAME", "coupon"),
            charset='utf8mb4',
            collation='utf8mb4_unicode_ci'
        )
        logging.info("Connected to database")
        return connection
    except mysql.connector.Error as err:
        logging.error(f"Database connection error: {err}")
        sys.exit(1)

def display_coupon_results(coupons, query, category, location, discount, previous_queries):
    active_count = sum(1 for coupon in coupons if coupon['status'] == 1)
    inactive_count = len(coupons) - active_count
    
    print(f"\n{'='*80}")
    print("🎫 COUPON SEARCH RESULTS")
    print(f"{'='*80}")
    print(f"Query: {query}")
    if previous_queries:
        print(f"Previous Queries: {', '.join(previous_queries[-2:])}")
    print(f"Filters:")
    print(f"  • Category: {category or 'Any'}")
    print(f"  • Location: {location or 'Any'}")
    discount_str = "Any"
    if discount:
        if discount['min'] == 0:
            discount_str = f"Up to {discount['max']}%"
        elif discount['max'] == 100:
            discount_str = f"At least {discount['min']}%"
        else:
            discount_str = f"{discount['min']}% to {discount['max']}%"
    print(f"  • Discount: {discount_str}")
    print(f"Results: {len(coupons)} coupons (Active: {active_count}, Inactive: {inactive_count})\n")
    
    if not coupons:
        print(f"No coupons found for the specified filters. Try different criteria.")
        return
    
    for idx, coupon in enumerate(coupons, 1):
        status = "Active" if coupon['status'] == 1 else f"Inactive (Expired: {coupon['expiry_date']})"
        discount_str = f"{coupon['percentage']}% Off" if coupon['percentage'] > 0 else "No discount"
        
        print(f"{idx}. {coupon['name_en']} ({coupon['name_cn']})")
        print(f"   • Discount: {discount_str}")
        print(f"   • Status: {status}")
        print(f"   • Category: {coupon['category_name_en'] or 'Unknown'}")
        print(f"   • Location: {coupon['city_name'] or coupon['country_name'] or coupon['territory'] or 'Any'}")
        print(f"   • Quantity: {coupon['quantity']}")
        print()

def clean_exit(db_connection):
    try:
        if os.path.exists("query_history.txt"):
            os.remove("query_history.txt")
            logging.info("Cleared query_history.txt")
    except Exception as e:
        logging.error(f"Error clearing query_history.txt: {e}")
    if db_connection and db_connection.is_connected():
        db_connection.close()
        logging.info("Database connection closed")
    print("\nGoodbye!")
    sys.exit(0)

def main():
    db_connection = connect_to_db()
    extractor = EnhancedRuleBasedExtractor(db_connection)
    session_queries = []
    
    try:
        if os.path.exists("query_history.txt"):
            os.remove("query_history.txt")
            logging.info("Cleared query_history.txt on startup")
    except Exception as e:
        logging.error(f"Error clearing query_history.txt: {e}")
    
    try:
        while True:
            query = input("\n🔍 What are you looking for? ").strip()
            if query.lower() in ['quit', 'exit']:
                clean_exit(db_connection)
            
            print(f"\n{'='*80}\nPROCESSING QUERY: '{query}'\n{'='*80}")
            
            try:
                category = None
                location = None
                discount = None
                coupon_name = None
                
                current_category = extractor.extract_category(query, session_queries[-1] if session_queries else None)
                current_location = extractor._extract_location_from_query(query)
                current_discount = extractor._extract_discount_from_query(query)
                current_coupon_name = extractor._extract_coupon_name_from_query(query)
                
                for prev_query in reversed(session_queries[-2:]):
                    if not category and not current_category:
                        category = extractor.extract_category(prev_query, session_queries[-3] if len(session_queries) > 2 else None)
                    if not location and not current_location:
                        location = extractor._extract_location_from_query(prev_query)
                    if not discount and not current_discount:
                        discount = extractor._extract_discount_from_query(prev_query)
                    if not coupon_name and not current_coupon_name:
                        coupon_name = extractor._extract_coupon_name_from_query(prev_query)
                
                category = current_category or category
                location = current_location or location
                discount = current_discount or discount
                coupon_name = current_coupon_name or coupon_name
                
                print(f"\n🧠 QUERY ANALYSIS:")
                print(f"   Current Query: {query}")
                print(f"   Category: {category or 'Any'}")
                print(f"   Location: {location or 'Any'}")
                print(f"   Coupon Name: {coupon_name or 'Any'}")
                discount_str = "Any"
                if discount:
                    if discount['min'] == 0:
                        discount_str = f"Up to {discount['max']}%"
                    elif discount['max'] == 100:
                        discount_str = f"At least {discount['min']}%"
                    else:
                        discount_str = f"{discount['min']}% to {discount['max']}%"
                print(f"   Discount: {discount_str}")
                
                coupons, _ = extractor.search_coupons(
                    category=category,
                    location=location,
                    discount=discount,
                    coupon_name=coupon_name,
                    limit=10,
                    active_only=False
                )
                display_coupon_results(coupons, query, category, location, discount, session_queries)
                
                session_queries.append(query)
                try:
                    with open("query_history.txt", "w") as f:
                        f.write("\n".join(session_queries[-3:]))
                    logging.info(f"Saved query: '{query}'")
                except Exception as e:
                    logging.error(f"Error saving query: {e}")
                
            except Exception as e:
                logging.error(f"Error processing query '{query}': {e}")
                print(f"Error: {e}")
                
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received")
        clean_exit(db_connection)
    
    finally:
        clean_exit(db_connection)

if __name__ == "__main__":
    main()