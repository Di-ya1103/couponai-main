import mysql.connector
from config import Config

# Print config for debugging
print("DB Config:", Config.DB_CONFIG)

try:
    # Connect to MySQL using config
    connection = mysql.connector.connect(**Config.DB_CONFIG)
    if connection.is_connected():
        print("Successfully connected to MySQL!")
        cursor = connection.cursor()
        # Test query
        cursor.execute("SELECT name_en, name_cn FROM categories LIMIT 5")
        rows = cursor.fetchall()
        for row in rows:
            print(f"Category: {row[0]} | Chinese Name: {row[1]}")
except mysql.connector.Error as e:
    print(f"Error connecting to MySQL: {e}")
finally:
    if 'connection' in locals() and connection.is_connected():
        cursor.close()
        connection.close()
        print("MySQL connection closed.")