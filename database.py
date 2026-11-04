import sqlite3
import os
try:
    connection = sqlite3.connect("school.db")
    

    # Test whether the database responds
    cursor = connection.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS students (
    student_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    age INTEGER,
    course TEXT
        )
    """)
    connection.commit()
    print("Students table created successfully")

    cursor.execute("""
    INSERT INTO students (name, age, course)
    VALUES (?, ?, ?)
    """, ("John", 21, "Computer Science"))
    connection.commit()

    students = [
        ("Mary", 22, "Accounting"),
        ("Peter", 20, "Information Systems"),
        ("Sarah", 23, "Computer Science"),
        ("James", 19, "Engineering")
        ]

    
    cursor.executemany("""
    INSERT INTO students (name, age, course) VALUES (?, ?, ?)
    """, students)
    connection.commit()
    # print("Students inserted successfully!")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM students")
    students = cursor.fetchall()
    for student in students:
    print(students)
    # cursor.execute("SELECT * FROM students WHERE age > ?", (20,))
    # for student in cursor.fetchall():
    #     print(student)
    # cursor.execute("SELECT * FROM students WHERE age > ?", (20,))
    # for student in cursor.fetchall():
    #     print(student)
    # cursor.execute("""
    # SELECT * FROM students
    # WHERE age >= ? AND course = ?
    # """, (21, "Computer Science"))
    # cursor.execute("SELECT * FROM students WHERE name LIKE ?", ("%ar%",))

    # cursor.execute("SELECT * FROM students WHERE age > ?", (20,))
    # for student in cursor.fetchall():
    #     print(student)
    cursor.execute("""
    SELECT * FROM students
    WHERE age >= ? AND course = ?
    """, (21, "Computer Science"))
    cursor.execute("SELECT * FROM students WHERE name LIKE ?", ("%ar%",))
        
except sqlite3.Error as error:
 print("Database connection failed:", error)
finally:
 connection.close()

